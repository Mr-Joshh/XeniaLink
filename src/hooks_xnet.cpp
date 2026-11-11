// XNet: replaces Microsoft's secure addressing with the plain public-IP model
// Xenia Netplay uses. The title calls NetDll_* exports directly, and each takes a
// leading XNCALLER_TYPE argument.

#include "hooks.h"
#include "hooking.h"
#include "api.h"
#include "config.h"
#include "log.h"
#include <winsockx.h>
#include <stdlib.h>
#include <stdio.h>

#define XEX_PRIVILEGE_INSECURE_SOCKETS 6  // XEX_SYSTEM_INSECURE_SOCKETS = 1 << 6

typedef INT (*XNetStartup_t)(DWORD caller, const XNetStartupParams* params);
typedef DWORD (*XNetGetTitleXnAddr_t)(DWORD caller, XNADDR* xna);
typedef BOOL (*XexCheckExecutablePrivilege_t)(DWORD privilege);

static XNetStartup_t g_orig_XNetStartup;
static XNetGetTitleXnAddr_t g_orig_XNetGetTitleXnAddr;
static XexCheckExecutablePrivilege_t g_orig_XexCheckPrivilege;
static BOOL g_title_active = FALSE;

// Small IP -> (MAC, session) cache so XNetInAddrToXnAddr doesn't hit the server
// on every packet.
#define PEER_CACHE_SIZE 32
struct PeerEntry { IN_ADDR ip; BYTE mac[6]; ULONGLONG session_id; };
static PeerEntry g_peers[PEER_CACHE_SIZE];
static DWORD g_peer_count;
static CRITICAL_SECTION g_peer_lock;

static const PeerEntry* LookupPeer(IN_ADDR ip) {
  EnterCriticalSection(&g_peer_lock);
  for (DWORD i = 0; i < g_peer_count; i++) {
    if (g_peers[i].ip.s_addr == ip.s_addr) {
      LeaveCriticalSection(&g_peer_lock);
      return &g_peers[i];
    }
  }
  LeaveCriticalSection(&g_peer_lock);

  ApiPlayer player;
  if (!ApiFindPlayer(ip, &player)) return NULL;

  EnterCriticalSection(&g_peer_lock);
  PeerEntry* e = &g_peers[g_peer_count < PEER_CACHE_SIZE ? g_peer_count++
                                                         : (ip.s_addr % PEER_CACHE_SIZE)];
  e->ip = ip;
  memcpy(e->mac, player.mac, 6);
  e->session_id = player.session_id;
  LeaveCriticalSection(&g_peer_lock);
  return e;
}

// Logs the first few calls of each hook, so a crash log shows the last steps.
#define LOG_FIRST(counter, ...) do { if (counter < 20) { counter++; LogDebug(__VA_ARGS__); } } while (0)
// Same cap, but always logged (errors).
#define LOG_FIRST_ERR(counter, ...) do { if (counter < 20) { counter++; Log(__VA_ARGS__); } } while (0)
static DWORD g_l_title, g_l_x2i, g_l_i2x, g_l_reg, g_l_unreg, g_l_conn, g_l_status, g_l_qosl,
    g_l_qos, g_l_qosr, g_l_dns;

// ---- startup / security ----------------------------------------------------

static INT Hook_XNetStartup(DWORD caller, const XNetStartupParams* params) {
  XNetStartupParams p;
  memset(&p, 0, sizeof(p));
  if (params) memcpy(&p, params, min(sizeof(p), (size_t)params->cfgSizeOfStruct));
  p.cfgSizeOfStruct = sizeof(p);
  p.cfgFlags |= XNET_STARTUP_BYPASS_SECURITY;
  Log("xnet: XNetStartup (flags now %02X)", p.cfgFlags);
  return g_orig_XNetStartup(caller, &p);
}

// First Assault (UE3) doesn't import XNetStartup: it looks up NetDll_XNetStartupEx
// with XexGetProcedureAddress and calls it with NULL params. Hand it this wrapper
// instead so the bypass flag still gets set (otherwise its sockets stay secure and
// plain TCP from Xenia never connects).
#define ORD_NetDll_XNetStartupEx 0x050
#define ORD_XexGetProcedureAddress 0x197

typedef INT (*XNetStartupEx_t)(DWORD caller, const XNetStartupParams* params, DWORD version);
typedef DWORD (*XexGetProcedureAddress_t)(HANDLE module, DWORD ordinal, PVOID* out);
static XNetStartupEx_t g_orig_XNetStartupEx;
static XexGetProcedureAddress_t g_orig_XexGetProcedureAddress;

static INT Hook_XNetStartupEx(DWORD caller, const XNetStartupParams* params, DWORD version) {
  XNetStartupParams p;
  memset(&p, 0, sizeof(p));
  if (params) memcpy(&p, params, min(sizeof(p), (size_t)params->cfgSizeOfStruct));
  p.cfgSizeOfStruct = sizeof(p);
  p.cfgFlags |= XNET_STARTUP_BYPASS_SECURITY;
  INT result = g_orig_XNetStartupEx(caller, &p, version);
  Log("xnet: XNetStartupEx (params %p, flags now %02X) -> %d", params, p.cfgFlags, result);
  return result;
}

static DWORD Hook_XexGetProcedureAddress(HANDLE module, DWORD ordinal, PVOID* out) {
  DWORD status = g_orig_XexGetProcedureAddress(module, ordinal, out);
  HANDLE xam = NULL;
  if (status == 0 && out && *out && ordinal == ORD_NetDll_XNetStartupEx &&
      XexGetModuleHandle(MODULE_XAM, &xam) == 0 && module == xam) {
    g_orig_XNetStartupEx = (XNetStartupEx_t)*out;
    *out = (PVOID)Hook_XNetStartupEx;
    Log("xnet: title looked up XNetStartupEx -> wrapped");
  }
  return status;
}

// Patched into xam's own import table: xam checks this privilege before
// allowing insecure sockets.
static BOOL Hook_XexCheckExecutablePrivilege(DWORD privilege) {
  if (g_title_active && privilege == XEX_PRIVILEGE_INSECURE_SOCKETS) return TRUE;
  return g_orig_XexCheckPrivilege(privilege);
}

// ---- addressing ------------------------------------------------------------

static DWORD Hook_XNetGetTitleXnAddr(DWORD caller, XNADDR* xna) {
  DWORD status = g_orig_XNetGetTitleXnAddr(caller, xna);
  if (status == XNET_GET_XNADDR_PENDING || !xna) return status;
  // Same shape as Xenia: ina and inaOnline both carry the public IP.
  xna->ina = g_identity.public_ip;
  xna->inaOnline = g_identity.public_ip;
  xna->wPortOnline = g_config.player_port;
  LOG_FIRST(g_l_title, "xnet: GetTitleXnAddr -> status %08X", status | XNET_GET_XNADDR_ONLINE);
  return status | XNET_GET_XNADDR_ONLINE;
}

static INT Hook_XNetXnAddrToInAddr(DWORD caller, const XNADDR* xna,
                                   const XNKID* xnkid, IN_ADDR* ina) {
  if (!xna || !ina) return WSAEINVAL;
  LOG_FIRST(g_l_x2i, "xnet: XnAddrToInAddr");
  if (memcmp(xna->abEnet, g_identity.mac, 6) == 0) {
    *ina = g_identity.local_ip;  // ourselves
  } else {
    *ina = xna->inaOnline.s_addr ? xna->inaOnline : xna->ina;
  }
  return 0;
}

static INT Hook_XNetInAddrToXnAddr(DWORD caller, IN_ADDR ina, XNADDR* xna,
                                   XNKID* xnkid) {
  if (xna) memset(xna, 0, sizeof(*xna));
  if (xnkid) memset(xnkid, 0, sizeof(*xnkid));
  LOG_FIRST(g_l_i2x, "xnet: InAddrToXnAddr");

  if (ina.s_addr == g_identity.local_ip.s_addr || ina.s_addr == htonl(INADDR_LOOPBACK)) {
    if (xna) Hook_XNetGetTitleXnAddr(caller, xna);
    return 0;
  }

  if (xna) {
    xna->ina = ina;
    xna->inaOnline = ina;
    xna->wPortOnline = g_config.player_port;
  }
  const PeerEntry* peer = LookupPeer(ina);
  if (peer) {
    if (xna) memcpy(xna->abEnet, peer->mac, 6);
    if (xnkid) memcpy(xnkid->ab, &peer->session_id, sizeof(XNKID));
  }
  return 0;
}

// ---- keys / connections (no security layer, so these just succeed) ---------

static INT Hook_XNetRegisterKey(DWORD caller, const XNKID* xnkid, const XNKEY* xnkey) {
  LOG_FIRST(g_l_reg, "xnet: RegisterKey");
  return 0;
}

static INT Hook_XNetUnregisterKey(DWORD caller, const XNKID* xnkid) {
  LOG_FIRST(g_l_unreg, "xnet: UnregisterKey");
  return 0;
}

static INT Hook_XNetConnect(DWORD caller, IN_ADDR ina) {
  LOG_FIRST(g_l_conn, "xnet: Connect");
  return 0;
}

static DWORD Hook_XNetGetConnectStatus(DWORD caller, IN_ADDR ina) {
  LOG_FIRST(g_l_status, "xnet: GetConnectStatus");
  return XNET_CONNECT_STATUS_CONNECTED;
}

// ---- QoS ----------------------------------------------------------------------
// Like Xenia: the host's QoS data (game-specific blob from XNetQosListen) is
// stored on the backend; searchers fetch it per session in XNetQosLookup.

#define MAX_QOS_DATA 1024

struct QosUpload {
  ULONGLONG session;
  DWORD len;
  BYTE data[MAX_QOS_DATA];
};

static DWORD WINAPI QosUploadThread(LPVOID param) {
  QosUpload* u = (QosUpload*)param;
  ApiSessionQosUpload(XamGetCurrentTitleId(), u->session, u->data, u->len);
  free(u);
  return 0;
}

static INT Hook_XNetQosListen(DWORD caller, const XNKID* xnkid, const BYTE* data,
                              UINT data_len, DWORD bits_per_sec, DWORD flags) {
  LOG_FIRST(g_l_qosl, "xnet: QosListen flags %08X data %u", flags, data_len);
  if ((flags & XNET_QOS_LISTEN_SET_DATA) && xnkid && data && data_len) {
    QosUpload* u = (QosUpload*)malloc(sizeof(QosUpload));
    if (u) {
      memcpy(&u->session, xnkid->ab, 8);
      u->len = min((DWORD)data_len, (DWORD)MAX_QOS_DATA);
      memcpy(u->data, data, u->len);
      HANDLE t = CreateThread(NULL, 0, QosUploadThread, u, 0, NULL);
      if (t) CloseHandle(t); else free(u);
    }
  }
  return 0;
}

static INT Hook_XNetQosLookup(DWORD caller, UINT cxna, const XNADDR* apxna[],
                              const XNKID* apxnkid[], const XNKEY* apxnkey[],
                              UINT cina, const IN_ADDR aina[],
                              const DWORD adwServiceId[], UINT probes,
                              DWORD bits_per_sec, DWORD flags, WSAEVENT event,
                              XNQOS** out) {
  const UINT count = cxna + cina;
  LOG_FIRST(g_l_qos, "xnet: QosLookup %u xnaddr + %u ina, flags %08X", cxna, cina, flags);

  // Fetch each target session's QoS data first (hosts found via search).
  static BYTE fetched[8][MAX_QOS_DATA];
  DWORD fetched_len[8] = {0};
  DWORD total = 0;
  for (UINT i = 0; i < cxna && i < 8; i++) {
    if (apxnkid && apxnkid[i]) {
      ULONGLONG session;
      memcpy(&session, apxnkid[i]->ab, 8);
      fetched_len[i] = ApiSessionQosGet(XamGetCurrentTitleId(), session, fetched[i],
                                        MAX_QOS_DATA);
      total += fetched_len[i];
    }
  }

  const size_t head = sizeof(XNQOS) + (count ? count - 1 : 0) * sizeof(XNQOSINFO);
  XNQOS* qos = (XNQOS*)malloc(head + total);
  if (!qos) return WSAENOBUFS;
  memset(qos, 0, head + total);
  qos->cxnqos = count;
  qos->cxnqosPending = 0;
  BYTE* tail = (BYTE*)qos + head;
  for (UINT i = 0; i < count; i++) {
    XNQOSINFO* info = &qos->axnqosinfo[i];
    info->bFlags = XNET_XNQOSINFO_COMPLETE | XNET_XNQOSINFO_TARGET_CONTACTED;
    info->cProbesXmit = info->cProbesRecv = (WORD)(probes ? probes : 4);
    info->wRttMinInMsecs = 40;
    info->wRttMedInMsecs = 50;
    info->dwUpBitsPerSec = info->dwDnBitsPerSec = 10 * 1000 * 1000;
    if (i < 8 && fetched_len[i]) {
      memcpy(tail, fetched[i], fetched_len[i]);
      info->pbData = tail;
      info->cbData = (WORD)fetched_len[i];
      info->bFlags |= XNET_XNQOSINFO_DATA_RECEIVED;
      tail += fetched_len[i];
    }
  }
  *out = qos;
  if (event) SetEvent(event);
  return 0;
}

static INT Hook_XNetQosRelease(DWORD caller, XNQOS* qos) {
  LOG_FIRST(g_l_qosr, "xnet: QosRelease %p", qos);
  free(qos);
  return 0;
}

// ---- keep the console off real Xbox Live -----------------------------------

typedef INT (*XNetDnsLookup_t)(DWORD caller, const char* name, WSAEVENT event,
                               XNDNS** out);
static XNetDnsLookup_t g_orig_XNetDnsLookup;

static INT Hook_XNetDnsLookup(DWORD caller, const char* name, WSAEVENT event,
                              XNDNS** out) {
  if (g_config.block_xbox_live && name &&
      (strstr(name, "xboxlive.com") || strstr(name, "xbox.com") ||
       strstr(name, "xboxlive.net"))) {
    Log("xnet: blocked DNS lookup %s", name);
    return WSAHOST_NOT_FOUND;
  }
  return g_orig_XNetDnsLookup(caller, name, event, out);
}

// ---- sockets (logging only) ---------------------------------------------------
// Shows whether the game really opens a TCP listener on its game port and whether
// Xenia's connect is ever accepted. accept() is polled, so only successes and the
// first few failures are logged.

typedef SOCKET (*NetSocket_t)(DWORD caller, int af, int type, int protocol);
typedef int (*NetBind_t)(DWORD caller, SOCKET s, const sockaddr* name, int len);
typedef int (*NetListen_t)(DWORD caller, SOCKET s, int backlog);
typedef SOCKET (*NetAccept_t)(DWORD caller, SOCKET s, sockaddr* addr, int* len);
typedef int (*NetConnect_t)(DWORD caller, SOCKET s, const sockaddr* name, int len);
typedef int (*NetGetLastError_t)();
typedef int (*NetSetsockopt_t)(DWORD caller, SOCKET s, int level, int opt, const char* val, int len);
static NetSetsockopt_t g_orig_setsockopt;
static NetSocket_t g_orig_socket;
static NetBind_t g_orig_bind;
static NetListen_t g_orig_listen;
static NetAccept_t g_orig_accept;
static NetConnect_t g_orig_connect;
static NetGetLastError_t g_orig_WSAGetLastError;
static DWORD g_l_sock, g_l_bind, g_l_listen, g_l_accept_err, g_l_tcpconn;

static int LastNetError() { return g_orig_WSAGetLastError ? g_orig_WSAGetLastError() : -1; }

static void FormatAddr(const sockaddr* a, char* out, size_t size) {
  if (!a || a->sa_family != AF_INET) { strcpy_s(out, size, "?"); return; }
  const sockaddr_in* in = (const sockaddr_in*)a;
  const BYTE* b = (const BYTE*)&in->sin_addr;
  _snprintf_s(out, size, _TRUNCATE, "%u.%u.%u.%u:%u", b[0], b[1], b[2], b[3], ntohs(in->sin_port));
}

// Retail XNet ignores XNET_STARTUP_BYPASS_SECURITY (devkit only), so the game's
// sockets stay secure and silently drop plain packets from Xenia. Mark each TCP/UDP
// socket insecure, like http.cpp does for our own sockets. VDP sockets can't be
// marked (setsockopt fails), and Xenia treats VDP as plain UDP anyway, so in-match
// VDP sockets (proto 254, port 1000) are created as UDP instead.
static int MarkInsecure(DWORD caller, SOCKET s) {
  BOOL yes = TRUE;
  if (!g_orig_setsockopt) return -1;
  int r = g_orig_setsockopt(caller, s, SOL_SOCKET, SO_MARKINSECURE, (const char*)&yes, sizeof(yes));
  return r ? LastNetError() : 0;
}

static SOCKET Hook_socket(DWORD caller, int af, int type, int protocol) {
  int real_protocol = protocol;
  if (af == AF_INET && protocol == IPPROTO_VDP) real_protocol = IPPROTO_UDP;
  SOCKET s = g_orig_socket(caller, af, type, real_protocol);
  int mark = -2;
  if (s != INVALID_SOCKET && af == AF_INET &&
      (real_protocol == 0 || real_protocol == IPPROTO_TCP || real_protocol == IPPROTO_UDP))
    mark = MarkInsecure(caller, s);
  LOG_FIRST(g_l_sock, "net: socket(af %d, type %d, proto %d%s) -> %08X, insecure %d", af, type,
            protocol, real_protocol != protocol ? " as UDP" : "", (DWORD)s, mark);
  return s;
}

static int Hook_bind(DWORD caller, SOCKET s, const sockaddr* name, int len) {
  int r = g_orig_bind(caller, s, name, len);
  char a[32];
  FormatAddr(name, a, sizeof(a));
  LOG_FIRST(g_l_bind, "net: bind(%08X, %s) -> %d (err %d)", (DWORD)s, a, r, r ? LastNetError() : 0);
  return r;
}

static int Hook_listen(DWORD caller, SOCKET s, int backlog) {
  int r = g_orig_listen(caller, s, backlog);
  LOG_FIRST(g_l_listen, "net: listen(%08X, %d) -> %d (err %d)", (DWORD)s, backlog, r, r ? LastNetError() : 0);
  return r;
}

static SOCKET Hook_accept(DWORD caller, SOCKET s, sockaddr* addr, int* len) {
  SOCKET r = g_orig_accept(caller, s, addr, len);
  if (r != INVALID_SOCKET) {
    MarkInsecure(caller, r);
    char a[32];
    FormatAddr(addr, a, sizeof(a));
    Log("net: accept(%08X) -> %08X from %s", (DWORD)s, (DWORD)r, a);
  } else {
    int err = LastNetError();
    if (err != WSAEWOULDBLOCK) LOG_FIRST_ERR(g_l_accept_err, "net: accept(%08X) failed, err %d", (DWORD)s, err);
  }
  return r;
}

typedef int (*NetSendto_t)(DWORD caller, SOCKET s, const char* buf, int len, int flags,
                           const sockaddr* to, int tolen);
typedef int (*NetRecvfrom_t)(DWORD caller, SOCKET s, char* buf, int len, int flags,
                             sockaddr* from, int* fromlen);
static NetSendto_t g_orig_sendto;
static NetRecvfrom_t g_orig_recvfrom;
static DWORD g_l_sendto, g_l_sendto_err, g_l_recv, g_l_recv_err;

static int Hook_sendto(DWORD caller, SOCKET s, const char* buf, int len, int flags,
                       const sockaddr* to, int tolen) {
  int r = g_orig_sendto(caller, s, buf, len, flags, to, tolen);
  char a[32];
  FormatAddr(to, a, sizeof(a));
  if (r < 0) {
    LOG_FIRST_ERR(g_l_sendto_err, "net: sendto(%08X, %d B -> %s) failed, err %d", (DWORD)s, len, a, LastNetError());
  } else {
    LOG_FIRST(g_l_sendto, "net: sendto(%08X, %d B -> %s) -> %d", (DWORD)s, len, a, r);
  }
  return r;
}

static int Hook_recvfrom(DWORD caller, SOCKET s, char* buf, int len, int flags,
                         sockaddr* from, int* fromlen) {
  int r = g_orig_recvfrom(caller, s, buf, len, flags, from, fromlen);
  if (r >= 0) {
    char a[32];
    FormatAddr(from, a, sizeof(a));
    LOG_FIRST(g_l_recv, "net: recvfrom(%08X) %d B from %s", (DWORD)s, r, a);
  } else {
    int err = LastNetError();
    if (err != WSAEWOULDBLOCK) LOG_FIRST_ERR(g_l_recv_err, "net: recvfrom(%08X) failed, err %d", (DWORD)s, err);
  }
  return r;
}

static int Hook_connect(DWORD caller, SOCKET s, const sockaddr* name, int len) {
  int r = g_orig_connect(caller, s, name, len);
  char a[32];
  FormatAddr(name, a, sizeof(a));
  LOG_FIRST(g_l_tcpconn, "net: connect(%08X, %s) -> %d (err %d)", (DWORD)s, a, r, r ? LastNetError() : 0);
  return r;
}

// ---- install -----------------------------------------------------------------

VOID XNetSetTitleActive(BOOL active) { g_title_active = active; }

DWORD InstallXNetHooks(PLDR_DATA_TABLE_ENTRY title) {
  static BOOL once = FALSE;
  if (!once) {
    once = TRUE;
    InitializeCriticalSection(&g_peer_lock);
    g_orig_XexCheckPrivilege = (XexCheckExecutablePrivilege_t)ResolveFunction(
        MODULE_KERNEL, ORD_XexCheckExecutablePrivilege);
    HANDLE xam = NULL;
    if (XexGetModuleHandle(MODULE_XAM, &xam) == 0 && xam) {
      PatchModuleImport((PLDR_DATA_TABLE_ENTRY)xam, MODULE_KERNEL,
                        ORD_XexCheckExecutablePrivilege,
                        (DWORD)Hook_XexCheckExecutablePrivilege);
    }
  }
  g_peer_count = 0;
  g_title_active = TRUE;

  g_orig_XNetStartup = (XNetStartup_t)ResolveFunction(MODULE_XAM, ORD_NetDll_XNetStartup);
  g_orig_XNetGetTitleXnAddr =
      (XNetGetTitleXnAddr_t)ResolveFunction(MODULE_XAM, ORD_NetDll_XNetGetTitleXnAddr);
  g_orig_XNetDnsLookup =
      (XNetDnsLookup_t)ResolveFunction(MODULE_XAM, ORD_NetDll_XNetDnsLookup);
  g_orig_socket = (NetSocket_t)ResolveFunction(MODULE_XAM, ORD_NetDll_socket);
  g_orig_bind = (NetBind_t)ResolveFunction(MODULE_XAM, ORD_NetDll_bind);
  g_orig_listen = (NetListen_t)ResolveFunction(MODULE_XAM, ORD_NetDll_listen);
  g_orig_accept = (NetAccept_t)ResolveFunction(MODULE_XAM, ORD_NetDll_accept);
  g_orig_connect = (NetConnect_t)ResolveFunction(MODULE_XAM, ORD_NetDll_connect);
  g_orig_sendto = (NetSendto_t)ResolveFunction(MODULE_XAM, ORD_NetDll_sendto);
  g_orig_recvfrom = (NetRecvfrom_t)ResolveFunction(MODULE_XAM, ORD_NetDll_recvfrom);
  g_orig_setsockopt = (NetSetsockopt_t)ResolveFunction(MODULE_XAM, ORD_NetDll_setsockopt);
  g_orig_WSAGetLastError =
      (NetGetLastError_t)ResolveFunction(MODULE_XAM, ORD_NetDll_WSAGetLastError);

  struct { DWORD ordinal; DWORD hook; } hooks[] = {
      {ORD_NetDll_XNetStartup, (DWORD)Hook_XNetStartup},
      {ORD_NetDll_XNetGetTitleXnAddr, (DWORD)Hook_XNetGetTitleXnAddr},
      {ORD_NetDll_XNetXnAddrToInAddr, (DWORD)Hook_XNetXnAddrToInAddr},
      {ORD_NetDll_XNetInAddrToXnAddr, (DWORD)Hook_XNetInAddrToXnAddr},
      {ORD_NetDll_XNetRegisterKey, (DWORD)Hook_XNetRegisterKey},
      {ORD_NetDll_XNetUnregisterKey, (DWORD)Hook_XNetUnregisterKey},
      {ORD_NetDll_XNetConnect, (DWORD)Hook_XNetConnect},
      {ORD_NetDll_XNetGetConnectStatus, (DWORD)Hook_XNetGetConnectStatus},
      {ORD_NetDll_XNetQosListen, (DWORD)Hook_XNetQosListen},
      {ORD_NetDll_XNetQosLookup, (DWORD)Hook_XNetQosLookup},
      {ORD_NetDll_XNetQosRelease, (DWORD)Hook_XNetQosRelease},
      {ORD_NetDll_XNetDnsLookup, (DWORD)Hook_XNetDnsLookup},
      {ORD_NetDll_socket, (DWORD)Hook_socket},
      {ORD_NetDll_bind, (DWORD)Hook_bind},
      {ORD_NetDll_listen, (DWORD)Hook_listen},
      {ORD_NetDll_accept, (DWORD)Hook_accept},
      {ORD_NetDll_connect, (DWORD)Hook_connect},
      {ORD_NetDll_sendto, (DWORD)Hook_sendto},
      {ORD_NetDll_recvfrom, (DWORD)Hook_recvfrom},
  };
  DWORD patched = 0;
  for (int i = 0; i < ARRAYSIZE(hooks); i++) {
    if (PatchModuleImport(title, MODULE_XAM, hooks[i].ordinal, hooks[i].hook) == S_OK)
      patched++;
  }

  g_orig_XexGetProcedureAddress = (XexGetProcedureAddress_t)ResolveFunction(
      MODULE_KERNEL, ORD_XexGetProcedureAddress);
  if (PatchModuleImport(title, MODULE_KERNEL, ORD_XexGetProcedureAddress,
                        (DWORD)Hook_XexGetProcedureAddress) == S_OK)
    patched++;
  return patched;
}
