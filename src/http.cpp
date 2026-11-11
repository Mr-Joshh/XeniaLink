#include "http.h"
#include "kernel.h"
#include "config.h"
#include "log.h"
#include "tls.h"
#include <winsockx.h>
#include <stdio.h>
#include <stdlib.h>

static BOOL g_net_up = FALSE;

BOOL HttpEnsureNetwork() {
  if (g_net_up) return TRUE;

  XNetStartupParams xnsp;
  memset(&xnsp, 0, sizeof(xnsp));
  xnsp.cfgSizeOfStruct = sizeof(xnsp);
  xnsp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;
  // Fails harmlessly if the title already started XNet.
  XNetStartup(&xnsp);

  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    Log("http: WSAStartup failed %d", WSAGetLastError());
    return FALSE;
  }
  g_net_up = TRUE;
  return TRUE;
}

// ---- DNS (cached: every API request goes to the same host) -----------------

#define DNS_CACHE_MS (10 * 60 * 1000)
static CRITICAL_SECTION g_dns_lock;
static volatile LONG g_dns_lock_init;
static char g_dns_host[128];
static IN_ADDR g_dns_addr;
static DWORD g_dns_time;

static void DnsLockInit() {
  if (InterlockedCompareExchange(&g_dns_lock_init, 1, 0) == 0) {
    InitializeCriticalSection(&g_dns_lock);
    g_dns_lock_init = 2;
  }
  while (g_dns_lock_init != 2) Sleep(1);
}

static void ForgetHost() {
  DnsLockInit();
  EnterCriticalSection(&g_dns_lock);
  g_dns_host[0] = 0;
  LeaveCriticalSection(&g_dns_lock);
}

static BOOL ResolveHost(const char* host, IN_ADDR* out) {
  out->s_addr = inet_addr(host);
  if (out->s_addr != INADDR_NONE) return TRUE;

  DnsLockInit();
  EnterCriticalSection(&g_dns_lock);
  BOOL cached = g_dns_host[0] && strcmp(g_dns_host, host) == 0 &&
                GetTickCount() - g_dns_time < DNS_CACHE_MS;
  if (cached) *out = g_dns_addr;
  LeaveCriticalSection(&g_dns_lock);
  if (cached) return TRUE;

  XNDNS* dns = NULL;
  if (XNetDnsLookup(host, NULL, &dns) != 0 || !dns) return FALSE;
  while (dns->iStatus == WSAEINPROGRESS) Sleep(10);
  BOOL ok = dns->iStatus == 0 && dns->cina > 0;
  if (ok) *out = dns->aina[0];
  XNetDnsRelease(dns);

  if (ok) {
    EnterCriticalSection(&g_dns_lock);
    strncpy_s(g_dns_host, sizeof(g_dns_host), host, _TRUNCATE);
    g_dns_addr = *out;
    g_dns_time = GetTickCount();
    LeaveCriticalSection(&g_dns_lock);
  }
  return ok;
}

BOOL HttpFindHeader(const char* headers, const char* name, char* out, DWORD out_size) {
  if (!headers) return FALSE;
  size_t name_len = strlen(name);
  for (const char* line = strstr(headers, "\r\n"); line; line = strstr(line, "\r\n")) {
    line += 2;
    if (_strnicmp(line, name, name_len) == 0 && line[name_len] == ':') {
      const char* v = line + name_len + 1;
      while (*v == ' ') v++;
      DWORD n = 0;
      while (v[n] && v[n] != '\r' && n + 1 < out_size) { out[n] = v[n]; n++; }
      out[n] = 0;
      return TRUE;
    }
  }
  return FALSE;
}

// Decodes a chunked body in place. Returns the decoded length.
static DWORD Dechunk(char* body, DWORD len) {
  char* in = body;
  char* end = body + len;
  char* out = body;
  while (in < end) {
    DWORD chunk = strtoul(in, NULL, 16);
    char* data = strstr(in, "\r\n");
    if (!data || chunk == 0) break;
    data += 2;
    if (data + chunk > end) chunk = (DWORD)(end - data);
    memmove(out, data, chunk);
    out += chunk;
    in = data + chunk + 2;  // skip CRLF after the chunk
  }
  *out = 0;
  return (DWORD)(out - body);
}

// ---- connections -----------------------------------------------------------
// A plain or TLS connection. The API connection is kept open between requests
// (HTTP keep-alive), so a request costs one round trip instead of DNS + TCP
// connect + TLS handshake + request.

struct Conn {
  SOCKET s;
  TlsConn* tls;
  DWORD last_used;
};

static BOOL ConnOpen(Conn* c, const char* host, WORD port, BOOL tls) {
  c->s = INVALID_SOCKET;
  c->tls = NULL;
  if (!HttpEnsureNetwork()) return FALSE;

  IN_ADDR addr;
  if (!ResolveHost(host, &addr)) {
    Log("http: cannot resolve %s", host);
    return FALSE;
  }

  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return FALSE;
  BOOL yes = TRUE;
  setsockopt(s, SOL_SOCKET, SO_MARKINSECURE, (const char*)&yes, sizeof(yes));
  int timeout_ms = 15000;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
  // Requests are small and one per round trip: send them immediately.
  setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&yes, sizeof(yes));

  sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr = addr;
  if (connect(s, (sockaddr*)&sa, sizeof(sa)) != 0) {
    Log("http: connect %s:%u failed %d", host, port, WSAGetLastError());
    closesocket(s);
    ForgetHost();  // the server may have moved
    return FALSE;
  }

  if (tls) {
    c->tls = TlsConnect(s, host);
    if (!c->tls) {
      closesocket(s);
      return FALSE;
    }
  }
  c->s = s;
  c->last_used = GetTickCount();
  return TRUE;
}

static void ConnClose(Conn* c) {
  if (c->tls) TlsClose(c->tls);
  if (c->s != INVALID_SOCKET) closesocket(c->s);
  c->s = INVALID_SOCKET;
  c->tls = NULL;
}

static BOOL ConnSend(Conn* c, const char* data, int len) {
  if (c->tls) return TlsWriteAll(c->tls, data, len);
  while (len > 0) {
    int n = send(c->s, data, len, 0);
    if (n <= 0) return FALSE;
    data += n;
    len -= n;
  }
  return TRUE;
}

static int ConnRecv(Conn* c, char* buf, int len) {
  return c->tls ? TlsRead(c->tls, buf, len) : recv(c->s, buf, len, 0);
}

// Reads one response. Uses Content-Length / chunked framing so the connection
// can be reused; falls back to reading until the server closes. *reusable says
// whether the connection can carry another request.
static BOOL ReadResponse(Conn* c, HttpResponse* out, BOOL* reusable) {
  *reusable = FALSE;
  DWORD cap = 8192, len = 0;
  char* buf = (char*)malloc(cap);
  if (!buf) return FALSE;

  DWORD header_len = 0;       // up to (not including) the blank line
  long content_length = -1;   // -1 = unknown
  BOOL chunked = FALSE, closed = FALSE, have_headers = FALSE, ok = TRUE;
  char* headers = NULL;

  for (;;) {
    if (have_headers) {
      DWORD body_len = len - (header_len + 4);
      if (content_length >= 0 && body_len >= (DWORD)content_length) break;
      if (chunked && body_len >= 5 &&
          (memcmp(buf + len - 5, "0\r\n\r\n", 5) == 0)) break;
    }
    if (len + 2048 + 1 > cap) {
      cap *= 2;
      char* grown = (char*)realloc(buf, cap);
      if (!grown) { ok = FALSE; break; }
      buf = grown;
    }
    int n = ConnRecv(c, buf + len, 2048);
    if (n < 0) { ok = FALSE; break; }
    if (n == 0) { closed = TRUE; break; }
    len += n;
    buf[len] = 0;

    if (!have_headers) {
      char* sep = strstr(buf, "\r\n\r\n");
      if (!sep) continue;
      have_headers = TRUE;
      header_len = (DWORD)(sep - buf);
      headers = (char*)malloc(header_len + 1);
      if (!headers) { ok = FALSE; break; }
      memcpy(headers, buf, header_len);
      headers[header_len] = 0;
      char value[32];
      if (HttpFindHeader(headers, "Content-Length", value, sizeof(value)))
        content_length = atol(value);
      if (HttpFindHeader(headers, "Transfer-Encoding", value, sizeof(value)) &&
          _stricmp(value, "chunked") == 0)
        chunked = TRUE;
      int status = atoi(headers + 9);
      if (status == 204 || status == 304) content_length = 0;  // never a body
    }
  }

  if (!ok || !have_headers || len < 12) {
    free(buf);
    free(headers);
    return FALSE;
  }
  buf[len] = 0;

  char* body = buf + header_len + 4;
  DWORD body_len = (DWORD)(buf + len - body);
  if (content_length >= 0 && body_len > (DWORD)content_length) body_len = content_length;
  memmove(buf, body, body_len);
  buf[body_len] = 0;
  if (chunked) body_len = Dechunk(buf, body_len);

  char value[32];
  BOOL server_closes = HttpFindHeader(headers, "Connection", value, sizeof(value)) &&
                       _stricmp(value, "close") == 0;
  *reusable = !closed && !server_closes && (content_length >= 0 || chunked);

  out->status = atoi(headers + 9);
  out->headers = headers;
  out->body = buf;
  out->body_len = body_len;
  return TRUE;
}

BOOL HttpExchange(const char* host, WORD port, const char* request, DWORD request_len,
                  HttpResponse* out) {
  return HttpExchangeEx(host, port, FALSE, request, request_len, out);
}

BOOL HttpExchangeEx(const char* host, WORD port, BOOL tls, const char* request,
                    DWORD request_len, HttpResponse* out) {
  memset(out, 0, sizeof(*out));
  out->status = -1;
  Conn c;
  if (!ConnOpen(&c, host, port, tls)) return FALSE;
  BOOL reusable;
  BOOL ok = ConnSend(&c, request, (int)request_len) && ReadResponse(&c, out, &reusable);
  ConnClose(&c);
  return ok;
}

// ---- API requests ----------------------------------------------------------

// Kept-alive API connections. The console often sends two calls at once (a QoS
// upload next to a session modify), so there are two; a third request waits
// for the first one to free up rather than paying for a new handshake. A slot
// idle for API_IDLE_MS is closed (Heroku drops idle connections, and an unused
// TLS connection holds ~20 KB).
#define API_SLOTS 2
#define API_IDLE_MS 60000
struct ApiSlot {
  CRITICAL_SECTION lock;
  Conn conn;
};
static ApiSlot g_api[API_SLOTS];
static volatile LONG g_api_init;

static void ApiInit() {
  if (InterlockedCompareExchange(&g_api_init, 1, 0) == 0) {
    for (int i = 0; i < API_SLOTS; i++) {
      InitializeCriticalSection(&g_api[i].lock);
      g_api[i].conn.s = INVALID_SOCKET;
      g_api[i].conn.tls = NULL;
    }
    g_api_init = 2;
  }
  while (g_api_init != 2) Sleep(1);
}

// Locks a free slot (or waits for slot 0). Also closes other idle slots.
static ApiSlot* ApiAcquire() {
  ApiSlot* got = NULL;
  for (int i = 0; i < API_SLOTS; i++) {
    if (!TryEnterCriticalSection(&g_api[i].lock)) continue;
    Conn* c = &g_api[i].conn;
    if (c->s != INVALID_SOCKET && GetTickCount() - c->last_used > API_IDLE_MS) ConnClose(c);
    if (!got && (c->s != INVALID_SOCKET || i == API_SLOTS - 1 ||
                 g_api[i + 1].conn.s == INVALID_SOCKET)) {
      got = &g_api[i];  // prefer a slot that already has an open connection
    } else {
      LeaveCriticalSection(&g_api[i].lock);
    }
  }
  if (!got) {
    for (int i = 0; i < API_SLOTS && !got; i++) {
      if (TryEnterCriticalSection(&g_api[i].lock)) got = &g_api[i];
    }
  }
  if (!got) {
    EnterCriticalSection(&g_api[0].lock);
    got = &g_api[0];
  }
  return got;
}

BOOL HttpRequest(const char* method, const char* path, const char* json_body,
                 HttpResponse* out) {
  return HttpRequestEx(method, path, json_body, json_body ? (DWORD)strlen(json_body) : 0,
                       json_body ? "application/json" : NULL, out);
}

BOOL HttpRequestEx(const char* method, const char* path, const VOID* body, DWORD body_len,
                   const char* content_type, HttpResponse* out) {
  memset(out, 0, sizeof(*out));
  out->status = -1;
  ApiInit();

  char* request = (char*)malloc(1024 + body_len);
  if (!request) return FALSE;
  int len = _snprintf_s(
      request, 1024, _TRUNCATE,
      "%s %s%s HTTP/1.1\r\n"
      "Host: %s\r\n"
      "User-Agent: XeniaLink/0.1.0\r\n"
      "Accept: application/json\r\n"
      "Connection: keep-alive\r\n"
      "%s%s%s"
      "Content-Length: %u\r\n\r\n",
      method, g_config.api_base_path, path, g_config.api_host,
      content_type ? "Content-Type: " : "", content_type ? content_type : "",
      content_type ? "\r\n" : "", body_len);
  if (len < 0) {
    free(request);
    return FALSE;
  }
  if (body_len) memcpy(request + len, body, body_len);
  DWORD total = len + body_len;
  DWORD t0 = GetTickCount();
  BOOL ok = FALSE, reused = FALSE;

  ApiSlot* slot = ApiAcquire();
  DWORD waited = GetTickCount() - t0;
  Conn* c = &slot->conn;
  // Use the kept-alive connection; if it went stale (the server closed it),
  // retry once on a fresh one.
  for (int attempt = 0; attempt < 2 && !ok; attempt++) {
    reused = c->s != INVALID_SOCKET;
    if (!reused && !ConnOpen(c, g_config.api_host, g_config.api_port, g_config.api_tls))
      break;
    BOOL reusable = FALSE;
    ok = ConnSend(c, request, (int)total) && ReadResponse(c, out, &reusable);
    if (!ok || !reusable) ConnClose(c);
    else c->last_used = GetTickCount();
    if (!ok && !reused) break;  // a fresh connection failed: don't retry
  }
  LeaveCriticalSection(&slot->lock);

  LogDebug("http: %s %s -> %d in %u ms (slot %d, %s%s)", method, path, out->status,
           GetTickCount() - t0, (int)(slot - g_api), reused ? "kept-alive" : "new connection",
           waited > 20 ? ", waited for a free slot" : "");
  free(request);
  return ok;
}

VOID HttpFree(HttpResponse* resp) {
  free(resp->headers);
  free(resp->body);
  resp->headers = NULL;
  resp->body = NULL;
}
