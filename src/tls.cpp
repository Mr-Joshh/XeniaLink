// TLS client for the HTTPS Xenia server API. BearSSL does the
// protocol; this file supplies the socket I/O, entropy, time and trust anchors.

#ifndef _XBOX
#define _CRT_RAND_S  // rand_s() for the PC test harness
#endif
#include "tls.h"
#ifdef _XBOX
#include "log.h"
#else
VOID Log(const char* fmt, ...);  // provided by the PC test harness
#define LogDebug Log
#endif
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "bearssl.h"
}
#ifdef TLS_ANCHORS_HEADER
#include TLS_ANCHORS_HEADER  // PC test harness
#else
#include "trust_anchors.h"
#endif

#ifdef _XBOX
#include "kernel.h"
#endif

// days since 0000-01-01 (BearSSL's epoch) for 1601-01-01 (FILETIME's epoch)
#define DAYS_TO_1601 584754
// If the console clock is before 2025-01-01 it's surely unset: use 2026-11-11.
#define DAYS_2025_01_01 739617
#define DAYS_FALLBACK 740296

struct TlsConn {
  br_ssl_client_context cc;
  br_x509_minimal_context xc;
  br_sslio_context io;
  SOCKET s;
  BOOL failed;
  // Half-duplex buffer (16.7 KB instead of 33 KB): HTTP sends a request, then
  // reads the whole reply, so input and output never overlap.
  unsigned char iobuf[BR_SSL_BUFSIZE_MONO];
};

// Like br_ssl_client_init_full, but only what modern servers (Heroku) need:
// TLS 1.2, ECDHE with ChaCha20-Poly1305 or AES-GCM, RSA/ECDSA certificates.
// Leaving out CBC, CCM, 3DES, static RSA/ECDH and TLS 1.0/1.1 keeps their
// code out of the plugin (smaller image in the console's memory).
static void ClientInit(br_ssl_client_context* cc, br_x509_minimal_context* xc) {
  static const uint16_t suites[] = {
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  };
  // Certificate chains still use SHA-1..SHA-512 signatures; MD5 isn't needed.
  static const br_hash_class* hashes[] = {
    NULL, &br_sha1_vtable, &br_sha224_vtable, &br_sha256_vtable,
    &br_sha384_vtable, &br_sha512_vtable,
  };

  br_ssl_client_zero(cc);
  br_ssl_engine_set_versions(&cc->eng, BR_TLS12, BR_TLS12);
  br_x509_minimal_init(xc, &br_sha256_vtable, TAs, TAs_NUM);
  br_ssl_engine_set_suites(&cc->eng, suites, sizeof(suites) / sizeof(suites[0]));
  br_ssl_engine_set_default_rsavrfy(&cc->eng);
  br_ssl_engine_set_default_ecdsa(&cc->eng);
  br_x509_minimal_set_rsa(xc, br_ssl_engine_get_rsavrfy(&cc->eng));
  br_x509_minimal_set_ecdsa(xc, br_ssl_engine_get_ec(&cc->eng),
                            br_ssl_engine_get_ecdsa(&cc->eng));
  for (int id = br_sha1_ID; id <= br_sha512_ID; id++) {
    br_ssl_engine_set_hash(&cc->eng, id, hashes[id - 1]);
    br_x509_minimal_set_hash(xc, id, hashes[id - 1]);
  }
  br_ssl_engine_set_x509(&cc->eng, &xc->vtable);
  br_ssl_engine_set_prf_sha256(&cc->eng, &br_tls12_sha256_prf);
  br_ssl_engine_set_prf_sha384(&cc->eng, &br_tls12_sha384_prf);
  br_ssl_engine_set_default_aes_gcm(&cc->eng);
  br_ssl_engine_set_default_chapol(&cc->eng);
}

// One cached session: every request goes to the same API host.
static CRITICAL_SECTION g_session_lock;
static BOOL g_session_ready, g_have_session;
static char g_session_host[128];
static br_ssl_session_parameters g_session;
static DWORD g_handshakes;

static void TlsGlobalInit() {
  static volatile LONG once = 0;
  if (InterlockedCompareExchange(&once, 1, 0) == 0) {
    InitializeCriticalSection(&g_session_lock);
    TlsInitAnchors();
    g_session_ready = TRUE;
  }
  while (!g_session_ready) Sleep(1);
}

static void GetEntropy(unsigned char* buf, DWORD len) {
#ifdef _XBOX
  XeCryptRandom(buf, len);
#else
  for (DWORD i = 0; i < len; i++) {
    unsigned int r;
    rand_s(&r);
    buf[i] = (unsigned char)r;
  }
#endif
}

static void GetTlsTime(uint32_t* days, uint32_t* seconds) {
  FILETIME ft;
  GetSystemTimeAsFileTime(&ft);
  ULONGLONG t = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
  ULONGLONG secs = t / 10000000ULL;
  *days = (uint32_t)(secs / 86400) + DAYS_TO_1601;
  *seconds = (uint32_t)(secs % 86400);
  if (*days < DAYS_2025_01_01) {
    static BOOL warned = FALSE;
    if (!warned) {
      warned = TRUE;
      Log("tls: console clock looks unset; checking certificates against 2026-11-11");
    }
    *days = DAYS_FALLBACK;
    *seconds = 0;
  }
}

static int SockRead(void* ctx, unsigned char* buf, size_t len) {
  int n = recv(*(SOCKET*)ctx, (char*)buf, (int)len, 0);
  return n > 0 ? n : -1;
}

static int SockWrite(void* ctx, const unsigned char* buf, size_t len) {
  int n = send(*(SOCKET*)ctx, (const char*)buf, (int)len, 0);
  return n > 0 ? n : -1;
}

static void LogFailure(TlsConn* c, const char* what) {
  int err = br_ssl_engine_last_error(&c->cc.eng);
  // Common codes: 62 BR_ERR_X509_NOT_TRUSTED, 54 BR_ERR_X509_EXPIRED,
  // 56 BR_ERR_X509_BAD_SERVER_NAME, 31 BR_ERR_IO (socket), 4 BR_ERR_BAD_VERSION.
  Log("tls: %s failed, BearSSL error %d", what, err);
}

TlsConn* TlsConnect(SOCKET s, const char* host) {
  TlsGlobalInit();
  TlsConn* c = (TlsConn*)malloc(sizeof(TlsConn));
  if (!c) {
    Log("tls: out of memory");
    return NULL;
  }
  memset(c, 0, sizeof(*c));
  c->s = s;

  ClientInit(&c->cc, &c->xc);
  uint32_t days, seconds;
  GetTlsTime(&days, &seconds);
  br_x509_minimal_set_time(&c->xc, days, seconds);
  br_ssl_engine_set_buffer(&c->cc.eng, c->iobuf, sizeof(c->iobuf), 0);

  unsigned char seed[32];
  GetEntropy(seed, sizeof(seed));
  br_ssl_engine_inject_entropy(&c->cc.eng, seed, sizeof(seed));

  BOOL resume = FALSE;
  EnterCriticalSection(&g_session_lock);
  if (g_have_session && strcmp(g_session_host, host) == 0) {
    br_ssl_engine_set_session_parameters(&c->cc.eng, &g_session);
    resume = TRUE;
  }
  LeaveCriticalSection(&g_session_lock);

  if (!br_ssl_client_reset(&c->cc, host, resume ? 1 : 0)) {
    LogFailure(c, "reset");
    free(c);
    return NULL;
  }
  br_sslio_init(&c->io, &c->cc.eng, SockRead, &c->s, SockWrite, &c->s);

  // Drive the handshake now, so certificate problems show up here.
  if (br_sslio_flush(&c->io) < 0 ||
      (br_ssl_engine_current_state(&c->cc.eng) & BR_SSL_SENDAPP) == 0) {
    LogFailure(c, "handshake");
    free(c);
    return NULL;
  }

  if (g_handshakes++ < 3) {
    br_ssl_session_parameters p;
    br_ssl_engine_get_session_parameters(&c->cc.eng, &p);
    LogDebug("tls: connected to %s (TLS %04X, suite %04X%s)", host,
        (unsigned)c->cc.eng.session.version, (unsigned)p.cipher_suite,
        resume ? ", resumed" : "");
  }
  EnterCriticalSection(&g_session_lock);
  br_ssl_engine_get_session_parameters(&c->cc.eng, &g_session);
  strncpy_s(g_session_host, sizeof(g_session_host), host, _TRUNCATE);
  g_have_session = TRUE;
  LeaveCriticalSection(&g_session_lock);
  return c;
}

BOOL TlsWriteAll(TlsConn* c, const void* data, int len) {
  if (br_sslio_write_all(&c->io, data, len) < 0 || br_sslio_flush(&c->io) < 0) {
    LogFailure(c, "write");
    c->failed = TRUE;
    return FALSE;
  }
  return TRUE;
}

int TlsRead(TlsConn* c, void* buf, int len) {
  int n = br_sslio_read(&c->io, buf, len);
  if (n > 0) return n;
  int err = br_ssl_engine_last_error(&c->cc.eng);
  // A clean close_notify (OK) or the server just closing the TCP connection
  // after "Connection: close" (IO) both end the response.
  if (err == BR_ERR_OK || err == BR_ERR_IO) return 0;
  LogFailure(c, "read");
  c->failed = TRUE;
  return -1;
}

VOID TlsClose(TlsConn* c) {
  if (!c) return;
  if (c->failed) {
    // Don't resume a session that ended in an error.
    EnterCriticalSection(&g_session_lock);
    g_have_session = FALSE;
    LeaveCriticalSection(&g_session_lock);
  }
  free(c);
}
