// XHttp, implemented inside the plugin.
//
// The console's own XHttp only talks to services that Xbox Live has approved
// for the title (checked through XAuth), so it can't reach a community backend
// while offline. Like the Xenia First Assault build, the plugin implements the
// XHttp API itself over plain TCP sockets.
//
// Model (same as WinHTTP async): API calls queue status callbacks, and the game
// pumps them by calling XHttpDoWork on its session handle. The actual network
// exchange happens on a worker thread started by XHttpReceiveResponse.

#include "hooks.h"
#include "hooking.h"
#include "config.h"
#include "http.h"
#include "log.h"
#include <xhttp.h>
#include <stdio.h>
#include <stdlib.h>

#define XH_MAGIC 0x58484E44  // 'XHND'

extern volatile BOOL g_xhttp_connected;  // hooks_xauth.cpp

enum XhType { XH_SESSION = 1, XH_CONNECT, XH_REQUEST };

struct XhEvent;

struct XhHandle {
  DWORD magic;
  XhType type;
  XhHandle* session;   // owning session (self for sessions)
  XhHandle* parent;    // connect for requests, session for connects
  XHTTP_STATUS_CALLBACK callback;
  DWORD callback_flags;
  BOOL closed;
  LONG refs;           // freed when it reaches zero

  // session
  CRITICAL_SECTION lock;
  XhEvent* events_head;
  XhEvent* events_tail;

  // connect
  char host[128];
  WORD port;

  // request
  char verb[16];
  char* path;
  char* extra_headers;
  BYTE* body;
  DWORD body_len, body_cap, total_len;
  DWORD_PTR context;
  HttpResponse response;
  DWORD read_pos;
  volatile BOOL worker_running;
};

struct XhEvent {
  XhEvent* next;
  XhHandle* handle;
  DWORD status;
  PVOID info;          // points at info_buf or a caller buffer
  DWORD info_len;
  BYTE info_buf[16];
};

static XhHandle* AsHandle(HINTERNET h, XhType type) {
  XhHandle* x = (XhHandle*)h;
  if (!x || x->magic != XH_MAGIC || (type && x->type != type)) {
    SetLastError(ERROR_INVALID_HANDLE);
    return NULL;
  }
  return x;
}

static VOID Release(XhHandle* h) {
  if (InterlockedDecrement(&h->refs) != 0) return;
  if (h->type == XH_SESSION) DeleteCriticalSection(&h->lock);
  if (h->type == XH_REQUEST) {
    free(h->path);
    free(h->extra_headers);
    free(h->body);
    HttpFree(&h->response);
  }
  if (h->parent) Release(h->parent);
  h->magic = 0;
  free(h);
}

static XhHandle* NewHandle(XhType type, XhHandle* parent) {
  XhHandle* h = (XhHandle*)calloc(1, sizeof(XhHandle));
  if (!h) return NULL;
  h->magic = XH_MAGIC;
  h->type = type;
  h->refs = 1;
  h->parent = parent;
  if (parent) {
    InterlockedIncrement(&parent->refs);
    h->session = parent->session;
    // Children inherit the callback that was set when they were created.
    h->callback = parent->callback;
    h->callback_flags = parent->callback_flags;
  } else {
    h->session = h;
    InitializeCriticalSection(&h->lock);
  }
  return h;
}

// Queues a callback; XHttpDoWork on the session delivers it.
static VOID Post(XhHandle* h, DWORD status, const VOID* info, DWORD info_len,
                 PVOID external_info = NULL) {
  XhEvent* e = (XhEvent*)calloc(1, sizeof(XhEvent));
  if (!e) return;
  e->handle = h;
  e->status = status;
  e->info_len = info_len;
  if (external_info) {
    e->info = external_info;
  } else {
    if (info && info_len <= sizeof(e->info_buf)) memcpy(e->info_buf, info, info_len);
    e->info = e->info_buf;
  }
  InterlockedIncrement(&h->refs);
  XhHandle* s = h->session;
  EnterCriticalSection(&s->lock);
  if (s->events_tail) s->events_tail->next = e; else s->events_head = e;
  s->events_tail = e;
  LeaveCriticalSection(&s->lock);
}

static VOID PostError(XhHandle* h, DWORD api, DWORD error) {
  XHTTP_ASYNC_RESULT r;
  r.dwResult = api;
  r.dwError = error;
  Post(h, XHTTP_CALLBACK_STATUS_REQUEST_ERROR, &r, sizeof(r));
}

// "127.0.0.1"/"localhost" -> xhttp_host (config).
static VOID RewriteHost(const char* in, char* out, DWORD out_size) {
  if (g_config.xhttp_host[0] &&
      (!_stricmp(in, "127.0.0.1") || !_stricmp(in, "localhost"))) {
    strcpy_s(out, out_size, g_config.xhttp_host);
    Log("xhttp: redirecting %s -> %s", in, out);
  } else {
    strcpy_s(out, out_size, in);
  }
}

// ---- API -----------------------------------------------------------------------

static BOOL Hook_XHttpStartup(DWORD caller, DWORD reserved, PVOID reserved2) {
  return HttpEnsureNetwork();
}

static VOID Hook_XHttpShutdown(DWORD caller) {}

static HINTERNET Hook_XHttpOpen(DWORD caller, const CHAR* user_agent, DWORD access_type,
                                const CHAR* proxy, const CHAR* bypass, DWORD flags) {
  XhHandle* s = NewHandle(XH_SESSION, NULL);
  LogDebug("xhttp: Open '%s' -> %p", user_agent ? user_agent : "", s);
  return s;
}

static HINTERNET Hook_XHttpConnect(DWORD caller, HINTERNET session, const CHAR* server,
                                   INTERNET_PORT port, DWORD flags) {
  XhHandle* s = AsHandle(session, XH_SESSION);
  if (!s || !server) return NULL;
  XhHandle* c = NewHandle(XH_CONNECT, s);
  if (!c) return NULL;
  RewriteHost(server, c->host, sizeof(c->host));
  c->port = port ? port : INTERNET_DEFAULT_HTTP_PORT;
  LogDebug("xhttp: Connect %s:%u -> %p", c->host, c->port, c);
  g_xhttp_connected = TRUE;
  return c;
}

static HINTERNET Hook_XHttpOpenRequest(DWORD caller, HINTERNET connect, const CHAR* verb,
                                       const CHAR* object, const CHAR* version,
                                       const CHAR* referrer, const CHAR** reserved,
                                       DWORD flags) {
  XhHandle* c = AsHandle(connect, XH_CONNECT);
  if (!c) return NULL;
  XhHandle* r = NewHandle(XH_REQUEST, c);
  if (!r) return NULL;
  strcpy_s(r->verb, sizeof(r->verb), verb && *verb ? verb : "GET");
  r->path = _strdup(object && *object ? object : "/");
  if (flags & XHTTP_FLAG_SECURE) {
    Log("xhttp: request wants HTTPS; sending plain HTTP (no TLS on console yet)");
  }
  LogDebug("xhttp: OpenRequest %s %s -> %p", r->verb, r->path, r);
  return r;
}

static BOOL Hook_XHttpSetOption(DWORD caller, HINTERNET h, DWORD option, const VOID* buffer,
                                DWORD length) {
  return AsHandle(h, (XhType)0) != NULL;
}

static BOOL Hook_XHttpQueryOption(DWORD caller, HINTERNET h, DWORD option, VOID* buffer,
                                  DWORD* length) {
  SetLastError(ERROR_INVALID_PARAMETER);
  return FALSE;
}

static XHTTP_STATUS_CALLBACK Hook_XHttpSetStatusCallback(DWORD caller, HINTERNET h,
                                                         XHTTP_STATUS_CALLBACK callback,
                                                         DWORD flags, DWORD_PTR reserved) {
  XhHandle* x = AsHandle(h, (XhType)0);
  if (!x) return (XHTTP_STATUS_CALLBACK)(-1);
  XHTTP_STATUS_CALLBACK prev = x->callback;
  x->callback = callback;
  x->callback_flags = flags;
  return prev;
}

static BOOL AppendBody(XhHandle* r, const VOID* data, DWORD len) {
  if (!len) return TRUE;
  if (r->body_len + len > r->body_cap) {
    DWORD cap = max(r->body_cap * 2, r->body_len + len);
    BYTE* grown = (BYTE*)realloc(r->body, cap);
    if (!grown) return FALSE;
    r->body = grown;
    r->body_cap = cap;
  }
  memcpy(r->body + r->body_len, data, len);
  r->body_len += len;
  return TRUE;
}

static BOOL Hook_XHttpSendRequest(DWORD caller, HINTERNET request, const CHAR* headers,
                                  DWORD headers_len, const VOID* optional,
                                  DWORD optional_len, DWORD total_len, DWORD_PTR context) {
  XhHandle* r = AsHandle(request, XH_REQUEST);
  if (!r) return FALSE;
  r->context = context;
  if (headers) {
    DWORD n = headers_len == (DWORD)-1 ? (DWORD)strlen(headers) : headers_len;
    free(r->extra_headers);
    r->extra_headers = (char*)malloc(n + 1);
    if (r->extra_headers) { memcpy(r->extra_headers, headers, n); r->extra_headers[n] = 0; }
  }
  r->body_len = 0;
  AppendBody(r, optional, optional_len);
  r->total_len = max(total_len, optional_len);
  LogDebug("xhttp: SendRequest %s %s (body %u/%u)", r->verb, r->path, r->body_len, r->total_len);
  if (r->extra_headers) {
    // One line per header, shortened (bearer tokens are long).
    char line[120];
    const char* p = r->extra_headers;
    while (*p) {
      const char* e = p;
      while (*e && *e != 13 && *e != 10) e++;  // CR / LF
      DWORD n = min((DWORD)(e - p), (DWORD)sizeof(line) - 1);
      if (n) {
        memcpy(line, p, n);
        line[n] = 0;
        LogDebug("xhttp:   > %s", line);
      }
      while (*e == 13 || *e == 10) e++;
      p = e;
    }
  }
  if (r->body_len && r->body_len < 200) {
    char body[200];
    memcpy(body, r->body, r->body_len);
    body[r->body_len] = 0;
    LogDebug("xhttp:   body %s", body);
  }
  Post(r, XHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE, NULL, 0);
  return TRUE;
}

static BOOL Hook_XHttpWriteData(DWORD caller, HINTERNET request, const VOID* buffer,
                                DWORD len, DWORD* written) {
  XhHandle* r = AsHandle(request, XH_REQUEST);
  if (!r) return FALSE;
  if (!AppendBody(r, buffer, len)) {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }
  if (written) *written = len;
  Post(r, XHTTP_CALLBACK_STATUS_WRITE_COMPLETE, &len, sizeof(len));
  return TRUE;
}

static BOOL HasHeader(const char* headers, const char* name) {
  if (!headers) return FALSE;
  size_t n = strlen(name);
  for (const char* p = headers; *p; p++) {
    if ((p == headers || p[-1] == '\n') && _strnicmp(p, name, n) == 0 && p[n] == ':')
      return TRUE;
  }
  return FALSE;
}

static DWORD WINAPI ExchangeThread(LPVOID param) {
  XhHandle* r = (XhHandle*)param;
  XhHandle* c = r->parent;

  // Game headers, trimmed of trailing CRLFs; we add our own terminator.
  const char* extra = r->extra_headers ? r->extra_headers : "";
  size_t extra_len = strlen(extra);
  while (extra_len && (extra[extra_len - 1] == '\n' || extra[extra_len - 1] == '\r')) extra_len--;

  const size_t cap = 512 + strlen(r->path) + extra_len + r->body_len;
  char* req = (char*)malloc(cap);
  BOOL ok = FALSE;
  if (req) {
    int len = _snprintf_s(req, cap, _TRUNCATE, "%s %s HTTP/1.1\r\nHost: %s:%u\r\n",
                          r->verb, r->path, c->host, c->port);
    if (extra_len) {
      memcpy(req + len, extra, extra_len);
      len += (int)extra_len;
      req[len++] = '\r';
      req[len++] = '\n';
    }
    if (!HasHeader(r->extra_headers, "Content-Length") &&
        (r->body_len || _stricmp(r->verb, "GET") != 0)) {
      len += _snprintf_s(req + len, cap - len, _TRUNCATE, "Content-Length: %u\r\n", r->body_len);
    }
    len += _snprintf_s(req + len, cap - len, _TRUNCATE, "Connection: close\r\n\r\n");
    if (r->body_len) {
      memcpy(req + len, r->body, r->body_len);
      len += r->body_len;
    }
    ok = HttpExchange(c->host, c->port, req, len, &r->response);
    free(req);
  }

  if (ok) {
    Log("xhttp: %s %s -> HTTP %d (%u bytes)", r->verb, r->path, r->response.status,
        r->response.body_len);
    Post(r, XHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE, NULL, 0);
  } else {
    Log("xhttp: %s %s -> connection failed", r->verb, r->path);
    PostError(r, API_RECEIVE_RESPONSE, ERROR_XHTTP_CONNECTION_ERROR);
  }
  r->worker_running = FALSE;
  Release(r);  // ref taken in ReceiveResponse
  return 0;
}

static BOOL Hook_XHttpReceiveResponse(DWORD caller, HINTERNET request, VOID* reserved) {
  XhHandle* r = AsHandle(request, XH_REQUEST);
  if (!r) return FALSE;
  if (r->worker_running) return TRUE;
  HttpFree(&r->response);
  r->read_pos = 0;
  r->worker_running = TRUE;
  InterlockedIncrement(&r->refs);
  HANDLE t = CreateThread(NULL, 0, ExchangeThread, r, 0, NULL);
  if (!t) {
    r->worker_running = FALSE;
    Release(r);
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }
  CloseHandle(t);
  return TRUE;
}

static BOOL ReturnString(const char* s, PVOID buffer, DWORD* len) {
  DWORD need = (DWORD)strlen(s);
  if (!buffer || *len < need + 1) {
    *len = need + 1;
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;
  }
  memcpy(buffer, s, need + 1);
  *len = need;
  return TRUE;
}

static BOOL ReturnNumberOrString(const char* s, DWORD level, PVOID buffer, DWORD* len) {
  if (level & XHTTP_QUERY_FLAG_NUMBER) {
    if (!buffer || *len < sizeof(DWORD)) {
      *len = sizeof(DWORD);
      SetLastError(ERROR_INSUFFICIENT_BUFFER);
      return FALSE;
    }
    *(DWORD*)buffer = strtoul(s, NULL, 10);
    *len = sizeof(DWORD);
    return TRUE;
  }
  return ReturnString(s, buffer, len);
}

static BOOL Hook_XHttpQueryHeaders(DWORD caller, HINTERNET request, DWORD level,
                                   const CHAR* name, PVOID buffer, DWORD* len, DWORD* index) {
  XhHandle* r = AsHandle(request, XH_REQUEST);
  if (!r || !len) return FALSE;
  if (!r->response.headers) {
    SetLastError(ERROR_XHTTP_HEADER_NOT_FOUND);
    return FALSE;
  }
  char value[512];
  const DWORD what = level & 0xFFFF;
  switch (what) {
    case XHTTP_QUERY_STATUS_CODE:
      _snprintf_s(value, sizeof(value), _TRUNCATE, "%d", r->response.status);
      return ReturnNumberOrString(value, level, buffer, len);
    case XHTTP_QUERY_RAW_HEADERS_CRLF:
      return ReturnString(r->response.headers, buffer, len);
    case XHTTP_QUERY_CONTENT_LENGTH:
      _snprintf_s(value, sizeof(value), _TRUNCATE, "%u", r->response.body_len);
      return ReturnNumberOrString(value, level, buffer, len);
    case XHTTP_QUERY_CONTENT_TYPE:
      if (HttpFindHeader(r->response.headers, "Content-Type", value, sizeof(value)))
        return ReturnString(value, buffer, len);
      break;
    case XHTTP_QUERY_CUSTOM:
      if (name && HttpFindHeader(r->response.headers, name, value, sizeof(value)))
        return ReturnNumberOrString(value, level, buffer, len);
      break;
    default:
      Log("xhttp: QueryHeaders level %u not handled", what);
      break;
  }
  SetLastError(ERROR_XHTTP_HEADER_NOT_FOUND);
  return FALSE;
}

static BOOL Hook_XHttpReadData(DWORD caller, HINTERNET request, VOID* buffer, DWORD len,
                               DWORD* read) {
  XhHandle* r = AsHandle(request, XH_REQUEST);
  if (!r) return FALSE;
  DWORD left = r->response.body_len > r->read_pos ? r->response.body_len - r->read_pos : 0;
  DWORD n = min(len, left);
  if (n) memcpy(buffer, r->response.body + r->read_pos, n);
  r->read_pos += n;
  if (read) *read = n;
  // READ_COMPLETE points at the caller's buffer; 0 bytes means end of body.
  Post(r, XHTTP_CALLBACK_STATUS_READ_COMPLETE, NULL, n, buffer);
  return TRUE;
}

static BOOL Hook_XHttpDoWork(DWORD caller, HINTERNET session, DWORD ms) {
  XhHandle* s = AsHandle(session, XH_SESSION);
  if (!s) return FALSE;

  // Detach the queue, then deliver without holding the lock (callbacks may
  // call back into XHttp).
  EnterCriticalSection(&s->lock);
  XhEvent* e = s->events_head;
  s->events_head = s->events_tail = NULL;
  LeaveCriticalSection(&s->lock);

  while (e) {
    XhEvent* next = e->next;
    XhHandle* h = e->handle;
    if (h->callback && (h->callback_flags & e->status) &&
        (!h->closed || e->status == XHTTP_CALLBACK_STATUS_HANDLE_CLOSING)) {
      h->callback(h, h->context, e->status, e->info, e->info_len);
    }
    Release(h);
    free(e);
    e = next;
  }
  return TRUE;
}

static BOOL Hook_XHttpCloseHandle(DWORD caller, HINTERNET h) {
  XhHandle* x = AsHandle(h, (XhType)0);
  if (!x) return FALSE;
  x->closed = TRUE;
  if (x->type != XH_SESSION && x->callback &&
      (x->callback_flags & XHTTP_CALLBACK_STATUS_HANDLE_CLOSING)) {
    Post(x, XHTTP_CALLBACK_STATUS_HANDLE_CLOSING, &x, sizeof(x));
  }
  if (x->type == XH_SESSION) {
    // Drop anything still queued.
    EnterCriticalSection(&x->lock);
    XhEvent* e = x->events_head;
    x->events_head = x->events_tail = NULL;
    LeaveCriticalSection(&x->lock);
    while (e) {
      XhEvent* n = e->next;
      Release(e->handle);  // each queued event holds a reference
      free(e);
      e = n;
    }
  }
  Release(x);
  return TRUE;
}

// Copies or points at one URL component per the URL_COMPONENTS rules.
static BOOL SetComponent(LPSTR* field, DWORD* field_len, const char* src, DWORD len) {
  if (!*field && !*field_len) return TRUE;  // not requested
  if (!*field) {                            // return a pointer into the input
    *field = (LPSTR)src;
    *field_len = len;
    return TRUE;
  }
  if (*field_len <= len) {                  // caller buffer too small
    *field_len = len + 1;
    return FALSE;
  }
  memcpy(*field, src, len);
  (*field)[len] = 0;
  *field_len = len;
  return TRUE;
}

static BOOL Hook_XHttpCrackUrl(DWORD caller, const CHAR* url, DWORD url_len, DWORD flags,
                               PURL_COMPONENTS c) {
  if (!url || !c) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }
  if (!url_len) url_len = (DWORD)strlen(url);
  const char* p = url;
  const char* end = url + url_len;

  const char* colon = strstr(p, "://");
  if (!colon || colon >= end) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }
  DWORD scheme_len = (DWORD)(colon - p);
  BOOL https = scheme_len == 5 && _strnicmp(p, "https", 5) == 0;
  BOOL ok = SetComponent(&c->lpszScheme, &c->dwSchemeLength, p, scheme_len);
  c->nScheme = https ? INTERNET_SCHEME_HTTPS : INTERNET_SCHEME_HTTP;
  p = colon + 3;

  const char* host = p;
  while (p < end && *p != ':' && *p != '/' && *p != '?' && *p != '#') p++;
  ok &= SetComponent(&c->lpszHostName, &c->dwHostNameLength, host, (DWORD)(p - host));

  c->nPort = https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
  if (p < end && *p == ':') {
    c->nPort = (INTERNET_PORT)strtoul(p + 1, NULL, 10);
    p++;
    while (p < end && *p >= '0' && *p <= '9') p++;
  }

  const char* path = p;
  while (p < end && *p != '?' && *p != '#') p++;
  if (p == path) {
    ok &= SetComponent(&c->lpszUrlPath, &c->dwUrlPathLength, "/", 1);
  } else {
    ok &= SetComponent(&c->lpszUrlPath, &c->dwUrlPathLength, path, (DWORD)(p - path));
  }
  ok &= SetComponent(&c->lpszExtraInfo, &c->dwExtraInfoLength, p, (DWORD)(end - p));

  if (c->lpszUserName || c->dwUserNameLength) {
    c->dwUserNameLength = 0;
    if (c->lpszUserName) c->lpszUserName[0] = 0;
  }
  if (c->lpszPassword || c->dwPasswordLength) {
    c->dwPasswordLength = 0;
    if (c->lpszPassword) c->lpszPassword[0] = 0;
  }

  if (!ok) {
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;
  }
  return TRUE;
}

DWORD InstallXHttpHooks(PLDR_DATA_TABLE_ENTRY title) {
  if (!g_config.xhttp_emulate) return 0;

  struct { DWORD ordinal; DWORD hook; } hooks[] = {
      {ORD_NetDll_XHttpStartup, (DWORD)Hook_XHttpStartup},
      {ORD_NetDll_XHttpShutdown, (DWORD)Hook_XHttpShutdown},
      {ORD_NetDll_XHttpOpen, (DWORD)Hook_XHttpOpen},
      {ORD_NetDll_XHttpCloseHandle, (DWORD)Hook_XHttpCloseHandle},
      {ORD_NetDll_XHttpConnect, (DWORD)Hook_XHttpConnect},
      {ORD_NetDll_XHttpSetStatusCallback, (DWORD)Hook_XHttpSetStatusCallback},
      {ORD_NetDll_XHttpOpenRequest, (DWORD)Hook_XHttpOpenRequest},
      {ORD_NetDll_XHttpSendRequest, (DWORD)Hook_XHttpSendRequest},
      {ORD_NetDll_XHttpReceiveResponse, (DWORD)Hook_XHttpReceiveResponse},
      {ORD_NetDll_XHttpQueryHeaders, (DWORD)Hook_XHttpQueryHeaders},
      {ORD_NetDll_XHttpReadData, (DWORD)Hook_XHttpReadData},
      {ORD_NetDll_XHttpWriteData, (DWORD)Hook_XHttpWriteData},
      {ORD_NetDll_XHttpQueryOption, (DWORD)Hook_XHttpQueryOption},
      {ORD_NetDll_XHttpSetOption, (DWORD)Hook_XHttpSetOption},
      {ORD_NetDll_XHttpDoWork, (DWORD)Hook_XHttpDoWork},
      {ORD_NetDll_XHttpCrackUrl, (DWORD)Hook_XHttpCrackUrl},
  };
  DWORD patched = 0;
  for (int i = 0; i < ARRAYSIZE(hooks); i++) {
    if (PatchModuleImport(title, MODULE_XAM, hooks[i].ordinal, hooks[i].hook) == S_OK)
      patched++;
  }
  return patched;
}
