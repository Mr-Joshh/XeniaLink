#pragma once
#include <xtl.h>

struct HttpResponse {
  int status;        // HTTP status code, or -1 on network error
  char* headers;     // raw header block (status line + headers), NUL-terminated
  char* body;        // NUL-terminated, heap-allocated
  DWORD body_len;
};

// Sends one request to the configured API server and waits for the reply.
// method: "GET", "POST", "DELETE". path is appended to api_base_path.
// json_body may be NULL.
BOOL HttpRequest(const char* method, const char* path, const char* json_body,
                 HttpResponse* out);
// Same, with an arbitrary body (binary allowed) and content type.
BOOL HttpRequestEx(const char* method, const char* path, const VOID* body, DWORD body_len,
                   const char* content_type, HttpResponse* out);

// Sends a complete, pre-built HTTP request to host:port and reads the whole
// reply (handles Content-Length, chunked, and read-until-close bodies).
BOOL HttpExchange(const char* host, WORD port, const char* request, DWORD request_len,
                  HttpResponse* out);
// Same, optionally over TLS (BearSSL, see tls.cpp).
BOOL HttpExchangeEx(const char* host, WORD port, BOOL tls, const char* request,
                    DWORD request_len, HttpResponse* out);

VOID HttpFree(HttpResponse* resp);

// Finds a header value (case-insensitive name) in a raw header block.
// Returns FALSE if missing.
BOOL HttpFindHeader(const char* headers, const char* name, char* out, DWORD out_size);

// Brings up insecure XNet + Winsock for the title. Safe to call repeatedly.
BOOL HttpEnsureNetwork();
