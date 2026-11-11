#pragma once
// Minimal TLS 1.2 client (BearSSL) over an already-connected socket, for the
// HTTPS Xenia Web Services API. Builds on the console and on the PC (test harness).

#ifdef _XBOX
#include <xtl.h>
#include <winsockx.h>
#else
#include <winsock2.h>
#include <windows.h>
#endif

struct TlsConn;

// Runs the handshake with server name `host` (SNI + certificate check).
// Returns NULL on failure (logged). The socket stays owned by the caller.
TlsConn* TlsConnect(SOCKET s, const char* host);

// Sends all bytes. Returns FALSE on error.
BOOL TlsWriteAll(TlsConn* c, const void* data, int len);

// Reads up to len bytes. Returns >0 bytes read, 0 when the server closed the
// connection, -1 on error.
int TlsRead(TlsConn* c, void* buf, int len);

// Frees the connection (keeps the session for a faster handshake next time).
VOID TlsClose(TlsConn* c);
