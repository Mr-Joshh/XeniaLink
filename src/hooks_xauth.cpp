// XAuth ("non-XLSP third-party connectivity"): a real console asks Microsoft's
// STS for a signed token before talking to a game's own web backend. Offline
// that's impossible, so hand out the same mock token the Xenia First Assault
// build uses; the community backend accepts it.
//
// Also injects the "Live connected" notification the game waits for after
// XAuthStartup (Xenia does the same).

#include "hooks.h"
#include "hooking.h"
#include "config.h"
#include "log.h"
#include <xauth.h>
#include <stdlib.h>

static const char kMockToken[] = "MOCK_XBOX_STS_TOKEN_FOR_LOCAL_SERVER";

// ---- XAuth -------------------------------------------------------------------

static HRESULT Hook_XampXAuthStartup(const XAUTH_SETTINGS* settings) {
  Log("xauth: XAuthStartup (flags %08X)", settings ? settings->Flags : 0);
  if (g_config.inject_live_notify) NotifyLiveConnected();
  return S_OK;
}

static VOID Hook_XampXAuthShutdown() {}

static HRESULT Hook_XamGetToken(DWORD user_index, const CHAR* urn, DWORD urn_length,
                                RELYING_PARTY_TOKEN** token, PXOVERLAPPED overlapped) {
  LogDebug("xauth: XAuthGetToken user %u urn '%.*s'", user_index, (int)min(urn_length, 120),
      urn ? urn : "");
  if (!token) return E_INVALIDARG;

  // Match what First Assault sees under Xenia: a successful call whose token
  // pointer is empty. The game then sends "Authorization: XBL2.0 x=(null)",
  // which the community backend accepts. With a real-looking token it treats the
  // request as an Xbox login it can't verify (HTTP 400) and falls back to
  // Lucas Online registration.
  const DWORD len = sizeof(kMockToken) - 1;
  RELYING_PARTY_TOKEN* t = (RELYING_PARTY_TOKEN*)malloc(sizeof(RELYING_PARTY_TOKEN) + len);
  if (!t) return E_OUTOFMEMORY;
  t->Reserved = 0;
  t->Length = len;
  t->pToken = NULL;
  *token = t;

  if (overlapped) {
    overlapped->InternalHigh = 0;
    overlapped->dwExtendedError = 0;
    overlapped->InternalLow = ERROR_SUCCESS;
    if (overlapped->hEvent) SetEvent(overlapped->hEvent);
    return HRESULT_FROM_WIN32(ERROR_IO_PENDING);
  }
  return S_OK;
}

static VOID Hook_XamFreeToken(RELYING_PARTY_TOKEN* token) { free(token); }

// ---- notifications -------------------------------------------------------------

typedef HANDLE (*XamNotifyCreateListener_t)(ULONGLONG areas, DWORD version);
typedef BOOL (*XNotifyGetNext_t)(HANDLE listener, DWORD filter, PDWORD id, PULONG_PTR param);
static XamNotifyCreateListener_t g_orig_CreateListener;
static XNotifyGetNext_t g_orig_GetNext;

#define MAX_LISTENERS 8
// Notifications we inject, as bits in Listener::pending.
#define PENDING_LIVE    0x1  // XN_LIVE_CONNECTIONCHANGED (connected)
#define PENDING_SIGNIN  0x2  // XN_SYS_SIGNINCHANGED (signed-in user mask)
#define PENDING_LINK    0x4  // XN_LIVE_LINK_STATE_CHANGED (link up)

struct Listener {
  HANDLE handle;
  ULONGLONG areas;
  DWORD pending;
};
static Listener g_listeners[MAX_LISTENERS];
static CRITICAL_SECTION g_notify_lock;
static BOOL g_live_announced;
static DWORD g_last_announce;   // tick of the last (re)broadcast
static DWORD g_rebroadcasts;
volatile BOOL g_xhttp_connected; // set by hooks_xhttp.cpp on XHttpConnect

// Which notifications a listener should get, from its areas.
static DWORD PendingFor(ULONGLONG areas) {
  DWORD bits = 0;
  if (areas & XNOTIFY_LIVE) bits |= PENDING_LIVE | PENDING_LINK;
  if (areas & XNOTIFY_SYSTEM) bits |= PENDING_SIGNIN;
  return bits;
}

static ULONG_PTR SignedInMask() {
  ULONG_PTR mask = 0;
  for (DWORD i = 0; i < XUSER_MAX_COUNT; i++) {
    // Plugin's own (unhooked) import, so this is the real local sign-in state.
    if (XUserGetSigninState(i) != eXUserSigninState_NotSignedIn) mask |= 1 << i;
  }
  return mask;
}

// Like Xenia: after XAuth "completes", tell Live listeners the connection is up
// and System listeners that sign-in changed, so UE3 re-checks and logs in.
VOID NotifyLiveConnected() {
  EnterCriticalSection(&g_notify_lock);
  g_live_announced = TRUE;
  g_last_announce = GetTickCount();
  for (int i = 0; i < MAX_LISTENERS; i++) {
    if (g_listeners[i].handle) g_listeners[i].pending |= PendingFor(g_listeners[i].areas);
  }
  LeaveCriticalSection(&g_notify_lock);
}

static HANDLE Hook_XamNotifyCreateListener(ULONGLONG areas, DWORD version) {
  HANDLE h = g_orig_CreateListener(areas, version);
  if (!h) return h;
  EnterCriticalSection(&g_notify_lock);
  for (int i = 0; i < MAX_LISTENERS; i++) {
    if (!g_listeners[i].handle) {
      g_listeners[i].handle = h;
      g_listeners[i].areas = areas;
      // A listener created after XAuthStartup still needs to hear it.
      g_listeners[i].pending = g_live_announced ? PendingFor(areas) : 0;
      break;
    }
  }
  LeaveCriticalSection(&g_notify_lock);
  LogDebug("xauth: notify listener %p areas %08X%08X", h, (DWORD)(areas >> 32), (DWORD)areas);
  return h;
}

static BOOL Hook_XNotifyGetNext(HANDLE listener, DWORD filter, PDWORD id, PULONG_PTR param) {
  EnterCriticalSection(&g_notify_lock);

  // Like Xenia's watchdog: if the game still hasn't connected to its backend
  // 12 s after the last broadcast, send the notifications again (3 times max).
  if (g_live_announced && !g_xhttp_connected && g_rebroadcasts < 3 &&
      GetTickCount() - g_last_announce > 12000) {
    g_rebroadcasts++;
    LeaveCriticalSection(&g_notify_lock);
    Log("xauth: no XHttpConnect yet, re-sending Live/sign-in notifications (%u)", g_rebroadcasts);
    NotifyLiveConnected();
    EnterCriticalSection(&g_notify_lock);
  }

  // Listener created before our hooks went in: adopt it, areas unknown.
  Listener* l = NULL;
  for (int i = 0; i < MAX_LISTENERS && !l; i++) {
    if (g_listeners[i].handle == listener) l = &g_listeners[i];
  }
  for (int i = 0; i < MAX_LISTENERS && !l; i++) {
    if (!g_listeners[i].handle) {
      l = &g_listeners[i];
      l->handle = listener;
      l->areas = XNOTIFY_SYSTEM | XNOTIFY_LIVE;
      l->pending = g_live_announced ? PendingFor(l->areas) : 0;
    }
  }

  DWORD out_id = 0;
  ULONG_PTR out_param = 0;
  if (l && (l->pending & PENDING_LIVE) && (filter == 0 || filter == XN_LIVE_CONNECTIONCHANGED)) {
    l->pending &= ~PENDING_LIVE;
    out_id = XN_LIVE_CONNECTIONCHANGED;
    out_param = XONLINE_S_LOGON_CONNECTION_ESTABLISHED;
  } else if (l && (l->pending & PENDING_LINK) &&
             (filter == 0 || filter == XN_LIVE_LINK_STATE_CHANGED)) {
    // Xenia follows every connection notification with "link up"; First Assault
    // only starts its Lucas Online login after receiving it.
    l->pending &= ~PENDING_LINK;
    out_id = XN_LIVE_LINK_STATE_CHANGED;
    out_param = 1;
  } else if (l && (l->pending & PENDING_SIGNIN) &&
             (filter == 0 || filter == XN_SYS_SIGNINCHANGED)) {
    l->pending &= ~PENDING_SIGNIN;
    out_id = XN_SYS_SIGNINCHANGED;
    out_param = SignedInMask();
  }
  LeaveCriticalSection(&g_notify_lock);

  if (out_id) {
    if (id) *id = out_id;
    if (param) *param = out_param;
    LogDebug("xauth: delivered %s (param %08X) to %p",
        out_id == XN_LIVE_CONNECTIONCHANGED    ? "XN_LIVE_CONNECTIONCHANGED"
        : out_id == XN_LIVE_LINK_STATE_CHANGED ? "XN_LIVE_LINK_STATE_CHANGED"
                                               : "XN_SYS_SIGNINCHANGED",
        (DWORD)out_param, listener);
    return TRUE;
  }

  BOOL got = g_orig_GetNext(listener, filter, id, param);
  if (got && id) {
    // Hide "Live connection lost" from the real stack; we are never really on Live.
    if (*id == XN_LIVE_CONNECTIONCHANGED && param &&
        *param != XONLINE_S_LOGON_CONNECTION_ESTABLISHED) {
      *param = XONLINE_S_LOGON_CONNECTION_ESTABLISHED;
    }
    if (*id == XN_LIVE_LINK_STATE_CHANGED && param) *param = 1;
    LogDebug("xauth: real notification %08X (param %08X)", *id, param ? (DWORD)*param : 0);
  }
  return got;
}

DWORD InstallXAuthHooks(PLDR_DATA_TABLE_ENTRY title) {
  static BOOL once = FALSE;
  if (!once) { InitializeCriticalSection(&g_notify_lock); once = TRUE; }
  EnterCriticalSection(&g_notify_lock);
  memset(g_listeners, 0, sizeof(g_listeners));
  g_live_announced = FALSE;
  g_rebroadcasts = 0;
  g_xhttp_connected = FALSE;
  LeaveCriticalSection(&g_notify_lock);

  g_orig_CreateListener =
      (XamNotifyCreateListener_t)ResolveFunction(MODULE_XAM, ORD_XamNotifyCreateListener);
  g_orig_GetNext = (XNotifyGetNext_t)ResolveFunction(MODULE_XAM, ORD_XNotifyGetNext);

  struct { DWORD ordinal; DWORD hook; } hooks[] = {
      {ORD_XampXAuthStartup, (DWORD)Hook_XampXAuthStartup},
      {ORD_XampXAuthShutdown, (DWORD)Hook_XampXAuthShutdown},
      {ORD_XamGetToken, (DWORD)Hook_XamGetToken},
      {ORD_XamFreeToken, (DWORD)Hook_XamFreeToken},
      {ORD_XamNotifyCreateListener, (DWORD)Hook_XamNotifyCreateListener},
      {ORD_XNotifyGetNext, (DWORD)Hook_XNotifyGetNext},
  };
  DWORD patched = 0;
  for (int i = 0; i < ARRAYSIZE(hooks); i++) {
    if (PatchModuleImport(title, MODULE_XAM, hooks[i].ordinal, hooks[i].hook) == S_OK)
      patched++;
  }
  return patched;
}
