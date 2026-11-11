// XSession* over the XGI message pipe (app 0xFB) → Xenia Web Services.
// Mirrors xam/apps/xgi_app.cc + xsession.cc in Xenia Canary Netplay.

#include "hooks.h"
#include "hooking.h"
#include "xbox_types.h"
#include "api.h"
#include "config.h"
#include "log.h"
#include "session_props.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

typedef DWORD (*XMsgStartIORequestEx_t)(DWORD app, DWORD msg, PXOVERLAPPED ov,
                                        PVOID buffer, DWORD len, PVOID unknown);
typedef DWORD (*XMsgStartIORequest_t)(DWORD app, DWORD msg, PXOVERLAPPED ov,
                                      PVOID buffer, DWORD len);
typedef DWORD (*XMsgInProcessCall_t)(DWORD app, DWORD msg, PVOID param1, PVOID param2);

static XMsgStartIORequestEx_t g_orig_StartIORequestEx;
static XMsgStartIORequest_t g_orig_StartIORequest;
static XMsgInProcessCall_t g_orig_InProcessCall;

static BOOL HandleXLiveBaseAsync(DWORD msg, PVOID buffer, PXOVERLAPPED ov, DWORD* ret);

// ---- per-title session table -----------------------------------------------

#define MAX_SESSIONS 8
struct LocalSession {
  DWORD obj_ptr;         // the game's XSession kernel object (our key)
  ULONGLONG id;
  DWORD flags;
  BOOL is_host;
  BOOL advertised;
  DWORD public_slots, private_slots;
  DWORD filled_public, filled_private;
  XSESSION_INFO info;
  ULONGLONG nonce;
  DWORD state;           // 0 lobby, 2 in game
};

static LocalSession g_sessions[MAX_SESSIONS];
static CRITICAL_SECTION g_sess_lock;
static DWORD g_title_id, g_media_id, g_version;

VOID XgiResetForTitle(DWORD title_id, DWORD media_id, DWORD version) {
  static BOOL once = FALSE;
  if (!once) { InitializeCriticalSection(&g_sess_lock); once = TRUE; }
  EnterCriticalSection(&g_sess_lock);
  memset(g_sessions, 0, sizeof(g_sessions));
  g_title_id = title_id;
  g_media_id = media_id;
  PropsReset(title_id);
  g_version = version;
  LeaveCriticalSection(&g_sess_lock);
}

static LocalSession* FindSession(DWORD obj_ptr, BOOL create) {
  LocalSession* free_slot = NULL;
  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (g_sessions[i].obj_ptr == obj_ptr) return &g_sessions[i];
    if (!g_sessions[i].obj_ptr && !free_slot) free_slot = &g_sessions[i];
  }
  if (create && free_slot) {
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->obj_ptr = obj_ptr;
    return free_slot;
  }
  return NULL;
}

static ULONGLONG Random64() {
  ULONGLONG v;
  XeCryptRandom((BYTE*)&v, sizeof(v));
  return v;
}

static VOID OurXnAddr(XNADDR* xna) {
  memset(xna, 0, sizeof(*xna));
  XNetGetTitleXnAddr(xna);  // plugin's unhooked import: local info + MAC
  xna->ina = g_identity.public_ip;
  xna->inaOnline = g_identity.public_ip;
  xna->wPortOnline = g_config.player_port;
}

// Collects XUIDs for a join/leave request (remote XUIDs or local user indices).
static DWORD ManageXuids(const XGI_SESSION_MANAGE* m, ULONGLONG* xuids, BOOL* priv,
                         DWORD max) {
  DWORD n = min(m->array_count, max);
  for (DWORD i = 0; i < n; i++) {
    if (m->xuid_array_ptr) {
      xuids[i] = ((ULONGLONG*)m->xuid_array_ptr)[i];
    } else if (m->indices_array_ptr) {
      XUID offline = 0;
      g_orig_XamUserGetXUID(((DWORD*)m->indices_array_ptr)[i], 1, &offline);
      xuids[i] = OnlineXuidFor(offline);
    }
    priv[i] = m->private_slots_array_ptr ? ((BOOL*)m->private_slots_array_ptr)[i] : FALSE;
  }
  return n;
}

// Xenia uses this fixed key (00 01 .. 0F) for every session it hosts and every
// search result it builds, and the server doesn't store keys. The game checks
// the key against the host's QoS data, so both sides must use the same one.
static VOID IdentityExchangeKey(XNKEY* key) {
  for (BYTE i = 0; i < sizeof(key->ab); i++) key->ab[i] = i;
}

// ---- message handlers (run on a worker thread; may block on HTTP) -----------

static DWORD OnCreate(XGI_SESSION_CREATE* d) {
  EnterCriticalSection(&g_sess_lock);
  LocalSession* s = FindSession(d->obj_ptr, TRUE);
  LeaveCriticalSection(&g_sess_lock);
  if (!s) return ERROR_NOT_ENOUGH_MEMORY;

  XSESSION_INFO* info = (XSESSION_INFO*)d->session_info_ptr;
  Log("xgi: XSessionCreate obj %08X flags %08X slots %u+%u user %u info %08X",
      d->obj_ptr, d->flags, d->num_slots_public, d->num_slots_private, d->user_index,
      d->session_info_ptr);
  if (!info) return ERROR_INVALID_PARAMETER;
  s->flags = d->flags;
  s->public_slots = d->num_slots_public;
  s->private_slots = d->num_slots_private;
  s->is_host = (d->flags & XSESSION_FLAG_HOST) != 0;

  if (s->is_host) {
    s->id = (Random64() & 0x00FFFFFFFFFFFFFFULL) | ((ULONGLONG)XNKID_ONLINE_PEER << 56);
    memcpy(info->sessionID.ab, &s->id, 8);
    OurXnAddr(&info->hostAddress);
    IdentityExchangeKey(&info->keyExchangeKey);
    s->nonce = Random64();

    // The profile is often signed in after the boot handshake (at the title's
    // start screen), so register again here or the server answers 403
    // "Player not found" and the session is never advertised.
    RegisterSignedInPlayers();
    XUID offline = 0;
    g_orig_XamUserGetXUID(d->user_index, 1, &offline);
    s->advertised = ApiSessionCreate(g_title_id, s->id, OnlineXuidFor(offline),
                                     d->flags, d->num_slots_public,
                                     d->num_slots_private, g_media_id, g_version);
    if (s->advertised) {
      char gamertag[XUSER_NAME_SIZE] = "";
      XUserGetName(d->user_index, gamertag, sizeof(gamertag));
      PropsAddDefaults(OnlineXuidFor(offline), gamertag);
      PropsSetHostSession(s->id);
    }
    Log("xgi: hosting session %016I64X (flags %08X, %u+%u slots) %s", s->id,
        d->flags, d->num_slots_public, d->num_slots_private,
        s->advertised ? "advertised" : "NOT advertised");
  } else {
    // Joining: the game filled session_info from a search result / invite.
    memcpy(&s->id, info->sessionID.ab, 8);
    s->nonce = Random64();
    Log("xgi: client session %016I64X", s->id);
  }
  s->info = *info;
  if (d->nonce_ptr) *(ULONGLONG*)d->nonce_ptr = s->nonce;
  return ERROR_SUCCESS;
}

static DWORD OnDelete(XGI_SESSION_STATE* d) {
  EnterCriticalSection(&g_sess_lock);
  LocalSession* s = FindSession(d->obj_ptr, FALSE);
  LocalSession copy;
  if (s) { copy = *s; memset(s, 0, sizeof(*s)); }
  LeaveCriticalSection(&g_sess_lock);
  if (s && copy.is_host && copy.advertised) {
    PropsSetHostSession(0);
    ApiSessionDelete(g_title_id, copy.id);
  }
  return ERROR_SUCCESS;
}

static DWORD OnJoinLeave(XGI_SESSION_MANAGE* d, BOOL join) {
  LocalSession* s = FindSession(d->obj_ptr, FALSE);
  if (!s) return ERROR_INVALID_HANDLE;
  ULONGLONG xuids[16];
  BOOL priv[16];
  DWORD n = ManageXuids(d, xuids, priv, 16);
  for (DWORD i = 0; i < n; i++) {
    DWORD* filled = priv[i] ? &s->filled_private : &s->filled_public;
    if (join) (*filled)++;
    else if (*filled) (*filled)--;
  }
  if (join) ApiSessionJoin(g_title_id, s->id, xuids, priv, n);
  else ApiSessionLeave(g_title_id, s->id, xuids, n);
  return ERROR_SUCCESS;
}

static DWORD OnModify(XGI_SESSION_MODIFY* d) {
  LocalSession* s = FindSession(d->obj_ptr, FALSE);
  if (!s) return ERROR_INVALID_HANDLE;
  s->flags = d->flags;
  s->public_slots = d->max_public_slots;
  s->private_slots = d->max_private_slots;
  if (s->is_host && s->advertised)
    ApiSessionModify(g_title_id, s->id, d->flags, d->max_public_slots, d->max_private_slots);
  return ERROR_SUCCESS;
}

static VOID FillSearchResult(XSESSION_SEARCHRESULT* r, const ApiSession* s) {
  memset(r, 0, sizeof(*r));
  memcpy(r->info.sessionID.ab, &s->id, 8);
  r->info.hostAddress.ina = s->host_ip;
  r->info.hostAddress.inaOnline = s->host_ip;
  r->info.hostAddress.wPortOnline = s->port;
  memcpy(r->info.hostAddress.abEnet, s->mac, 6);
  // abOnline is an SGADDR; platform_type @+0x10 = Xbox 360 (1), as Xenia sets it.
  r->info.hostAddress.abOnline[16] = 1;
  IdentityExchangeKey(&r->info.keyExchangeKey);
  r->dwOpenPublicSlots = s->open_public;
  r->dwOpenPrivateSlots = s->open_private;
  r->dwFilledPublicSlots = s->filled_public;
  r->dwFilledPrivateSlots = s->filled_private;
}

// Bump allocator over the unused tail of the game's results buffer. Real xam
// packs properties there too; the game sizes the buffer for it.
struct TailAlloc {
  BYTE* p;
  BYTE* end;
};

static VOID* TailTake(TailAlloc* t, DWORD size, DWORD align) {
  BYTE* p = (BYTE*)(((DWORD)t->p + align - 1) & ~(align - 1));
  if (p + size > t->end) return NULL;
  t->p = p + size;
  return p;
}

// Like Xenia's GetSessions: give each result the host's contexts and properties
// from the server. UE3 rebuilds the host's game settings from these, so without
// them the game skips the session.
static VOID FillSearchResultProps(XSESSION_SEARCHRESULT* r, const ApiSession* s, TailAlloc* t) {
  static ApiProp props[API_MAX_PROPS];
  DWORD n = ApiSessionPropertiesGet(g_title_id, s->id, props, API_MAX_PROPS);
  DWORD n_ctx = 0, n_prop = 0;
  for (DWORD i = 0; i < n; i++) {
    if ((props[i].id >> 28) == 0) n_ctx++; else n_prop++;
  }
  XUSER_CONTEXT* ctx = n_ctx ? (XUSER_CONTEXT*)TailTake(t, n_ctx * sizeof(XUSER_CONTEXT), 4) : NULL;
  XUSER_PROPERTY* prop =
      n_prop ? (XUSER_PROPERTY*)TailTake(t, n_prop * sizeof(XUSER_PROPERTY), 8) : NULL;
  if ((n_ctx && !ctx) || (n_prop && !prop)) {
    Log("xgi: no room for %u contexts + %u properties of %016I64X", n_ctx, n_prop, s->id);
    return;
  }

  DWORD ci = 0, pi = 0;
  for (DWORD i = 0; i < n; i++) {
    const ApiProp* src = &props[i];
    if ((src->id >> 28) == 0) {
      ctx[ci].dwContextId = src->id;
      ctx[ci].dwValue = *(const DWORD*)src->value;
      ci++;
      continue;
    }
    XUSER_PROPERTY* dst = &prop[pi++];
    memset(dst, 0, sizeof(*dst));
    dst->dwPropertyId = src->id;
    dst->value.type = src->type;
    if (src->type == XUSER_DATA_TYPE_UNICODE || src->type == XUSER_DATA_TYPE_BINARY) {
      BYTE* payload = (BYTE*)TailTake(t, src->size, 2);
      if (!payload) {
        pi--;
        continue;
      }
      memcpy(payload, src->data, src->size);
      dst->value.binary.cbData = src->size;
      dst->value.binary.pbData = payload;
    } else {
      memcpy(&dst->value.nData, src->value, 8);  // union start, big-endian
    }
  }
  r->cContexts = ci;
  r->pContexts = ci ? ctx : NULL;
  r->cProperties = pi;
  r->pProperties = pi ? prop : NULL;
  Log("xgi: search result %016I64X: %u contexts, %u properties", s->id, ci, pi);
}

static DWORD WriteSearchResults(DWORD buffer_ptr, DWORD buffer_size,
                                const ApiSession* sessions, DWORD count) {
  // Like Xenia: always write the header into the caller's buffer and succeed
  // (no ERROR_INSUFFICIENT_BUFFER; First Assault shows "error while searching").
  XSESSION_SEARCHRESULT_HEADER* header = (XSESSION_SEARCHRESULT_HEADER*)buffer_ptr;
  if (!header) return ERROR_INVALID_PARAMETER;
  XSESSION_SEARCHRESULT* results = (XSESSION_SEARCHRESULT*)(header + 1);
  DWORD fit = buffer_size > sizeof(*header)
                  ? (buffer_size - sizeof(*header)) / sizeof(XSESSION_SEARCHRESULT)
                  : 0;
  if (count > fit) count = fit;
  for (DWORD i = 0; i < count; i++) FillSearchResult(&results[i], &sessions[i]);
  TailAlloc tail = {(BYTE*)(results + count), (BYTE*)buffer_ptr + buffer_size};
  for (DWORD i = 0; i < count; i++) FillSearchResultProps(&results[i], &sessions[i], &tail);
  header->dwSearchResults = count;
  header->pResults = results;
  return ERROR_SUCCESS;
}

static DWORD OnSearch(XGI_SESSION_SEARCH* d) {
  static ApiSession found[API_MAX_SESSIONS];
  DWORD max = min(d->num_results, (DWORD)API_MAX_SESSIONS);
  DWORD count = ApiSessionSearch(g_title_id, found, max);
  Log("xgi: XSessionSearch proc %u, %u results wanted, buffer %08X size %u -> %u sessions",
      d->proc_index, d->num_results, d->search_results_ptr, d->results_buffer_size, count);
  return WriteSearchResults(d->search_results_ptr, d->results_buffer_size, found, count);
}

static DWORD OnSearchById(XGI_SESSION_SEARCH_BYID* d) {
  ApiSession s;
  ULONGLONG id;
  memcpy(&id, d->session_id.ab, 8);
  DWORD count = ApiSessionGet(g_title_id, id, &s) ? 1 : 0;
  return WriteSearchResults(d->search_results_ptr, d->results_buffer_size, &s, count);
}

// XUserReadStats: like Xenia, return one view per spec with one row per XUID and
// every requested column present (empty values), so UE3's matchmaking/skill
// code always gets well-formed results.
struct XGI_XUSER_READ_STATS {
  DWORD title_id;
  DWORD xuids_count;
  DWORD xuids_ptr;    // XUID*
  DWORD specs_count;
  DWORD specs_ptr;    // XUSER_STATS_SPEC*
  DWORD results_size;
  DWORD results_ptr;  // XUSER_STATS_READ_RESULTS*
};

static DWORD OnReadStats(XGI_XUSER_READ_STATS* d) {
  if (!d || !d->xuids_count || !d->xuids_ptr || !d->specs_count || !d->specs_ptr ||
      !d->results_ptr) {
    return ERROR_INVALID_PARAMETER;
  }
  const XUID* xuids = (const XUID*)d->xuids_ptr;
  const XUSER_STATS_SPEC* specs = (const XUSER_STATS_SPEC*)d->specs_ptr;

  // Size needed: results + views + rows + columns.
  DWORD columns = 0;
  for (DWORD v = 0; v < d->specs_count; v++) columns += specs[v].dwNumColumnIds;
  const DWORD needed = sizeof(XUSER_STATS_READ_RESULTS) +
                       d->specs_count * sizeof(XUSER_STATS_VIEW) +
                       d->specs_count * d->xuids_count * sizeof(XUSER_STATS_ROW) +
                       columns * d->xuids_count * sizeof(XUSER_STATS_COLUMN);
  if (d->results_size && d->results_size < needed) {
    Log("xgi: XUserReadStats buffer %u < %u", d->results_size, needed);
    return ERROR_INSUFFICIENT_BUFFER;
  }

  BYTE* p = (BYTE*)d->results_ptr;
  memset(p, 0, needed);
  XUSER_STATS_READ_RESULTS* results = (XUSER_STATS_READ_RESULTS*)p;
  p += sizeof(*results);
  XUSER_STATS_VIEW* views = (XUSER_STATS_VIEW*)p;
  p += d->specs_count * sizeof(XUSER_STATS_VIEW);
  results->dwNumViews = d->specs_count;
  results->pViews = views;

  for (DWORD v = 0; v < d->specs_count; v++) {
    XUSER_STATS_ROW* rows = (XUSER_STATS_ROW*)p;
    p += d->xuids_count * sizeof(XUSER_STATS_ROW);
    views[v].dwViewId = specs[v].dwViewId;
    views[v].dwTotalViewRows = d->xuids_count;
    views[v].dwNumRows = d->xuids_count;
    views[v].pRows = rows;
    for (DWORD r = 0; r < d->xuids_count; r++) {
      XUSER_STATS_COLUMN* cols = (XUSER_STATS_COLUMN*)p;
      p += specs[v].dwNumColumnIds * sizeof(XUSER_STATS_COLUMN);
      rows[r].xuid = xuids[r];
      rows[r].dwRank = 0;
      rows[r].i64Rating = 0;
      rows[r].dwNumColumns = specs[v].dwNumColumnIds;
      rows[r].pColumns = cols;
      for (DWORD c = 0; c < specs[v].dwNumColumnIds; c++) {
        cols[c].wColumnId = specs[v].rgwColumnIds[c];
        cols[c].Value.type = XUSER_DATA_TYPE_NULL;
      }
    }
  }
  Log("xgi: XUserReadStats %u views x %u users answered locally", d->specs_count,
      d->xuids_count);
  return ERROR_SUCCESS;
}

// Returns TRUE if the message is ours; *result receives the Win32 result.
static BOOL Dispatch(DWORD msg, PVOID buffer, DWORD* result) {
  switch (msg) {
    case XGI_SESSION_CREATE_MSG: *result = OnCreate((XGI_SESSION_CREATE*)buffer); return TRUE;
    case XGI_SESSION_DELETE_MSG: *result = OnDelete((XGI_SESSION_STATE*)buffer); return TRUE;
    case XGI_SESSION_JOIN_MSG: *result = OnJoinLeave((XGI_SESSION_MANAGE*)buffer, TRUE); return TRUE;
    case XGI_SESSION_LEAVE_MSG: *result = OnJoinLeave((XGI_SESSION_MANAGE*)buffer, FALSE); return TRUE;
    case XGI_SESSION_MODIFY_MSG: *result = OnModify((XGI_SESSION_MODIFY*)buffer); return TRUE;
    case XGI_SESSION_SEARCH_MSG: *result = OnSearch((XGI_SESSION_SEARCH*)buffer); return TRUE;
    case XGI_SESSION_SEARCHEX_MSG:
      *result = OnSearch(&((XGI_SESSION_SEARCH_EX*)buffer)->session_search);
      return TRUE;
    case XGI_SESSION_SEARCHBYID_MSG:
      *result = OnSearchById((XGI_SESSION_SEARCH_BYID*)buffer);
      return TRUE;
    case XGI_USER_READ_STATS_MSG:
      *result = OnReadStats((XGI_XUSER_READ_STATS*)buffer);
      return TRUE;
    case XGI_SESSION_START_MSG:
    case XGI_SESSION_END_MSG:
    case XGI_SESSION_WRITESTATS_MSG:
      // TODO: stats/leaderboards (POST .../leaderboards).
      *result = ERROR_SUCCESS;
      return TRUE;
  }
  return FALSE;
}

// ---- async completion ---------------------------------------------------------

// XGI request buffers live on the caller's stack (the XDK wrappers build them
// in their own frame) and are only valid during the call. Real xam copies them;
// so do we, before returning ERROR_IO_PENDING. Pointers inside the request
// refer to the game's long-lived memory, so results are written through them.
#define MAX_XGI_REQUEST 0x100

struct PendingRequest {
  DWORD msg;
  PVOID buffer;  // points at data[] below
  PXOVERLAPPED ov;
  BYTE data[MAX_XGI_REQUEST];
};

static VOID CompleteOverlapped(PXOVERLAPPED ov, DWORD result) {
  ov->InternalHigh = 0;
  ov->dwExtendedError = result == ERROR_SUCCESS ? 0 : HRESULT_FROM_WIN32(result);
  __lwsync();
  ov->InternalLow = result;  // XGetOverlappedResult polls this
  if (ov->hEvent) SetEvent(ov->hEvent);
}

static DWORD WINAPI RequestThread(LPVOID param) {
  PendingRequest* req = (PendingRequest*)param;
  DWORD result = ERROR_FUNCTION_FAILED;
  Dispatch(req->msg, req->buffer, &result);
  LogDebug("xgi: msg %08X done -> %08X", req->msg, result);
  CompleteOverlapped(req->ov, result);
  free(req);
  return 0;
}

static BOOL IsOurs(DWORD app, DWORD msg) {
  if (app != XGI_APP_ID) return FALSE;
  // Must list the same messages as Dispatch().
  // TODO: XSessionGetDetails (0xB001D) and MigrateHost (0xB001E) still go to
  // real xam, which has no record of our sessions.
  switch (msg) {
    case XGI_SESSION_CREATE_MSG: case XGI_SESSION_DELETE_MSG:
    case XGI_SESSION_JOIN_MSG: case XGI_SESSION_LEAVE_MSG:
    case XGI_SESSION_MODIFY_MSG: case XGI_SESSION_SEARCH_MSG:
    case XGI_SESSION_SEARCHEX_MSG: case XGI_SESSION_SEARCHBYID_MSG:
    case XGI_SESSION_START_MSG: case XGI_SESSION_END_MSG:
    case XGI_SESSION_WRITESTATS_MSG: case XGI_USER_READ_STATS_MSG:
      return TRUE;
  }
  return FALSE;
}

static DWORD StartRequest(DWORD msg, PXOVERLAPPED ov, PVOID buffer, DWORD len) {
  LogDebug("xgi: msg %08X start (%s)", msg, ov ? "async" : "sync");
  if (!ov) {
    DWORD result = ERROR_FUNCTION_FAILED;
    Dispatch(msg, buffer, &result);
    return result;
  }
  PendingRequest* req = (PendingRequest*)malloc(sizeof(PendingRequest));
  if (!req) return ERROR_NOT_ENOUGH_MEMORY;
  req->msg = msg;
  if (!len || len > MAX_XGI_REQUEST) len = MAX_XGI_REQUEST;
  if (buffer) memcpy(req->data, buffer, len);
  req->buffer = buffer ? req->data : NULL;
  req->ov = ov;
  ov->InternalLow = ERROR_IO_PENDING;
  ov->InternalHigh = 0;
  ov->dwExtendedError = 0;
  if (ov->hEvent) ResetEvent(ov->hEvent);
  HANDLE t = CreateThread(NULL, 0, RequestThread, req, 0, NULL);
  if (!t) {
    free(req);
    return ERROR_NOT_ENOUGH_MEMORY;
  }
  CloseHandle(t);
  return ERROR_IO_PENDING;
}

// XUserSetContext (0xB0006) / XUserSetProperty (0xB0007): note the values for
// the backend, then let the real xam handle them as before. Layouts from Xenia:
// {user_index, pad, xuid, context_id|property_id, value|data_size, data_ptr}.
static VOID CaptureSetCall(DWORD app, DWORD msg, PVOID buffer) {
  if (app != XGI_APP_ID || !buffer) return;
  const DWORD* d = (const DWORD*)buffer;
  if (msg == 0x000B0006) {
    PropsOnSetContext(d[4], d[5]);
  } else if (msg == 0x000B0007) {
    PropsOnSetProperty(d[4], d[5], (const VOID*)d[6]);
  } else {
    return;
  }
  PropsKick();
}

static DWORD Hook_XMsgStartIORequestEx(DWORD app, DWORD msg, PXOVERLAPPED ov,
                                       PVOID buffer, DWORD len, PVOID unknown) {
  CaptureSetCall(app, msg, buffer);
  if (IsOurs(app, msg)) return StartRequest(msg, ov, buffer, len);
  DWORD ret;
  if (app == XLIVEBASE_APP_ID && HandleXLiveBaseAsync(msg, buffer, ov, &ret)) return ret;
  if (app == XGI_APP_ID || app == XLIVEBASE_APP_ID) {
    LogDebug("xgi: pass-through app %02X msg %08X", app, msg);
  }
  return g_orig_StartIORequestEx(app, msg, ov, buffer, len, unknown);
}

static DWORD Hook_XMsgStartIORequest(DWORD app, DWORD msg, PXOVERLAPPED ov,
                                     PVOID buffer, DWORD len) {
  CaptureSetCall(app, msg, buffer);
  if (IsOurs(app, msg)) return StartRequest(msg, ov, buffer, len);
  DWORD ret;
  if (app == XLIVEBASE_APP_ID && HandleXLiveBaseAsync(msg, buffer, ov, &ret)) return ret;
  if (app == XGI_APP_ID || app == XLIVEBASE_APP_ID) {
    LogDebug("xgi: pass-through app %02X msg %08X (StartIORequest)", app, msg);
  }
  return g_orig_StartIORequest(app, msg, ov, buffer, len);
}

// ---- friends: an always-empty list ----------------------------------------------
// XFriendsCreateEnumerator hands back a dummy kernel handle (so the game's
// CloseHandle works) and XamEnumerate reports no items for it, like Xenia does
// for a profile without friends.

// XLiveBase marshals arguments as 16-byte entries: {native size, pad, u64 value ptr}.
struct XLB_ARG {
  DWORD native_size;
  DWORD pad;
  ULONGLONG value_ptr;
};

#define MAX_FAKE_ENUMS 8
static HANDLE g_fake_enums[MAX_FAKE_ENUMS];

static BOOL IsFakeEnum(HANDLE h) {
  for (int i = 0; i < MAX_FAKE_ENUMS; i++) {
    if (h && g_fake_enums[i] == h) return TRUE;
  }
  return FALSE;
}

static DWORD FriendsCreateEnumerator(PVOID args_ptr) {
  XLB_ARG* args = (XLB_ARG*)args_ptr;  // user, start, count, &buffer size, &handle
  if (!args) return E_INVALIDARG;
  DWORD count = args[2].value_ptr ? *(DWORD*)(DWORD)args[2].value_ptr : 0;
  DWORD* size_out = (DWORD*)(DWORD)args[3].value_ptr;
  HANDLE* handle_out = (HANDLE*)(DWORD)args[4].value_ptr;
  if (!handle_out || !size_out) return E_INVALIDARG;

  HANDLE h = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (!h) return E_OUTOFMEMORY;
  static DWORD next = 0;
  g_fake_enums[next++ % MAX_FAKE_ENUMS] = h;
  *size_out = count * sizeof(XONLINE_FRIEND);
  *handle_out = h;
  return ERROR_SUCCESS;
}

typedef DWORD (*XamEnumerate_t)(HANDLE h, DWORD flags, PVOID buffer, DWORD size,
                                PDWORD items, PXOVERLAPPED ov);
static XamEnumerate_t g_orig_XamEnumerate;

static DWORD Hook_XamEnumerate(HANDLE h, DWORD flags, PVOID buffer, DWORD size,
                               PDWORD items, PXOVERLAPPED ov) {
  if (!IsFakeEnum(h)) return g_orig_XamEnumerate(h, flags, buffer, size, items, ov);
  if (ov) {
    ov->InternalHigh = 0;
    ov->dwExtendedError = HRESULT_FROM_WIN32(ERROR_NO_MORE_FILES);
    __lwsync();
    ov->InternalLow = ERROR_FUNCTION_FAILED;
    if (ov->hEvent) SetEvent(ov->hEvent);
    return ERROR_IO_PENDING;
  }
  if (items) *items = 0;
  return ERROR_NO_MORE_FILES;
}

// ---- title storage -----------------------------------------------------------
// First Assault builds a title-storage path and enumerates it before logging in.
// Xenia's backend had no files for it, so an empty enumeration is enough.

struct XSTORAGE_BUILD_SERVER_PATH_ARGS {  // layout from Xenia's xnet.h
  DWORD user_index;
  DWORD pad;
  ULONGLONG xuid;
  DWORD storage_location;    // 1 game clip, 2 per title, 3 per user/title
  DWORD location_info_ptr;
  DWORD location_info_size;
  DWORD file_name_ptr;       // WCHAR*
  DWORD server_path_ptr;     // WCHAR* out
  DWORD server_path_length_ptr;  // DWORD* in/out, characters incl. NUL
};

static DWORD StorageBuildServerPath(XSTORAGE_BUILD_SERVER_PATH_ARGS* a) {
  if (!a || !a->server_path_length_ptr) return E_INVALIDARG;
  const DWORD title = XamGetCurrentTitleId();
  const wchar_t* file = a->file_name_ptr ? (const wchar_t*)a->file_name_ptr : L"";
  wchar_t path[300];
  if (a->storage_location == 2) {
    _snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE, L"//title.%08x/t:%08x/%s", title, title, file);
  } else if (a->storage_location == 3) {
    XUID xuid = a->xuid;
    if (a->user_index < XUSER_MAX_COUNT) {
      XUID offline = 0;
      g_orig_XamUserGetXUID(a->user_index, 1, &offline);
      xuid = OnlineXuidFor(offline);
    }
    _snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE, L"//tuser.%08x/u:%016I64x/%08x/%s", title,
                 xuid, title, file);
  } else {
    return 0x80151804;  // X_ONLINE_E_STORAGE_INVALID_FACILITY
  }
  DWORD needed = (DWORD)wcslen(path) + 1;
  DWORD* len = (DWORD*)a->server_path_length_ptr;
  if (a->server_path_ptr) {
    if (*len < needed) return E_INVALIDARG;
    memcpy((void*)a->server_path_ptr, path, needed * sizeof(wchar_t));
  }
  *len = needed;
  return ERROR_SUCCESS;
}

// Asynchronous: XStorageEnumerate (StartIORequest, buffer = XLIVE_ASYNC_TASK).
static DWORD StorageEnumerateEmpty(PVOID message) {
  // The buffer is an XLIVEBASE_ASYNC_MESSAGE; its first field points to the task.
  if (!message) return E_INVALIDARG;
  PVOID task = (PVOID)*(DWORD*)message;
  if (!task) return E_INVALIDARG;
  BYTE* results = (BYTE*)*(DWORD*)((BYTE*)task + 0x2C);  // results_ptr
  DWORD results_size = *(DWORD*)((BYTE*)task + 0x30);     // results_size
  if (!results || results_size < 12) return E_INVALIDARG;
  memset(results, 0, results_size);
  DWORD* r = (DWORD*)results;  // {total_num_items, num_items_returned, items_ptr}
  r[2] = (DWORD)(results + 12);
  return ERROR_SUCCESS;
}

// Async XLiveBase messages we complete ourselves. Returns TRUE if handled.
static BOOL HandleXLiveBaseAsync(DWORD msg, PVOID buffer, PXOVERLAPPED ov, DWORD* ret) {
  DWORD result;
  switch (msg) {
    case 0x0005000A:  // XStorageEnumerate
      result = StorageEnumerateEmpty(buffer);
      break;
    default:
      return FALSE;
  }
  LogDebug("xgi: XLiveBase %08X answered locally (async, result %08X)", msg, result);
  if (!ov) {
    *ret = result;
    return TRUE;
  }
  ov->InternalHigh = 0;
  ov->dwExtendedError = result;
  __lwsync();
  ov->InternalLow = result == ERROR_SUCCESS ? ERROR_SUCCESS : ERROR_FUNCTION_FAILED;
  if (ov->hEvent) SetEvent(ov->hEvent);
  *ret = ERROR_IO_PENDING;
  return TRUE;
}

// Synchronous XLiveBase calls, answered like Xenia's xlivebase_app.cc.
// Returns TRUE if handled.
static BOOL HandleXLiveBase(DWORD msg, PVOID param1, PVOID param2, DWORD* result) {
  switch (msg) {
    case 0x00058020:  // XFriendsCreateEnumerator (args in param2)
      *result = FriendsCreateEnumerator(param2);
      return TRUE;
    case 0x00058004:  // XOnlineGetLogonID
      if (param1) *(DWORD*)param1 = 1;
      *result = ERROR_SUCCESS;
      return TRUE;
    case 0x00058006:  // XOnlineGetNatType
      if (param1) *(DWORD*)param1 = 1;  // NAT_OPEN
      *result = ERROR_SUCCESS;
      return TRUE;
    case 0x00058035:  // XStorageBuildServerPath
      *result = StorageBuildServerPath((XSTORAGE_BUILD_SERVER_PATH_ARGS*)param1);
      return TRUE;
    case 0x00058037:  // XPresenceInitializeLegacy
    case 0x00058046:  // XPresenceInitialize
    case 0x00058056:  // XPresenceInitializeEx
      *result = ERROR_SUCCESS;
      return TRUE;
  }
  return FALSE;
}

static DWORD Hook_XMsgInProcessCall(DWORD app, DWORD msg, PVOID param1, PVOID param2) {
  if (IsOurs(app, msg)) return StartRequest(msg, NULL, param1, 0);
  DWORD result;
  if (app == XLIVEBASE_APP_ID && HandleXLiveBase(msg, param1, param2, &result)) {
    LogDebug("xgi: XLiveBase %08X answered locally", msg);
    return result;
  }
  if (app == XLIVEBASE_APP_ID && HandleXLiveBaseAsync(msg, param1, NULL, &result)) {
    return result;
  }
  if (app == XGI_APP_ID || app == XLIVEBASE_APP_ID) {
    LogDebug("xgi: pass-through app %02X msg %08X (InProcessCall)", app, msg);
  }
  return g_orig_InProcessCall(app, msg, param1, param2);
}

DWORD InstallXgiHooks(PLDR_DATA_TABLE_ENTRY title) {
  g_orig_StartIORequestEx =
      (XMsgStartIORequestEx_t)ResolveFunction(MODULE_XAM, ORD_XMsgStartIORequestEx);
  g_orig_StartIORequest =
      (XMsgStartIORequest_t)ResolveFunction(MODULE_XAM, ORD_XMsgStartIORequest);
  g_orig_InProcessCall =
      (XMsgInProcessCall_t)ResolveFunction(MODULE_XAM, ORD_XMsgInProcessCall);
  g_orig_XamEnumerate = (XamEnumerate_t)ResolveFunction(MODULE_XAM, ORD_XamEnumerate);
  memset(g_fake_enums, 0, sizeof(g_fake_enums));

  struct { DWORD ordinal; DWORD hook; } hooks[] = {
      {ORD_XMsgStartIORequestEx, (DWORD)Hook_XMsgStartIORequestEx},
      {ORD_XMsgStartIORequest, (DWORD)Hook_XMsgStartIORequest},
      {ORD_XMsgInProcessCall, (DWORD)Hook_XMsgInProcessCall},
      {ORD_XamEnumerate, (DWORD)Hook_XamEnumerate},
  };
  DWORD patched = 0;
  for (int i = 0; i < ARRAYSIZE(hooks); i++) {
    if (PatchModuleImport(title, MODULE_XAM, hooks[i].ordinal, hooks[i].hook) == S_OK)
      patched++;
  }
  return patched;
}
