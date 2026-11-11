// Session properties/contexts for matchmaking.
//
// The game sets them with XGI 0xB0006 (XUserSetContext) / 0xB0007
// (XUserSetProperty). Xenia's backend only returns a session to a filtered
// (Xenia) search if it has at least one context and one property, so the host
// uploads them to POST title/{T}/sessions/{id}/properties in Xenia's format:
//
//   base64( id as little-endian u32 | X_USER_DATA (16 bytes: type @0, value @8,
//           big-endian) | string/binary payload )

#include "session_props.h"
#include "api.h"
#include "log.h"
#include <stdio.h>
#include <string.h>

#define MAX_PROPS 48
#define MAX_PROP_DATA 128

struct StoredProp {
  DWORD id;
  BYTE type;  // X_USER_DATA_TYPE (from the id's top nibble)
  DWORD size;
  BYTE data[MAX_PROP_DATA];  // value as the game provided it (big-endian)
};

static StoredProp g_props[MAX_PROPS];
static DWORD g_prop_count;
static CRITICAL_SECTION g_props_lock;
static volatile LONG g_dirty;
static volatile LONG g_uploading;
static DWORD g_title_id;
static ULONGLONG g_host_session;  // 0 when not hosting an advertised session

enum { kContext = 0, kInt32 = 1, kInt64 = 2, kDouble = 3, kWString = 4, kFloat = 5,
       kBinary = 6, kDateTime = 7 };

VOID PropsReset(DWORD title_id) {
  static BOOL once = FALSE;
  if (!once) { InitializeCriticalSection(&g_props_lock); once = TRUE; }
  EnterCriticalSection(&g_props_lock);
  g_prop_count = 0;
  g_title_id = title_id;
  g_host_session = 0;
  LeaveCriticalSection(&g_props_lock);
}

static VOID Store(DWORD id, const BYTE* data, DWORD size) {
  if (size > MAX_PROP_DATA) size = MAX_PROP_DATA;
  EnterCriticalSection(&g_props_lock);
  StoredProp* p = NULL;
  for (DWORD i = 0; i < g_prop_count; i++) {
    if (g_props[i].id == id) p = &g_props[i];
  }
  if (!p && g_prop_count < MAX_PROPS) p = &g_props[g_prop_count++];
  if (p) {
    BOOL changed = p->id != id || p->size != size || memcmp(p->data, data, size) != 0;
    p->id = id;
    p->type = (BYTE)((id >> 28) & 0xF);
    p->size = size;
    memcpy(p->data, data, size);
    if (changed) InterlockedExchange(&g_dirty, 1);
  }
  LeaveCriticalSection(&g_props_lock);
}

VOID PropsOnSetContext(DWORD context_id, DWORD value) {
  BYTE be[4];
  memcpy(be, &value, 4);  // console memory is already big-endian
  Store(context_id, be, 4);
}

VOID PropsOnSetProperty(DWORD property_id, DWORD size, const VOID* data) {
  if (!data) return;
  BYTE type = (BYTE)((property_id >> 28) & 0xF);
  DWORD n = size;
  if (type == kContext || type == kInt32 || type == kFloat) n = 4;
  else if (type == kInt64 || type == kDouble || type == kDateTime) n = 8;
  Store(property_id, (const BYTE*)data, n);
}

VOID PropsAddDefaults(ULONGLONG online_xuid, const char* gamertag) {
  // Same ids/values as Xenia's UserTracker::AddDefaultProperties (seen on a
  // Xenia-hosted First Assault session). UE3 reads the host's id and name from
  // these, so a session without them isn't joinable from Xenia.
  struct { DWORD id; LONG value; } ints[] = {
      {0x10008101, 0},                     // XPROPERTY_GAMER_ZONE
      {0x10008102, 103},                   // XPROPERTY_GAMER_COUNTRY (US, as Xenia sends)
      {0x10008103, (LONG)XGetLanguage()},  // XPROPERTY_GAMER_LANGUAGE
      {0x10008201, 1},                     // XPROPERTY_PLATFORM_TYPE = Xbox 360
  };
  for (int i = 0; i < ARRAYSIZE(ints); i++) Store(ints[i].id, (const BYTE*)&ints[i].value, 4);

  Store(0x20008107, (const BYTE*)&online_xuid, 8);  // XPROPERTY_GAMER_PUID
  double mu = 3.0, sigma = 1.0;                     // X_STATS_SKILL_*_DEFAULT
  Store(0x30008105, (const BYTE*)&mu, 8);           // XPROPERTY_GAMER_MU
  Store(0x30008106, (const BYTE*)&sigma, 8);        // XPROPERTY_GAMER_SIGMA

  // Gamertag as big-endian UTF-16 without a terminator, like Xenia's blobs.
  WCHAR name[32];
  DWORD n = 0;
  for (; gamertag && gamertag[n] && n < ARRAYSIZE(name); n++) name[n] = (WCHAR)(BYTE)gamertag[n];
  Store(0x40008109, (const BYTE*)name, n * 2);  // XPROPERTY_GAMER_HOSTNAME
  Store(0x40008002, (const BYTE*)name, n * 2);  // X_PROPERTY_GAMERNAME
}

static const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static DWORD Base64(const BYTE* in, DWORD len, char* out) {
  DWORD o = 0;
  for (DWORD i = 0; i < len; i += 3) {
    DWORD v = in[i] << 16 | (i + 1 < len ? in[i + 1] << 8 : 0) | (i + 2 < len ? in[i + 2] : 0);
    out[o++] = kB64[(v >> 18) & 63];
    out[o++] = kB64[(v >> 12) & 63];
    out[o++] = i + 1 < len ? kB64[(v >> 6) & 63] : '=';
    out[o++] = i + 2 < len ? kB64[v & 63] : '=';
  }
  out[o] = 0;
  return o;
}

// Serializes one property like Xenia's Property::Serialize().
static DWORD Serialize(const StoredProp* p, BYTE* out) {
  memset(out, 0, 20);
  out[0] = (BYTE)(p->id);  // little-endian id (host order in Xenia)
  out[1] = (BYTE)(p->id >> 8);
  out[2] = (BYTE)(p->id >> 16);
  out[3] = (BYTE)(p->id >> 24);
  out[4] = p->type;
  if (p->type == kWString || p->type == kBinary) {
    DWORD size = p->size;
    memcpy(out + 12, &size, 4);  // union { cbData; ptr } (big-endian)
    memcpy(out + 20, p->data, p->size);
    return 20 + p->size;
  }
  memcpy(out + 12, p->data, p->size);  // value at X_USER_DATA+8
  return 20;
}

static DWORD WINAPI UploadThread(LPVOID) {
  Sleep(500);  // let a burst of set calls finish first
  InterlockedExchange(&g_dirty, 0);

  static char body[MAX_PROPS * 360 + 64];
  DWORD len = 0;
  len += _snprintf_s(body, sizeof(body), _TRUNCATE, "{\"properties\":[");
  ULONGLONG session;
  DWORD title;
  EnterCriticalSection(&g_props_lock);
  session = g_host_session;
  title = g_title_id;
  for (DWORD i = 0; i < g_prop_count && len + 400 < sizeof(body); i++) {
    BYTE raw[20 + MAX_PROP_DATA];
    char b64[(20 + MAX_PROP_DATA) * 4 / 3 + 8];
    DWORD n = Serialize(&g_props[i], raw);
    Base64(raw, n, b64);
    len += _snprintf_s(body + len, sizeof(body) - len, _TRUNCATE, "%s\"%s\"", i ? "," : "", b64);
  }
  DWORD count = g_prop_count;
  LeaveCriticalSection(&g_props_lock);
  _snprintf_s(body + len, sizeof(body) - len, _TRUNCATE, "]}");

  if (session) {
    BOOL ok = ApiSessionSetProperties(title, session, body);
    Log("props: uploaded %u properties/contexts for %016I64X -> %s", count, session,
        ok ? "OK" : "FAILED");
  }
  InterlockedExchange(&g_uploading, 0);
  if (g_dirty && g_host_session) PropsKick();  // changed while uploading
  return 0;
}

VOID PropsKick() {
  if (!g_host_session || !g_dirty) return;
  if (InterlockedCompareExchange(&g_uploading, 1, 0) != 0) return;
  HANDLE t = CreateThread(NULL, 0, UploadThread, NULL, 0, NULL);
  if (t) CloseHandle(t); else InterlockedExchange(&g_uploading, 0);
}

VOID PropsSetHostSession(ULONGLONG session_id) {
  g_host_session = session_id;
  if (session_id) {
    InterlockedExchange(&g_dirty, 1);
    PropsKick();
  }
}
