#pragma once
#include <xtl.h>

// Client for the Xenia Web Services REST API. Mirrors XLiveAPI.cpp in Xenia
// Canary Netplay so the server treats the console like another Xenia client.

#define API_MAX_SESSIONS 32

struct ApiSession {
  ULONGLONG id;
  DWORD flags;
  IN_ADDR host_ip;
  WORD port;
  BYTE mac[6];
  DWORD public_slots, private_slots;
  DWORD open_public, open_private;
  DWORD filled_public, filled_private;
};

struct ApiPlayer {
  ULONGLONG xuid;
  ULONGLONG session_id;
  IN_ADDR host_ip;
  BYTE mac[6];
};

// Identity of this console, filled by ApiInit.
struct ApiIdentity {
  IN_ADDR public_ip;   // from /whoami (or config override)
  IN_ADDR local_ip;
  BYTE mac[6];
  ULONGLONG machine_id;
};
extern ApiIdentity g_identity;

BOOL ApiInit();  // whoami + identity
BOOL ApiRegisterPlayer(ULONGLONG online_xuid, const char* gamertag);
BOOL ApiDeleteMySessions();
BOOL ApiFindPlayer(IN_ADDR ip, ApiPlayer* out);

BOOL ApiSessionCreate(DWORD title_id, ULONGLONG session_id, ULONGLONG host_xuid,
                      DWORD flags, DWORD public_slots, DWORD private_slots,
                      DWORD media_id, DWORD version);
BOOL ApiSessionDelete(DWORD title_id, ULONGLONG session_id);
BOOL ApiSessionModify(DWORD title_id, ULONGLONG session_id, DWORD flags,
                      DWORD public_slots, DWORD private_slots);
BOOL ApiSessionJoin(DWORD title_id, ULONGLONG session_id, const ULONGLONG* xuids,
                    const BOOL* private_slots, DWORD count);
BOOL ApiSessionLeave(DWORD title_id, ULONGLONG session_id, const ULONGLONG* xuids,
                     DWORD count);
BOOL ApiSessionGet(DWORD title_id, ULONGLONG session_id, ApiSession* out);
BOOL ApiSessionSetProperties(DWORD title_id, ULONGLONG session_id, const char* json);
BOOL ApiSessionQosUpload(DWORD title_id, ULONGLONG session_id, const VOID* data, DWORD len);
// Returns bytes copied into buf (0 if none).
DWORD ApiSessionQosGet(DWORD title_id, ULONGLONG session_id, VOID* buf, DWORD max);
// Returns the number of sessions written to out.
DWORD ApiSessionSearch(DWORD title_id, ApiSession* out, DWORD max);

// One session property/context as the host uploaded it (Xenia's format).
#define API_MAX_PROPS 48
#define API_MAX_PROP_DATA 256
struct ApiProp {
  DWORD id;
  BYTE type;                     // XUSER_DATA_TYPE_*; contexts have id top nibble 0
  BYTE value[8];                 // scalar value, big-endian (= XUSER_DATA union)
  DWORD size;                    // string/binary payload size
  BYTE data[API_MAX_PROP_DATA];  // string/binary payload
};
// GET title/{T}/sessions/{id}/properties. Returns the number written to out.
DWORD ApiSessionPropertiesGet(DWORD title_id, ULONGLONG session_id, ApiProp* out, DWORD max);
