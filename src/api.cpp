#include "api.h"
#include "config.h"
#include "http.h"
#include "json.h"
#include "log.h"
#include <winsockx.h>
#include <stdio.h>
#include <stdlib.h>

ApiIdentity g_identity;

static void IpToStr(IN_ADDR ip, char* out, DWORD size) {
  const BYTE* b = (const BYTE*)&ip.s_addr;
  _snprintf_s(out, size, _TRUNCATE, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static void MacToStr(const BYTE* mac, char* out, DWORD size) {
  // Server expects 12 hex digits with no separators (Xenia: "{:012x}").
  _snprintf_s(out, size, _TRUNCATE, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1],
              mac[2], mac[3], mac[4], mac[5]);
}

static void StrToMac(const char* s, BYTE* mac) {
  ULONGLONG v = _strtoui64(s, NULL, 16);
  for (int i = 5; i >= 0; i--) {
    mac[i] = (BYTE)(v & 0xFF);
    v >>= 8;
  }
}

static BOOL Call(const char* method, const char* path, const char* body,
                 HttpResponse* resp) {
  if (!HttpRequest(method, path, body, resp)) {
    Log("api: %s /%s -> network error", method, path);
    return FALSE;
  }
  Log("api: %s /%s -> %d", method, path, resp->status);
  if (resp->status < 200 || resp->status >= 300) {
    if (resp->body) Log("api:   %.200s", resp->body);
    HttpFree(resp);
    return FALSE;
  }
  return TRUE;
}

static BOOL CallNoBody(const char* method, const char* path, const char* body) {
  HttpResponse resp;
  if (!Call(method, path, body, &resp)) return FALSE;
  HttpFree(&resp);
  return TRUE;
}

BOOL ApiInit() {
  memset(&g_identity, 0, sizeof(g_identity));

  XNADDR local;
  memset(&local, 0, sizeof(local));
  XNetGetTitleXnAddr(&local);  // plugin's own (unhooked) import
  g_identity.local_ip = local.ina;
  memcpy(g_identity.mac, local.abEnet, 6);

  // Machine ID: Xenia sends a value with the 0xFA prefix; derive a stable one
  // from the MAC so it never collides with a real Live machine account.
  g_identity.machine_id = 0xFA00000000000000ULL;
  for (int i = 0; i < 6; i++) {
    g_identity.machine_id |= (ULONGLONG)g_identity.mac[i] << (8 * (5 - i));
  }

  if (g_config.public_ip_override[0]) {
    g_identity.public_ip.s_addr = inet_addr(g_config.public_ip_override);
    return TRUE;
  }

  HttpResponse resp;
  if (!Call("GET", "whoami", NULL, &resp)) return FALSE;
  char addr[32];
  BOOL ok = JsonGet(resp.body, "address", addr, sizeof(addr)) != NULL;
  if (ok) g_identity.public_ip.s_addr = inet_addr(addr);
  HttpFree(&resp);
  Log("api: public IP %s", ok ? "received" : "missing");
  return ok;
}

BOOL ApiRegisterPlayer(ULONGLONG online_xuid, const char* gamertag) {
  char xuid[17], machine[17], ip[16], mac[13], body[512];
  _snprintf_s(xuid, sizeof(xuid), _TRUNCATE, "%016I64X", online_xuid);
  _snprintf_s(machine, sizeof(machine), _TRUNCATE, "%016I64x", g_identity.machine_id);
  IpToStr(g_identity.public_ip, ip, sizeof(ip));
  MacToStr(g_identity.mac, mac, sizeof(mac));

  JsonWriter w;
  JsonBegin(&w, body, sizeof(body));
  JsonStr(&w, "xuid", xuid);
  JsonStr(&w, "gamertag", gamertag);
  JsonStr(&w, "machineId", machine);
  JsonStr(&w, "hostAddress", ip);
  JsonStr(&w, "macAddress", mac);
  return CallNoBody("POST", "players", JsonEnd(&w));
}

BOOL ApiDeleteMySessions() {
  char mac[13], path[64];
  MacToStr(g_identity.mac, mac, sizeof(mac));
  _snprintf_s(path, sizeof(path), _TRUNCATE, "DeleteSessions/%s", mac);
  return CallNoBody("DELETE", path, NULL);
}

BOOL ApiFindPlayer(IN_ADDR ip, ApiPlayer* out) {
  char ip_str[16], body[96], value[32];
  IpToStr(ip, ip_str, sizeof(ip_str));
  JsonWriter w;
  JsonBegin(&w, body, sizeof(body));
  JsonStr(&w, "hostAddress", ip_str);

  HttpResponse resp;
  if (!Call("POST", "players/find", JsonEnd(&w), &resp)) return FALSE;
  memset(out, 0, sizeof(*out));
  out->host_ip = ip;
  if (JsonGet(resp.body, "xuid", value, sizeof(value)))
    out->xuid = _strtoui64(value, NULL, 16);
  if (JsonGet(resp.body, "sessionId", value, sizeof(value)))
    out->session_id = _strtoui64(value, NULL, 16);
  if (JsonGet(resp.body, "macAddress", value, sizeof(value)))
    StrToMac(value, out->mac);
  HttpFree(&resp);
  return TRUE;
}

BOOL ApiSessionCreate(DWORD title_id, ULONGLONG session_id, ULONGLONG host_xuid,
                      DWORD flags, DWORD public_slots, DWORD private_slots,
                      DWORD media_id, DWORD version) {
  char path[64], xuid[17], sid[17], media[9], ver[9], ip[16], mac[13], title[9];
  char body[768];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions", title_id);
  _snprintf_s(xuid, sizeof(xuid), _TRUNCATE, "%016I64X", host_xuid);
  _snprintf_s(sid, sizeof(sid), _TRUNCATE, "%016I64x", session_id);
  _snprintf_s(media, sizeof(media), _TRUNCATE, "%08X", media_id);
  _snprintf_s(ver, sizeof(ver), _TRUNCATE, "%08X", version);
  _snprintf_s(title, sizeof(title), _TRUNCATE, "%08X", title_id);
  IpToStr(g_identity.public_ip, ip, sizeof(ip));
  MacToStr(g_identity.mac, mac, sizeof(mac));

  JsonWriter w;
  JsonBegin(&w, body, sizeof(body));
  JsonStr(&w, "xuid", xuid);
  JsonStr(&w, "title", title);  // TODO: Xenia sends the game's display name
  JsonStr(&w, "mediaId", media);
  JsonStr(&w, "version", ver);
  JsonStr(&w, "sessionId", sid);
  JsonInt(&w, "flags", flags);
  JsonInt(&w, "publicSlotsCount", public_slots);
  JsonInt(&w, "privateSlotsCount", private_slots);
  JsonStr(&w, "hostAddress", ip);
  JsonStr(&w, "macAddress", mac);
  JsonInt(&w, "port", g_config.player_port);
  return CallNoBody("POST", path, JsonEnd(&w));
}

BOOL ApiSessionDelete(DWORD title_id, ULONGLONG session_id) {
  char path[80];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions/%016I64x",
              title_id, session_id);
  return CallNoBody("DELETE", path, NULL);
}

BOOL ApiSessionModify(DWORD title_id, ULONGLONG session_id, DWORD flags,
                      DWORD public_slots, DWORD private_slots) {
  char path[96], body[128];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions/%016I64x/modify",
              title_id, session_id);
  JsonWriter w;
  JsonBegin(&w, body, sizeof(body));
  JsonInt(&w, "flags", flags);
  JsonInt(&w, "publicSlotsCount", public_slots);
  JsonInt(&w, "privateSlotsCount", private_slots);
  return CallNoBody("POST", path, JsonEnd(&w));
}

static void XuidArray(const ULONGLONG* xuids, DWORD count, char* out, DWORD size) {
  DWORD len = 0;
  out[len++] = '[';
  for (DWORD i = 0; i < count && len + 22 < size; i++) {
    len += _snprintf_s(out + len, size - len, _TRUNCATE, "%s\"%016I64X\"",
                       i ? "," : "", xuids[i]);
  }
  out[len++] = ']';
  out[len] = 0;
}

BOOL ApiSessionJoin(DWORD title_id, ULONGLONG session_id, const ULONGLONG* xuids,
                    const BOOL* private_slots, DWORD count) {
  char path[96], xuid_arr[512], priv_arr[128], body[768];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions/%016I64x/join",
              title_id, session_id);
  XuidArray(xuids, count, xuid_arr, sizeof(xuid_arr));

  DWORD len = 0;
  priv_arr[len++] = '[';
  for (DWORD i = 0; i < count && len + 8 < sizeof(priv_arr); i++) {
    len += _snprintf_s(priv_arr + len, sizeof(priv_arr) - len, _TRUNCATE, "%s%s",
                       i ? "," : "", (private_slots && private_slots[i]) ? "true" : "false");
  }
  priv_arr[len++] = ']';
  priv_arr[len] = 0;

  JsonWriter w;
  JsonBegin(&w, body, sizeof(body));
  JsonRaw(&w, "xuids", xuid_arr);
  JsonRaw(&w, "privateSlots", priv_arr);
  return CallNoBody("POST", path, JsonEnd(&w));
}

BOOL ApiSessionLeave(DWORD title_id, ULONGLONG session_id, const ULONGLONG* xuids,
                     DWORD count) {
  char path[96], xuid_arr[512], body[640];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions/%016I64x/leave",
              title_id, session_id);
  XuidArray(xuids, count, xuid_arr, sizeof(xuid_arr));
  JsonWriter w;
  JsonBegin(&w, body, sizeof(body));
  JsonRaw(&w, "xuids", xuid_arr);
  return CallNoBody("POST", path, JsonEnd(&w));
}

BOOL ApiSessionSetProperties(DWORD title_id, ULONGLONG session_id, const char* json) {
  char path[96];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions/%016I64x/properties",
              title_id, session_id);
  return CallNoBody("POST", path, json);
}

BOOL ApiSessionQosUpload(DWORD title_id, ULONGLONG session_id, const VOID* data, DWORD len) {
  char path[96];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions/%016I64x/qos", title_id,
              session_id);
  HttpResponse resp;
  // Same as Xenia (curl default for a binary body): the backend only fills
  // req.rawBody for content types it has a parser for.
  BOOL ok = HttpRequestEx("POST", path, data, len, "application/x-www-form-urlencoded", &resp);
  Log("api: POST /%s (%u bytes) -> %d", path, len, ok ? resp.status : -1);
  ok = ok && resp.status >= 200 && resp.status < 300;
  HttpFree(&resp);
  return ok;
}

DWORD ApiSessionQosGet(DWORD title_id, ULONGLONG session_id, VOID* buf, DWORD max) {
  char path[96];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions/%016I64x/qos", title_id,
              session_id);
  HttpResponse resp;
  if (!HttpRequestEx("GET", path, NULL, 0, NULL, &resp)) return 0;
  DWORD n = 0;
  if (resp.status == 200 && resp.body) {
    n = resp.body_len < max ? resp.body_len : max;
    memcpy(buf, resp.body, n);
  }
  Log("api: GET /%s -> %d (%u bytes)", path, resp.status, n);
  HttpFree(&resp);
  return n;
}

static void ParseSession(const char* obj, ApiSession* s) {
  char v[64];
  memset(s, 0, sizeof(*s));
  if (JsonGet(obj, "id", v, sizeof(v))) s->id = _strtoui64(v, NULL, 16);
  if (JsonGet(obj, "flags", v, sizeof(v))) s->flags = strtoul(v, NULL, 10);
  if (JsonGet(obj, "hostAddress", v, sizeof(v))) s->host_ip.s_addr = inet_addr(v);
  if (JsonGet(obj, "port", v, sizeof(v))) s->port = (WORD)atoi(v);
  if (JsonGet(obj, "macAddress", v, sizeof(v))) StrToMac(v, s->mac);
  if (JsonGet(obj, "publicSlotsCount", v, sizeof(v))) s->public_slots = atoi(v);
  if (JsonGet(obj, "privateSlotsCount", v, sizeof(v))) s->private_slots = atoi(v);
  if (JsonGet(obj, "openPublicSlotsCount", v, sizeof(v))) s->open_public = atoi(v);
  if (JsonGet(obj, "openPrivateSlotsCount", v, sizeof(v))) s->open_private = atoi(v);
  if (JsonGet(obj, "filledPublicSlotsCount", v, sizeof(v))) s->filled_public = atoi(v);
  if (JsonGet(obj, "filledPrivateSlotsCount", v, sizeof(v))) s->filled_private = atoi(v);
}

BOOL ApiSessionGet(DWORD title_id, ULONGLONG session_id, ApiSession* out) {
  char path[96];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions/%016I64x/details",
              title_id, session_id);
  HttpResponse resp;
  if (!Call("GET", path, NULL, &resp)) return FALSE;
  ParseSession(resp.body, out);
  HttpFree(&resp);
  return out->id != 0;
}

DWORD ApiSessionSearch(DWORD title_id, ApiSession* out, DWORD max) {
  // GET .../search returns every advertised session for the title. The POST
  // variant applies the game's matchmaking query but needs the XLAST XML,
  // which the console doesn't have (TODO: per-title XLAST files on Hdd:).
  char path[64];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions/search", title_id);
  HttpResponse resp;
  if (!Call("GET", path, NULL, &resp)) return 0;

  DWORD count = 0;
  const char* p = resp.body;
  const char* end = NULL;
  while (count < max && (p = JsonNextObject(p, &end)) != NULL) {
    // ParseSession reads fields with strstr, so isolate this object.
    size_t len = end - p + 1;
    char* obj = (char*)malloc(len + 1);
    if (!obj) break;
    memcpy(obj, p, len);
    obj[len] = 0;
    ParseSession(obj, &out[count]);
    free(obj);
    // Skip our own sessions.
    if (memcmp(out[count].mac, g_identity.mac, 6) != 0) count++;
    p = end + 1;
  }
  HttpFree(&resp);
  return count;
}

static int Base64Value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

// Decodes base64 text up to the closing quote. Returns bytes written.
static DWORD Base64Decode(const char* in, BYTE* out, DWORD max) {
  DWORD n = 0, bits = 0, acc = 0;
  for (; *in && *in != '"'; in++) {
    int v = Base64Value(*in);
    if (v < 0) continue;  // '=' padding
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (n < max) out[n++] = (BYTE)(acc >> bits);
    }
  }
  return n;
}

DWORD ApiSessionPropertiesGet(DWORD title_id, ULONGLONG session_id, ApiProp* out, DWORD max) {
  char path[96];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "title/%08X/sessions/%016I64x/properties",
              title_id, session_id);
  HttpResponse resp;
  if (!Call("GET", path, NULL, &resp)) return 0;

  // {"properties":["base64", ...]}; each blob is Xenia's serialized Property:
  // id (little-endian u32) | X_USER_DATA (type @4, value big-endian @12) | payload @20.
  DWORD count = 0;
  const char* p = resp.body ? strchr(resp.body, '[') : NULL;
  static BYTE raw[20 + API_MAX_PROP_DATA];
  while (p && count < max && (p = strchr(p, '"')) != NULL) {
    const char* start = ++p;
    DWORD n = Base64Decode(start, raw, sizeof(raw));
    p = strchr(start, '"');
    if (p) p++;
    if (n < 20) continue;
    ApiProp* prop = &out[count];
    memset(prop, 0, sizeof(*prop));
    prop->id = raw[0] | (raw[1] << 8) | (raw[2] << 16) | ((DWORD)raw[3] << 24);
    prop->type = raw[4];
    memcpy(prop->value, raw + 12, 8);
    if (prop->type == XUSER_DATA_TYPE_UNICODE || prop->type == XUSER_DATA_TYPE_BINARY) {
      DWORD size = (raw[12] << 24) | (raw[13] << 16) | (raw[14] << 8) | raw[15];
      prop->size = min(min(size, n - 20), (DWORD)API_MAX_PROP_DATA);
      memcpy(prop->data, raw + 20, prop->size);
    }
    count++;
  }
  HttpFree(&resp);
  return count;
}
