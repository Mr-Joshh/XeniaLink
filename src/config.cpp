#include "config.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Config g_config;

static void Trim(char* s) {
  char* start = s;
  while (*start == ' ' || *start == '\t') start++;
  if (start != s) memmove(s, start, strlen(start) + 1);
  size_t len = strlen(s);
  while (len && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r' ||
                 s[len - 1] == '\n' || s[len - 1] == '"')) {
    s[--len] = 0;
  }
  if (s[0] == '"') memmove(s, s + 1, strlen(s));
}

static BOOL ParseBool(const char* v) {
  return _stricmp(v, "true") == 0 || _stricmp(v, "1") == 0 || _stricmp(v, "yes") == 0;
}

// Splits "http(s)://host[:port][/path]" into the config fields.
static void ParseApiAddress(const char* url) {
  const char* p = url;
  g_config.api_tls = FALSE;
  g_config.api_port = 80;
  if (_strnicmp(p, "https://", 8) == 0) {
    g_config.api_tls = TRUE;
    g_config.api_port = 443;
    p += 8;
  } else if (_strnicmp(p, "http://", 7) == 0) {
    p += 7;
  }

  const char* host_end = p;
  while (*host_end && *host_end != ':' && *host_end != '/') host_end++;
  size_t host_len = host_end - p;
  if (host_len >= sizeof(g_config.api_host)) host_len = sizeof(g_config.api_host) - 1;
  memcpy(g_config.api_host, p, host_len);
  g_config.api_host[host_len] = 0;

  p = host_end;
  if (*p == ':') {
    g_config.api_port = (WORD)atoi(p + 1);
    while (*p && *p != '/') p++;
  }
  strcpy_s(g_config.api_base_path, sizeof(g_config.api_base_path), *p ? p : "/");
  size_t n = strlen(g_config.api_base_path);
  if (g_config.api_base_path[n - 1] != '/' && n + 1 < sizeof(g_config.api_base_path)) {
    strcat_s(g_config.api_base_path, sizeof(g_config.api_base_path), "/");
  }
}

static void SetDefaults() {
  memset(&g_config, 0, sizeof(g_config));
  ParseApiAddress("https://xenia-netplay-2a0298c0e3f4.herokuapp.com/");
  g_config.player_port = 36000;
  g_config.spoof_signin = TRUE;
  g_config.block_xbox_live = TRUE;
  strcpy_s(g_config.xhttp_host, sizeof(g_config.xhttp_host), "74.91.124.65");
  g_config.xhttp_emulate = TRUE;
  g_config.inject_live_notify = TRUE;
  // Dashboard, Aurora, FSD, XeXMenu, etc.: never hook these. (IDs other than the
  // dashboard FFFE07D1 are best guesses; check the log for the real ones.)
  strcpy_s(g_config.exclude_titles, sizeof(g_config.exclude_titles),
           "FFFE07D1,FFFF0055,F5D20000,C0DE9999,00000166");
  strcpy_s(g_config.log_path, sizeof(g_config.log_path), HDD_DEVICE "XeniaLink.log");
}

// "Hdd:\x" -> "\Device\Harddisk0\Partition1\x" so files open without drive links.
static void ToDevicePath(const char* in, char* out, DWORD size) {
  if (_strnicmp(in, "Hdd:\\", 5) == 0) {
    _snprintf_s(out, size, _TRUNCATE, "%s%s", HDD_DEVICE, in + 5);
  } else {
    strcpy_s(out, size, in);
  }
}

BOOL ConfigLoad(const char* path) {
  SetDefaults();

  static char text[8192];
  if (!KFileRead(path, text, sizeof(text))) {
    return FALSE;
  }

  char* ctx = NULL;
  for (char* line = strtok_s(text, "\r\n", &ctx); line; line = strtok_s(NULL, "\r\n", &ctx)) {
    char* comment = strchr(line, '#');
    if (comment) *comment = 0;
    char* eq = strchr(line, '=');
    if (!eq || line[0] == '[') continue;
    *eq = 0;
    char* key = line;
    char* value = eq + 1;
    Trim(key);
    Trim(value);

    if (!_stricmp(key, "api_address")) ParseApiAddress(value);
    else if (!_stricmp(key, "player_port")) g_config.player_port = (WORD)atoi(value);
    else if (!_stricmp(key, "public_ip_override"))
      strcpy_s(g_config.public_ip_override, sizeof(g_config.public_ip_override), value);
    else if (!_stricmp(key, "spoof_signin")) g_config.spoof_signin = ParseBool(value);
    else if (!_stricmp(key, "block_xbox_live")) g_config.block_xbox_live = ParseBool(value);
    else if (!_stricmp(key, "xhttp_host"))
      strcpy_s(g_config.xhttp_host, sizeof(g_config.xhttp_host), value);
    else if (!_stricmp(key, "xhttp_emulate")) g_config.xhttp_emulate = ParseBool(value);
    else if (!_stricmp(key, "inject_live_notify")) g_config.inject_live_notify = ParseBool(value);
    else if (!_stricmp(key, "debug_log")) g_config.debug_log = ParseBool(value);
    else if (!_stricmp(key, "exclude_titles"))
      strcpy_s(g_config.exclude_titles, sizeof(g_config.exclude_titles), value);
    else if (!_stricmp(key, "log_path"))
      ToDevicePath(value, g_config.log_path, sizeof(g_config.log_path));
  }
  return TRUE;
}

BOOL ConfigIsTitleExcluded(DWORD title_id) {
  char buf[sizeof(g_config.exclude_titles)];
  strcpy_s(buf, sizeof(buf), g_config.exclude_titles);
  char* ctx = NULL;
  for (char* tok = strtok_s(buf, ", ", &ctx); tok; tok = strtok_s(NULL, ", ", &ctx)) {
    if (strtoul(tok, NULL, 16) == title_id) return TRUE;
  }
  return FALSE;
}
