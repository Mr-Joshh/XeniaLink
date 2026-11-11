#pragma once
#include <xtl.h>

struct Config {
  // Where API calls go. "https://" = built-in TLS (BearSSL, see tls.cpp);
  // "http://" = plain HTTP.
  char api_host[128];
  WORD api_port;
  char api_base_path[64];  // e.g. "/" — prefix for every endpoint
  BOOL api_tls;

  // Port advertised in our XNADDR / session. Xenia always uses 36000.
  WORD player_port;

  // Override the public IP instead of asking /whoami (dotted string, or empty).
  char public_ip_override[32];

  BOOL spoof_signin;      // report Live sign-in + Gold
  BOOL block_xbox_live;   // fail DNS lookups for *.xboxlive.com etc.

  // XHttp (third-party web services, e.g. Star Wars: First Assault's backend).
  // Requests to 127.0.0.1/localhost are sent to xhttp_host instead.
  char xhttp_host[64];
  BOOL xhttp_emulate;          // implement XHttp in the plugin (needed offline)
  BOOL debug_log;               // extra diagnostic log lines (sockets, packets, timings)
  BOOL inject_live_notify;     // send XN_LIVE_CONNECTIONCHANGED after XAuthStartup

  // Comma-separated title IDs to skip (hex), e.g. "FFFE07D1,F5D20000".
  char exclude_titles[256];

  char log_path[MAX_PATH];
};

extern Config g_config;

// Loads defaults, then overrides from the INI file. Returns FALSE if the file
// was missing (defaults are still usable).
BOOL ConfigLoad(const char* path);
BOOL ConfigIsTitleExcluded(DWORD title_id);
