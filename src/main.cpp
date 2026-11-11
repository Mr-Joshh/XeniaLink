// XeniaLink — DashLaunch plugin entry point.
// Watches for title launches and patches each game's xam imports so its Xbox
// Live traffic goes to Xenia Web Services instead.

#include <xtl.h>
#include "hooking.h"
#include "hooks.h"
#include "config.h"
#include "api.h"
#include "http.h"
#include "log.h"
#include <stdio.h>

#define CONFIG_PATH HDD_DEVICE "XeniaLink.ini"

static BOOL g_unloading = FALSE;

// Server handshake for a freshly started title. Runs on its own thread so the
// game isn't blocked while we talk to the server.
// param: nonzero for a real game (it has a media ID), which gets an on-screen
// result; system titles like the boot title don't.
static DWORD WINAPI HandshakeThread(LPVOID param) {
  BOOL is_game = param != NULL;
  // Give the title a moment to start XNet itself (our XNetStartup hook adds the
  // bypass-security flag); HttpEnsureNetwork covers titles that never do.
  Sleep(3000);
  if (!ApiInit()) {
    Log("main: server handshake failed. Check api_address and the console's internet connection.");
    if (is_game) Notify(L"XeniaLink: can't reach Xenia server");
    return 0;
  }
  ApiDeleteMySessions();   // clear stale sessions, like Xenia does on boot
  RegisterSignedInPlayers();
  Log("main: handshake done");
  if (is_game) Notify(L"XeniaLink: connected to Xenia server");
  return 0;
}

// Returns the number of imports hooked (0 if the title isn't ready yet).
static DWORD OnTitleLaunched(DWORD title_id) {
  PLDR_DATA_TABLE_ENTRY title = GetTitleModule();
  if (!title || !title->XexHeaderBase) return 0;

  DWORD media_id = 0, version = 0;
  // XEX_EXECUTION_ID: MediaID, Version, BaseVersion, TitleID, ...
  const DWORD* exec = (const DWORD*)RtlImageXexHeaderField(
      title->XexHeaderBase, 0x00040006);
  if (exec) {
    media_id = exec[0];
    version = exec[1];
  }

  XgiResetForTitle(title_id, media_id, version);
  DWORD n = InstallLiveHooks(title);
  n += InstallXNetHooks(title);
  n += InstallXgiHooks(title);
  n += InstallXAuthHooks(title);
  n += InstallXHttpHooks(title);
  n += InstallCrashHooks(title);
  if (n) {
    Log("main: title %08X (media %08X) - %u imports hooked", title_id, media_id, n);
    HANDLE t = CreateThread(NULL, 0, HandshakeThread, (LPVOID)(media_id != 0), 0, NULL);
    if (t) CloseHandle(t);
  }
  return n;
}

static DWORD WINAPI MainThread(LPVOID) {
  // Plugins load early in boot; wait until the hard drive accepts files.
  LONG status = -1;
  for (int i = 0; i < 120 && status < 0; i++) {
    MountHdd();
    status = LogInit(HDD_DEVICE "XeniaLink.log");
    if (status < 0) Sleep(500);
  }
  BOOL have_ini = ConfigLoad(CONFIG_PATH);
  if (status >= 0 && _stricmp(g_config.log_path, HDD_DEVICE "XeniaLink.log") != 0) {
    LogInit(g_config.log_path);
  }
  Log("XeniaLink 0.1.0 loaded (%s). API %s://%s:%u%s", have_ini ? "ini" : "defaults",
      g_config.api_tls ? "https" : "http", g_config.api_host, g_config.api_port,
      g_config.api_base_path);

  DWORD last_title = 0;
  DWORD retry_until = 0;  // tick count; nonzero while waiting for imports
  while (!g_unloading) {
    DWORD title_id = XamGetCurrentTitleId();
    if (title_id != last_title) {
      last_title = title_id;
      retry_until = 0;
      if (title_id == 0 || ConfigIsTitleExcluded(title_id)) {
        XNetSetTitleActive(FALSE);
        Log("main: title %08X excluded", title_id);
      } else {
        retry_until = GetTickCount() + 5000;
      }
    }
    // The title ID changes before the loader has resolved the game's imports,
    // so keep trying until the hooks land (or give up after 5 s).
    if (retry_until) {
      if (OnTitleLaunched(title_id)) {
        retry_until = 0;
      } else if ((LONG)(GetTickCount() - retry_until) > 0) {
        Log("main: title %08X - no imports hooked", title_id);
        retry_until = 0;
      }
    }
    // Poll fast: hooks must be in before the game calls XNetStartup.
    // TODO: hook the title loader instead of polling.
    Sleep(5);
  }
  return 0;
}

BOOL APIENTRY DllMain(HANDLE module, DWORD reason, LPVOID reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    HANDLE thread = NULL;
    DWORD thread_id = 0;
    // System thread (flag 2) so it survives title changes.
    ExCreateThread(&thread, 0, &thread_id, (PVOID)XapiThreadStartup,
                   (LPTHREAD_START_ROUTINE)MainThread, NULL, 2);
    if (!thread) thread = CreateThread(NULL, 0, MainThread, NULL, 0, &thread_id);
    if (thread) CloseHandle(thread);
  } else if (reason == DLL_PROCESS_DETACH) {
    g_unloading = TRUE;
    Sleep(50);
  }
  return TRUE;
}
