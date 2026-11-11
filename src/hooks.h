#pragma once
#include "kernel.h"

// Installs all hooks into the given title module. Returns the number of
// imports patched.
DWORD InstallLiveHooks(PLDR_DATA_TABLE_ENTRY title);
DWORD InstallXNetHooks(PLDR_DATA_TABLE_ENTRY title);
DWORD InstallXgiHooks(PLDR_DATA_TABLE_ENTRY title);

// Insecure-socket privilege is only granted while a hooked title runs.
VOID XNetSetTitleActive(BOOL active);

// Called when a new title starts, before hooks fire. Clears per-title state.
VOID XgiResetForTitle(DWORD title_id, DWORD media_id, DWORD version);

// Stable fake online XUID (0009...) for a local profile's offline XUID.
ULONGLONG OnlineXuidFor(ULONGLONG offline_xuid);

// Registers every signed-in local profile with the server (once per title).
VOID RegisterSignedInPlayers();

DWORD InstallXAuthHooks(PLDR_DATA_TABLE_ENTRY title);
DWORD InstallXHttpHooks(PLDR_DATA_TABLE_ENTRY title);
DWORD InstallCrashHooks(PLDR_DATA_TABLE_ENTRY title);

// Queues XN_LIVE_CONNECTIONCHANGED (connected) for the game's Live listeners.
VOID NotifyLiveConnected();

// Original xam function used by other hook files.
typedef DWORD (*XamUserGetXUID_t)(DWORD user_index, DWORD type_mask, PXUID xuid);
extern XamUserGetXUID_t g_orig_XamUserGetXUID;
