#pragma once
#include <xtl.h>

// Records the game's session contexts/properties and uploads them for the
// session we host (see session_props.cpp).
VOID PropsReset(DWORD title_id);
VOID PropsOnSetContext(DWORD context_id, DWORD value);
VOID PropsOnSetProperty(DWORD property_id, DWORD size, const VOID* data);
// The system properties xam/Xenia add to every session (host XUID, gamertag,
// zone, country, language, platform, skill). Call before PropsSetHostSession.
VOID PropsAddDefaults(ULONGLONG online_xuid, const char* gamertag);
VOID PropsSetHostSession(ULONGLONG session_id);  // 0 = no longer hosting
VOID PropsKick();  // upload now if something changed
