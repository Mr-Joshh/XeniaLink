// Makes the game believe local profiles are signed in to Xbox Live with Gold.

#include "hooks.h"
#include "hooking.h"
#include "api.h"
#include "config.h"
#include "log.h"

typedef XUSER_SIGNIN_STATE (*XamUserGetSigninState_t)(DWORD user_index);
typedef DWORD (*XamUserGetSigninInfo_t)(DWORD user_index, DWORD flags,
                                       PXUSER_SIGNIN_INFO info);
typedef DWORD (*XamUserCheckPrivilege_t)(DWORD user_index, DWORD privilege,
                                        PBOOL result);
typedef DWORD (*XamUserGetMembershipTier_t)(DWORD user_index);
typedef BOOL (*XamUserIsOnlineEnabled_t)(DWORD user_index);

static XamUserGetSigninState_t g_orig_GetSigninState;
static XamUserGetSigninInfo_t g_orig_GetSigninInfo;
XamUserGetXUID_t g_orig_XamUserGetXUID;

#define XUID_TYPE_OFFLINE 1
#define XUID_TYPE_ONLINE  2
#define MEMBERSHIP_TIER_GOLD 6

ULONGLONG OnlineXuidFor(ULONGLONG offline_xuid) {
  // Xenia generates 0009xxxxxxxxxxxx online XUIDs. Derive one from the low
  // 48 bits of the offline XUID so it is stable across boots.
  return 0x0009000000000000ULL | (offline_xuid & 0x0000FFFFFFFFFFFFULL);
}

static BOOL IsLocallySignedIn(DWORD user_index) {
  return user_index < XUSER_MAX_COUNT &&
         g_orig_GetSigninState(user_index) != eXUserSigninState_NotSignedIn;
}

static DWORD g_log_state, g_log_info, g_log_priv;
#define LOG_FIRST(counter, ...) do { if (counter < 12) { counter++; LogDebug(__VA_ARGS__); } } while (0)

static XUSER_SIGNIN_STATE Hook_XamUserGetSigninState(DWORD user_index) {
  XUSER_SIGNIN_STATE state = IsLocallySignedIn(user_index) ? eXUserSigninState_SignedInToLive
                                                           : eXUserSigninState_NotSignedIn;
  LOG_FIRST(g_log_state, "live: GetSigninState(%u) -> %u", user_index, state);
  return state;
}

static DWORD Hook_XamUserGetSigninInfo(DWORD user_index, DWORD flags,
                                      PXUSER_SIGNIN_INFO info) {
  // ONLINE_XUID_ONLY would fail for an offline profile, so ask for the offline
  // info and convert it.
  DWORD result = g_orig_GetSigninInfo(
      user_index, flags & ~XUSER_GET_SIGNIN_INFO_ONLINE_XUID_ONLY, info);
  if (result != ERROR_SUCCESS || info->UserSigninState == eXUserSigninState_NotSignedIn) {
    return result;
  }
  info->UserSigninState = eXUserSigninState_SignedInToLive;
  info->dwInfoFlags |= XUSER_INFO_FLAG_LIVE_ENABLED;
  // Like Xenia/real xam: flags 0 returns the logon XUID, i.e. the online XUID
  // for a profile that is signed in to Live.
  if (!(flags & XUSER_GET_SIGNIN_INFO_OFFLINE_XUID_ONLY)) {
    info->xuid = OnlineXuidFor(info->xuid);
  }
  LOG_FIRST(g_log_info, "live: GetSigninInfo(%u, flags %X) -> xuid %016I64X", user_index, flags,
            info->xuid);
  return result;
}

static DWORD Hook_XamUserGetXUID(DWORD user_index, DWORD type_mask, PXUID xuid) {
  DWORD result = g_orig_XamUserGetXUID(user_index, XUID_TYPE_OFFLINE, xuid);
  if (result == ERROR_SUCCESS && (type_mask & XUID_TYPE_ONLINE)) {
    *xuid = OnlineXuidFor(*xuid);
  }
  return result;
}

static DWORD Hook_XamUserCheckPrivilege(DWORD user_index, DWORD privilege,
                                       PBOOL result) {
  if (!result) return ERROR_INVALID_PARAMETER;
  *result = IsLocallySignedIn(user_index);
  LOG_FIRST(g_log_priv, "live: CheckPrivilege(%u, %u) -> %d", user_index, privilege, *result);
  return ERROR_SUCCESS;
}

static DWORD Hook_XamUserGetMembershipTier(DWORD user_index) {
  return MEMBERSHIP_TIER_GOLD;
}

static BOOL Hook_XamUserIsOnlineEnabled(DWORD user_index) {
  return IsLocallySignedIn(user_index);
}

static DWORD Hook_XNetLogonGetTitleID() {
  return XamGetCurrentTitleId();
}

VOID RegisterSignedInPlayers() {
  for (DWORD i = 0; i < XUSER_MAX_COUNT; i++) {
    XUSER_SIGNIN_INFO info;
    if (g_orig_GetSigninInfo(i, 0, &info) != ERROR_SUCCESS ||
        info.UserSigninState == eXUserSigninState_NotSignedIn) {
      continue;
    }
    ApiRegisterPlayer(OnlineXuidFor(info.xuid), info.szUserName);
  }
}

DWORD InstallLiveHooks(PLDR_DATA_TABLE_ENTRY title) {
  g_orig_GetSigninState =
      (XamUserGetSigninState_t)ResolveFunction(MODULE_XAM, ORD_XamUserGetSigninState);
  g_orig_GetSigninInfo =
      (XamUserGetSigninInfo_t)ResolveFunction(MODULE_XAM, ORD_XamUserGetSigninInfo);
  g_orig_XamUserGetXUID =
      (XamUserGetXUID_t)ResolveFunction(MODULE_XAM, ORD_XamUserGetXUID);

  if (!g_config.spoof_signin) return 0;

  struct { DWORD ordinal; DWORD hook; } hooks[] = {
      {ORD_XamUserGetSigninState, (DWORD)Hook_XamUserGetSigninState},
      {ORD_XamUserGetSigninInfo, (DWORD)Hook_XamUserGetSigninInfo},
      {ORD_XamUserGetXUID, (DWORD)Hook_XamUserGetXUID},
      {ORD_XamUserCheckPrivilege, (DWORD)Hook_XamUserCheckPrivilege},
      {ORD_XamUserGetMembershipTier, (DWORD)Hook_XamUserGetMembershipTier},
      {ORD_XamUserIsOnlineEnabled, (DWORD)Hook_XamUserIsOnlineEnabled},
      {ORD_XNetLogonGetTitleID, (DWORD)Hook_XNetLogonGetTitleID},
  };
  DWORD patched = 0;
  for (int i = 0; i < ARRAYSIZE(hooks); i++) {
    if (PatchModuleImport(title, MODULE_XAM, hooks[i].ordinal, hooks[i].hook) == S_OK)
      patched++;
  }
  return patched;
}
