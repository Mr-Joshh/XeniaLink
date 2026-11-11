#pragma once
// Kernel declarations not in the public XDK headers, and the standard
// import-table patching helpers used by DashLaunch plugins.

#include "kernel.h"

#define MODULE_XAM      "xam.xex"
#define MODULE_KERNEL   "xboxkrnl.exe"

// xam.xex ordinals (verified against Xenia's xam_table.inc)
#define ORD_NetDll_socket                   0x003
#define ORD_NetDll_setsockopt               0x007
#define ORD_NetDll_bind                     0x00B
#define ORD_NetDll_connect                  0x00C
#define ORD_NetDll_listen                   0x00D
#define ORD_NetDll_accept                   0x00E
#define ORD_NetDll_recvfrom                 0x014
#define ORD_NetDll_sendto                   0x018
#define ORD_NetDll_WSAGetLastError          0x01B
#define ORD_NetDll_XNetStartup              0x033
#define ORD_NetDll_XNetCreateKey            0x036
#define ORD_NetDll_XNetRegisterKey          0x037
#define ORD_NetDll_XNetUnregisterKey        0x038
#define ORD_NetDll_XNetXnAddrToInAddr       0x039
#define ORD_NetDll_XNetInAddrToXnAddr       0x03C
#define ORD_NetDll_XNetConnect              0x041
#define ORD_NetDll_XNetGetConnectStatus     0x042
#define ORD_NetDll_XNetDnsLookup            0x043
#define ORD_NetDll_XNetQosListen            0x045
#define ORD_NetDll_XNetQosLookup            0x046
#define ORD_NetDll_XNetQosRelease           0x048
#define ORD_NetDll_XNetGetTitleXnAddr       0x049
#define ORD_NetDll_XNetStartupEx            0x050
#define ORD_XNetLogonGetTitleID             0x136
#define ORD_XMsgInProcessCall               0x1F4
#define ORD_XMsgStartIORequest              0x1F7
#define ORD_XMsgStartIORequestEx            0x1FC
#define ORD_XamUserGetXUID                  0x20A
#define ORD_XamUserGetSigninState           0x210
#define ORD_XamUserCheckPrivilege           0x212
#define ORD_XamUserGetMembershipTierFromXUID 0x217
#define ORD_XamUserGetMembershipTier        0x21B
#define ORD_XamUserIsOnlineEnabled          0x221
#define ORD_XamUserGetSigninInfo            0x227

#define ORD_NetDll_XHttpStartup             0x0C9
#define ORD_NetDll_XHttpShutdown            0x0CA
#define ORD_NetDll_XHttpOpen                0x0CB
#define ORD_NetDll_XHttpCloseHandle         0x0CC
#define ORD_NetDll_XHttpConnect             0x0CD
#define ORD_NetDll_XHttpSetStatusCallback   0x0CE
#define ORD_NetDll_XHttpOpenRequest         0x0CF
#define ORD_NetDll_XHttpSendRequest         0x0D1
#define ORD_NetDll_XHttpReceiveResponse     0x0D2
#define ORD_NetDll_XHttpQueryHeaders        0x0D3
#define ORD_NetDll_XHttpReadData            0x0D4
#define ORD_NetDll_XHttpWriteData           0x0D5
#define ORD_NetDll_XHttpQueryOption         0x0D6
#define ORD_NetDll_XHttpSetOption           0x0D7
#define ORD_NetDll_XHttpDoWork              0x0D8
#define ORD_NetDll_XHttpCrackUrl            0x0DC
#define ORD_XamEnumerate                    0x250
#define ORD_XamNotifyCreateListener         0x28A
#define ORD_XNotifyGetNext                  0x28B
#define ORD_XampXAuthStartup                0x4BC
#define ORD_XampXAuthShutdown               0x4BD
#define ORD_XamGetToken                     0x4BE
#define ORD_XamFreeToken                    0x4BF

// xboxkrnl.exe ordinals
#define ORD_XexExecutableModuleHandle       0x193
#define ORD_XexCheckExecutablePrivilege     0x194

// Returns the address of an export, or NULL.
DWORD ResolveFunction(const char* module_name, DWORD ordinal);

// Writes a 4-instruction absolute branch (lis/ori/mtctr/bctr[l]) into dest.
VOID PatchInJump(DWORD* dest, DWORD target, BOOL linked);

// Redirects one import of `module` (e.g. the running title) to `hook`.
// Returns S_OK if at least one thunk was patched.
HRESULT PatchModuleImport(PLDR_DATA_TABLE_ENTRY module, const char* imported_module,
                          DWORD ordinal, DWORD hook);

// Mounts Hdd: so the plugin can read its INI and write its log.
VOID MountHdd();
