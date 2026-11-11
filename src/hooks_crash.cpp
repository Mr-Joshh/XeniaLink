// Crash breadcrumbs: hook the game's own fatal-error paths (KeBugCheck[Ex],
// RtlRaiseException, DbgBreakPoint, XamLoaderTerminateTitle) and log where they
// were called from before passing them on. Addresses map back to the game image
// (base 0x82000000) or the plugin (0x91E00000).

#include "hooks.h"
#include "hooking.h"
#include "log.h"
#include "config.h"
#include <stdio.h>
extern "C" void* _ReturnAddress(void);
#pragma intrinsic(_ReturnAddress)

#define ORD_DbgBreakPoint           0x001
#define ORD_KeBugCheck              0x052
#define ORD_KeBugCheckEx            0x053
#define ORD_RtlRaiseException       0x136
#define ORD_XamLoaderTerminateTitle 0x1A9

extern "C" BOOL NTAPI MmIsAddressValid(PVOID address);

typedef VOID (*KeBugCheck_t)(DWORD code);
typedef VOID (*KeBugCheckEx_t)(DWORD code, DWORD p1, DWORD p2, DWORD p3, DWORD p4);
typedef VOID (*RtlRaiseException_t)(PEXCEPTION_RECORD record);
typedef VOID (*DbgBreakPoint_t)();
typedef VOID (*XamLoaderTerminateTitle_t)();

static KeBugCheck_t g_orig_KeBugCheck;
static KeBugCheckEx_t g_orig_KeBugCheckEx;
static RtlRaiseException_t g_orig_RtlRaiseException;
static DbgBreakPoint_t g_orig_DbgBreakPoint;
static XamLoaderTerminateTitle_t g_orig_TerminateTitle;

// Walks the PowerPC back chain from (roughly) the current stack pointer and logs
// the saved return addresses. Each frame: [sp] = caller's sp, saved LR at
// caller_sp - 8 (the XDK's "stw r12,-8(r1)" prologue).
static VOID LogStack(const char* what, DWORD caller) {
  Log("crash: %s called from %08X", what, caller);
  DWORD sp = (DWORD)&caller;
  char line[200];
  int len = 0;
  for (int i = 0; i < 16 && len < 180; i++) {
    sp &= ~3u;
    if (!sp || !MmIsAddressValid((PVOID)sp)) break;
    DWORD next = *(DWORD*)sp;
    if (next <= sp || !MmIsAddressValid((PVOID)(next - 8))) break;
    DWORD lr = *(DWORD*)(next - 8);
    len += _snprintf_s(line + len, sizeof(line) - len, _TRUNCATE, "%08X ", lr);
    sp = next;
  }
  line[len] = 0;
  Log("crash:   stack %s", line);
}

static VOID Hook_KeBugCheck(DWORD code) {
  Log("crash: KeBugCheck(%08X)", code);
  LogStack("KeBugCheck", (DWORD)_ReturnAddress());
  g_orig_KeBugCheck(code);
}

static VOID Hook_KeBugCheckEx(DWORD code, DWORD p1, DWORD p2, DWORD p3, DWORD p4) {
  Log("crash: KeBugCheckEx(%08X, %08X, %08X, %08X, %08X)", code, p1, p2, p3, p4);
  LogStack("KeBugCheckEx", (DWORD)_ReturnAddress());
  g_orig_KeBugCheckEx(code, p1, p2, p3, p4);
}

static VOID Hook_RtlRaiseException(PEXCEPTION_RECORD record) {
  // 0x406D1388 = MS_VC_EXCEPTION, raised to name a thread: harmless noise.
  if (record && record->ExceptionCode == 0x406D1388 && !g_config.debug_log) {
    g_orig_RtlRaiseException(record);
    return;
  }
  if (record) {
    Log("crash: RtlRaiseException code %08X at %08X, %u params [%08X %08X %08X]",
        record->ExceptionCode, (DWORD)record->ExceptionAddress, record->NumberParameters,
        record->NumberParameters > 0 ? (DWORD)record->ExceptionInformation[0] : 0,
        record->NumberParameters > 1 ? (DWORD)record->ExceptionInformation[1] : 0,
        record->NumberParameters > 2 ? (DWORD)record->ExceptionInformation[2] : 0);
  }
  LogStack("RtlRaiseException", (DWORD)_ReturnAddress());
  g_orig_RtlRaiseException(record);
}

static VOID Hook_DbgBreakPoint() {
  LogStack("DbgBreakPoint", (DWORD)_ReturnAddress());
  g_orig_DbgBreakPoint();
}

static VOID Hook_XamLoaderTerminateTitle() {
  LogStack("XamLoaderTerminateTitle", (DWORD)_ReturnAddress());
  g_orig_TerminateTitle();
}

DWORD InstallCrashHooks(PLDR_DATA_TABLE_ENTRY title) {
  g_orig_KeBugCheck = (KeBugCheck_t)ResolveFunction(MODULE_KERNEL, ORD_KeBugCheck);
  g_orig_KeBugCheckEx = (KeBugCheckEx_t)ResolveFunction(MODULE_KERNEL, ORD_KeBugCheckEx);
  g_orig_RtlRaiseException =
      (RtlRaiseException_t)ResolveFunction(MODULE_KERNEL, ORD_RtlRaiseException);
  g_orig_DbgBreakPoint = (DbgBreakPoint_t)ResolveFunction(MODULE_KERNEL, ORD_DbgBreakPoint);
  g_orig_TerminateTitle =
      (XamLoaderTerminateTitle_t)ResolveFunction(MODULE_XAM, ORD_XamLoaderTerminateTitle);

  DWORD patched = 0;
  if (PatchModuleImport(title, MODULE_KERNEL, ORD_KeBugCheck, (DWORD)Hook_KeBugCheck) == S_OK)
    patched++;
  if (PatchModuleImport(title, MODULE_KERNEL, ORD_KeBugCheckEx, (DWORD)Hook_KeBugCheckEx) == S_OK)
    patched++;
  if (PatchModuleImport(title, MODULE_KERNEL, ORD_RtlRaiseException,
                        (DWORD)Hook_RtlRaiseException) == S_OK)
    patched++;
  if (PatchModuleImport(title, MODULE_KERNEL, ORD_DbgBreakPoint, (DWORD)Hook_DbgBreakPoint) == S_OK)
    patched++;
  if (PatchModuleImport(title, MODULE_XAM, ORD_XamLoaderTerminateTitle,
                        (DWORD)Hook_XamLoaderTerminateTitle) == S_OK)
    patched++;
  return patched;
}
