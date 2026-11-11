#include "log.h"
#include "hooking.h"
#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define ORD_XNotifyQueueUI 0x290
#define XNOTIFYUI_TYPE_CUSTOM 0x22  // same type JRPC2 uses
#define XNOTIFYUI_PRIORITY_HIGH 2

#define FILE_SHARE_READ_WRITE     0x3
#define FILE_OPEN_IF_DISPOSITION  3
#define FILE_OVERWRITE_IF_DISP    5
#define FILE_SYNC_NONDIR          (0x20 | 0x40)  // synchronous I/O, non-directory
#define KOBJ_CASE_INSENSITIVE     0x40

static CRITICAL_SECTION g_log_lock;
static char g_log_path[MAX_PATH];
static BOOL g_log_ready = FALSE;

static LONG OpenFile(const char* path, ACCESS_MASK access, ULONG disposition, HANDLE* out) {
  KSTRING name;
  RtlInitAnsiString(&name, path);
  KOBJECT_ATTRIBUTES attrs = {NULL, &name, KOBJ_CASE_INSENSITIVE};
  KIO_STATUS_BLOCK io;
  return NtCreateFile(out, access | SYNCHRONIZE, &attrs, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ_WRITE, disposition, FILE_SYNC_NONDIR);
}

LONG KFileWrite(const char* path, const void* data, DWORD len, BOOL append) {
  HANDLE h = NULL;
  LONG status = OpenFile(path, GENERIC_WRITE,
                         append ? FILE_OPEN_IF_DISPOSITION : FILE_OVERWRITE_IF_DISP, &h);
  if (status < 0) return status;
  KIO_STATUS_BLOCK io;
  LARGE_INTEGER offset;
  offset.HighPart = -1;
  offset.LowPart = 0xFFFFFFFF;  // FILE_WRITE_TO_END_OF_FILE
  if (len) status = NtWriteFile(h, NULL, NULL, NULL, &io, (PVOID)data, len,
                                append ? &offset : NULL);
  NtClose(h);
  return status;
}

DWORD KFileRead(const char* path, char* buf, DWORD buf_size) {
  HANDLE h = NULL;
  buf[0] = 0;
  if (OpenFile(path, GENERIC_READ, 1 /* FILE_OPEN */, &h) < 0) return 0;
  KIO_STATUS_BLOCK io;
  LARGE_INTEGER offset;
  offset.QuadPart = 0;
  DWORD n = 0;
  if (NtReadFile(h, NULL, NULL, NULL, &io, buf, buf_size - 1, &offset) >= 0) {
    n = (DWORD)io.Information;
  }
  NtClose(h);
  buf[n] = 0;
  return n;
}

typedef VOID (*XNotifyQueueUI_t)(DWORD type, DWORD user_index, ULONGLONG areas,
                                 const wchar_t* text, PVOID context);

VOID Notify(const wchar_t* fmt, ...) {
  static XNotifyQueueUI_t notify = NULL;
  if (!notify) notify = (XNotifyQueueUI_t)ResolveFunction(MODULE_XAM, ORD_XNotifyQueueUI);
  if (!notify) return;
  wchar_t text[128];
  va_list args;
  va_start(args, fmt);
  _vsnwprintf_s(text, ARRAYSIZE(text), _TRUNCATE, fmt, args);
  va_end(args);
  notify(XNOTIFYUI_TYPE_CUSTOM, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, text, NULL);
}

LONG LogInit(const char* path) {
  static BOOL lock_ready = FALSE;
  if (!lock_ready) {
    InitializeCriticalSection(&g_log_lock);
    lock_ready = TRUE;
  }
  strncpy_s(g_log_path, sizeof(g_log_path), path, _TRUNCATE);

  // Keep the previous boot's log (e.g. a crash followed by a reboot) as *.prev.log.
  const char* ext = strrchr(path, '.');
  if (ext) {
    char prev[MAX_PATH];
    _snprintf_s(prev, sizeof(prev), _TRUNCATE, "%.*s.prev%s", (int)(ext - path), path, ext);
    const DWORD kMaxPrev = 1024 * 1024;
    char* old = (char*)malloc(kMaxPrev);
    if (old) {
      DWORD n = KFileRead(path, old, kMaxPrev);
      if (n) KFileWrite(prev, old, n, FALSE);
      free(old);
    }
  }

  static const char kHeader[] = "XeniaLink log\r\n";
  LONG status = KFileWrite(g_log_path, kHeader, sizeof(kHeader) - 1, FALSE);
  g_log_ready = status >= 0;
  return status;
}

static VOID LogV(const char* fmt, va_list args) {
  char line[1024];
  int n = _snprintf_s(line, sizeof(line), _TRUNCATE, "[%08X] ", GetTickCount());
  int m = _vsnprintf_s(line + n, sizeof(line) - n - 2, _TRUNCATE, fmt, args);
  if (m < 0) m = (int)strlen(line + n);
  OutputDebugStringA(line + n);
  OutputDebugStringA("\n");
  if (!g_log_ready) return;

  line[n + m] = '\r';
  line[n + m + 1] = '\n';
  EnterCriticalSection(&g_log_lock);
  KFileWrite(g_log_path, line, n + m + 2, TRUE);
  LeaveCriticalSection(&g_log_lock);
}

VOID Log(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  LogV(fmt, args);
  va_end(args);
}

VOID LogDebug(const char* fmt, ...) {
  if (!g_config.debug_log) return;
  va_list args;
  va_start(args, fmt);
  LogV(fmt, args);
  va_end(args);
}
