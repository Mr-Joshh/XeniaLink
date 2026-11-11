#pragma once
#include <xtl.h>

// Device paths on the internal HDD, used with the native file API so logging
// and config loading don't depend on the Hdd: drive link existing.
#define HDD_DEVICE "\\Device\\Harddisk0\\Partition1\\"

// Appends a printf-style line to the log file (and the debug output).
// path is a device path like HDD_DEVICE "XeniaLink.log".
// Returns the NTSTATUS of creating the file (0 = OK).
LONG LogInit(const char* path);
VOID Log(const char* fmt, ...);
// Like Log, but only written when debug_log = true in the ini (diagnostic detail).
VOID LogDebug(const char* fmt, ...);

// Shows an on-screen notification (works without any file access).
VOID Notify(const wchar_t* fmt, ...);

// Native file helpers. KFileRead returns bytes read (0 on failure) and
// NUL-terminates buf.
LONG KFileWrite(const char* device_path, const void* data, DWORD len, BOOL append);
DWORD KFileRead(const char* device_path, char* buf, DWORD buf_size);
