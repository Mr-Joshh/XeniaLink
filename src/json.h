#pragma once
#include <xtl.h>

// Minimal JSON helpers: enough for the small, flat objects the Xenia server
// sends and receives. Not a general parser.

struct JsonWriter {
  char* buf;
  DWORD cap;
  DWORD len;
  BOOL first;
};

VOID JsonBegin(JsonWriter* w, char* buf, DWORD cap);   // writes "{"
VOID JsonStr(JsonWriter* w, const char* key, const char* value);
VOID JsonInt(JsonWriter* w, const char* key, __int64 value);
VOID JsonBool(JsonWriter* w, const char* key, BOOL value);
VOID JsonRaw(JsonWriter* w, const char* key, const char* raw);  // pre-built array/object
const char* JsonEnd(JsonWriter* w);                    // writes "}", returns buf

// Finds "key": in `json` (searching from `from`) and copies its string value
// (or the literal text for numbers) into out. Returns pointer past the value,
// or NULL if not found.
const char* JsonGet(const char* from, const char* key, char* out, DWORD out_size);

// Iterates the objects of a top-level JSON array: returns pointer to the next
// '{' and sets *end to its matching '}'. Returns NULL when done.
const char* JsonNextObject(const char* p, const char** end);
