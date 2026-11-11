#include "json.h"
#include <stdio.h>
#include <string.h>

static VOID Append(JsonWriter* w, const char* s) {
  size_t n = strlen(s);
  if (w->len + n + 1 >= w->cap) n = w->cap - w->len - 1;
  memcpy(w->buf + w->len, s, n);
  w->len += (DWORD)n;
  w->buf[w->len] = 0;
}

static VOID Key(JsonWriter* w, const char* key) {
  if (!w->first) Append(w, ",");
  w->first = FALSE;
  Append(w, "\"");
  Append(w, key);
  Append(w, "\":");
}

VOID JsonBegin(JsonWriter* w, char* buf, DWORD cap) {
  w->buf = buf;
  w->cap = cap;
  w->len = 0;
  w->first = TRUE;
  buf[0] = 0;
  Append(w, "{");
}

VOID JsonStr(JsonWriter* w, const char* key, const char* value) {
  Key(w, key);
  Append(w, "\"");
  // Values we send are hex IDs, IPs and gamertags; escape the two risky chars.
  for (const char* p = value; *p; p++) {
    char c[3] = {*p, 0, 0};
    if (*p == '"' || *p == '\\') { c[0] = '\\'; c[1] = *p; }
    Append(w, c);
  }
  Append(w, "\"");
}

VOID JsonInt(JsonWriter* w, const char* key, __int64 value) {
  char num[32];
  _snprintf_s(num, sizeof(num), _TRUNCATE, "%I64d", value);
  Key(w, key);
  Append(w, num);
}

VOID JsonBool(JsonWriter* w, const char* key, BOOL value) {
  Key(w, key);
  Append(w, value ? "true" : "false");
}

VOID JsonRaw(JsonWriter* w, const char* key, const char* raw) {
  Key(w, key);
  Append(w, raw);
}

const char* JsonEnd(JsonWriter* w) {
  Append(w, "}");
  return w->buf;
}

const char* JsonGet(const char* from, const char* key, char* out, DWORD out_size) {
  char pattern[64];
  _snprintf_s(pattern, sizeof(pattern), _TRUNCATE, "\"%s\"", key);
  const char* p = strstr(from, pattern);
  if (!p) return NULL;
  p += strlen(pattern);
  while (*p == ' ' || *p == ':') p++;

  DWORD n = 0;
  if (*p == '"') {
    p++;
    while (*p && *p != '"' && n + 1 < out_size) {
      if (*p == '\\' && p[1]) p++;
      out[n++] = *p++;
    }
    if (*p == '"') p++;
  } else {
    while (*p && *p != ',' && *p != '}' && *p != ']' && n + 1 < out_size) {
      out[n++] = *p++;
    }
  }
  out[n] = 0;
  return p;
}

const char* JsonNextObject(const char* p, const char** end) {
  while (*p && *p != '{') p++;
  if (!*p) return NULL;
  int depth = 0;
  BOOL in_str = FALSE;
  for (const char* q = p; *q; q++) {
    if (in_str) {
      if (*q == '\\' && q[1]) q++;
      else if (*q == '"') in_str = FALSE;
    } else if (*q == '"') {
      in_str = TRUE;
    } else if (*q == '{') {
      depth++;
    } else if (*q == '}' && --depth == 0) {
      *end = q;
      return p;
    }
  }
  return NULL;
}
