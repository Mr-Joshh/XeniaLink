#include "hooking.h"

DWORD ResolveFunction(const char* module_name, DWORD ordinal) {
  HANDLE module = NULL;
  if (XexGetModuleHandle(module_name, &module) != 0 || module == NULL) {
    return 0;
  }
  DWORD address = 0;
  if (XexGetProcedureAddress(module, ordinal, &address) != 0) {
    return 0;
  }
  return address;
}

VOID PatchInJump(DWORD* dest, DWORD target, BOOL linked) {
  // lis r11, target@h
  dest[0] = 0x3D600000 | ((target >> 16) & 0xFFFF);
  // ori r11, r11, target@l
  dest[1] = 0x616B0000 | (target & 0xFFFF);
  // mtctr r11
  dest[2] = 0x7D6903A6;
  // bctr / bctrl
  dest[3] = linked ? 0x4E800421 : 0x4E800420;
  __dcbst(0, dest);
  __sync();
  __emit(0x4C00012C);  // isync
}

HRESULT PatchModuleImport(PLDR_DATA_TABLE_ENTRY module, const char* imported_module,
                          DWORD ordinal, DWORD hook) {
  const DWORD original = ResolveFunction(imported_module, ordinal);
  if (!original || !module) {
    return E_FAIL;
  }

  PXEX_IMPORT_DESCRIPTOR desc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(
      module->XexHeaderBase, 0x000103FF);
  if (!desc) {
    return E_FAIL;
  }

  HRESULT result = E_FAIL;
  char* string_table = (char*)(desc + 1);
  PXEX_IMPORT_TABLE table = (PXEX_IMPORT_TABLE)(string_table + desc->NameTableSize);

  for (DWORD m = 0; m < desc->ModuleCount; m++) {
    DWORD* thunks = (DWORD*)(table + 1);
    for (DWORD i = 0; i < table->ImportCount; i++) {
      // Each import has a data thunk (holds the export address) followed by a
      // code thunk (4 instructions that branch to it).
      DWORD* data_thunk = (DWORD*)thunks[i];
      if (*data_thunk != original) {
        continue;
      }
      *data_thunk = hook;
      if (i + 1 < table->ImportCount) {
        PatchInJump((DWORD*)thunks[i + 1], hook, FALSE);
      }
      result = S_OK;
    }
    table = (PXEX_IMPORT_TABLE)((BYTE*)table + table->TableSize);
  }
  return result;
}

PLDR_DATA_TABLE_ENTRY GetTitleModule() {
  // The export is a variable holding the title's loader entry.
  PLDR_DATA_TABLE_ENTRY* slot =
      (PLDR_DATA_TABLE_ENTRY*)ResolveFunction(MODULE_KERNEL, ORD_XexExecutableModuleHandle);
  return slot ? *slot : NULL;
}

VOID MountHdd() {
  // System threads resolve drive names through \System??\, titles through
  // \??\. Create both, like JRPC2 does. Fails harmlessly if a link exists.
  static const char* kLinks[] = {"\\System??\\Hdd:", "\\??\\Hdd:"};
  KSTRING link, device;
  RtlInitAnsiString(&device, "\\Device\\Harddisk0\\Partition1");
  for (int i = 0; i < ARRAYSIZE(kLinks); i++) {
    RtlInitAnsiString(&link, kLinks[i]);
    ObCreateSymbolicLink(&link, &device);
  }
}
