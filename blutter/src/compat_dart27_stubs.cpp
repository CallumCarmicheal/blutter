// Stubs for missing symbols in Dart 2.7.2 static library
// Mangled names extracted directly from the .a with `nm`

#include "pch.h"
#include <vm/native_arguments.h>

namespace dart {
namespace compiler {
namespace ffi {

size_t ElementSizeInBytes(intptr_t class_id) {
  return sizeof(intptr_t);
}

}  // namespace ffi
}  // namespace compiler
}  // namespace dart

// Weak stubs with exact mangled names from the static library
extern "C" {

__attribute__((weak)) void _ZN4dart16BootstrapNatives18DN_Wasm_growMemoryEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives18DN_Wasm_initMemoryEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives18DN_Wasm_initModuleEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives19DN_Wasm_initImportsEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives20DN_Wasm_callFunctionEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives20DN_Wasm_initFunctionEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives20DN_Wasm_initInstanceEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives22DN_Wasm_describeModuleEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives22DN_Wasm_getMemoryPagesEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives23DN_Wasm_addGlobalImportEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives23DN_Wasm_addMemoryImportEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives24DN_LinkedHashMap_getDataEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives24DN_LinkedHashMap_setDataEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives25DN_LinkedHashMap_getIndexEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives25DN_LinkedHashMap_setIndexEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives25DN_Wasm_addFunctionImportEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives28DN_LinkedHashMap_getHashMaskEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives28DN_LinkedHashMap_getUsedDataEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives28DN_LinkedHashMap_setHashMaskEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives28DN_LinkedHashMap_setUsedDataEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives30DN_Wasm_initMemoryFromInstanceEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives31DN_LinkedHashMap_getDeletedKeysEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}
__attribute__((weak)) void _ZN4dart16BootstrapNatives31DN_LinkedHashMap_setDeletedKeysEPNS_6ThreadEPNS_4ZoneEPNS_15NativeArgumentsE() {}

}
