#include "pch.h"
#include "DartLoader.h"
#include <stdexcept>
#include <cstdlib>

// Note: most running dart VM code from runtime/bin/main.cc

// Direct access to the VM's FLAG_causal_async_stacks global
extern "C" { extern bool _ZN4dart24FLAG_causal_async_stacksE; }
#define CAUSAL_FLAG _ZN4dart24FLAG_causal_async_stacksE

static void init_vm_flags()
{
	const char* options[] = {
		"--precompilation",
	};
	char* error = Dart_SetVMFlags(sizeof(options) / sizeof(*options), options);
	if (error) {
		throw std::runtime_error(error);
	}

	// In 2.7.2, Dart_SetVMFlags doesn't set causal_async_stacks, set it directly
	CAUSAL_FLAG = true;
}

static void init_dart(const uint8_t* vm_snapshot_data, const uint8_t* vm_snapshot_instructions)
{
	char* error = NULL;

	Dart_InitializeParams init_params;
	memset(&init_params, 0, sizeof(init_params));
	init_params.version = DART_INITIALIZE_PARAMS_CURRENT_VERSION;
	init_params.vm_snapshot_data = vm_snapshot_data;
	init_params.vm_snapshot_instructions = vm_snapshot_instructions;
	init_params.start_kernel_isolate = false;
	error = Dart_Initialize(&init_params);
	if (error) {
		throw std::runtime_error(error);
	}

	// Re-set in case Dart_Initialize overwrote it
	CAUSAL_FLAG = true;
}

static Dart_Isolate load_isolate(const uint8_t* isolate_snapshot_data, const uint8_t* isolate_snapshot_instructions)
{
	char* error = NULL;

	Dart_IsolateFlags flags;
	Dart_IsolateFlagsInitialize(&flags);
#if defined(HAS_IS_SYSTEM_ISOLATE)
	flags.is_system_isolate = false;
#endif
#if defined(HAS_SNAPSHOT_IS_DONT_NEED_SAFE)
	flags.snapshot_is_dontneed_safe = true;
#endif
	// null safety was introduced in Dart 2.12, not available in 2.7.2
	auto pos = strstr((const char*)isolate_snapshot_data + 0x30, "null-safety");
#if defined(HAS_NULL_SAFETY_FLAG)
	if (pos != NULL)
		flags.null_safety = pos[-1] == ' ';
	else
		flags.null_safety = false;
#endif

	auto isolate = Dart_CreateIsolateGroup(nullptr, nullptr, isolate_snapshot_data,
		isolate_snapshot_instructions, &flags,
		nullptr, nullptr, &error);
	if (isolate == NULL) {
		throw std::runtime_error(error);
	}

	return isolate;
}

Dart_Isolate DartLoader::Load(LibAppInfo& libInfo)
{
	init_vm_flags();

	init_dart(libInfo.vm_snapshot_data, libInfo.vm_snapshot_instructions);

	auto isolate = load_isolate(libInfo.isolate_snapshot_data, libInfo.isolate_snapshot_instructions);

	return isolate;
}

template<typename T>
inline void ignore_result(const T& /* unused result */) {}

void DartLoader::Unload()
{
	if (Dart_CurrentIsolate() != nullptr) {
		Dart_ShutdownIsolate();
	}
	ignore_result(Dart_Cleanup());
}
