#include "pch.h"
#include "DartDumper.h"
#include <fstream>
#include <format>
#include <set>
#include <map>
#include <ranges>
#include <iostream>
#include <sstream>
#include <numeric>
#include "Disassembler.h"
#include "DartThreadInfo.h"
#include "CodeAnalyzer.h"

// TODO: move arm64 specific code to *_arm64 file

static std::unordered_map<std::string, std::string> OP_MAP {
	{ "==", "eq" },
	{ "<", "lt" }, { ">", "gt" },
	{ "<=", "lte" }, { ">=", "gte" },
	{ "=", "assign" },
	{ "[]", "at" }, { "[]=", "at_assign" },
	{ "++", "increment" }, { "--", "decrement" },
	{ "+", "add" }, { "-", "sub" }, { "*", "mul" }, { "~/", "div" }, { "/", "divf" },
	{ "%", "mod" },
	{ "&", "LAnd" }, { "|", "LOr" }, { "^", "xor" }, { "~", "not" }, {">>", "shar"}, {"<<", "shal"}, {">>", "shr"}
};

static std::string getFunctionName4Ida(const DartFunction& dartFn, const std::string& cls_prefix)
{
	auto fnName = dartFn.Name();
	if (dartFn.IsClosure() && fnName == "<anonymous closure>") {
		return "_anon_closure";
	}

	if (OP_MAP.contains(fnName)) {
		return "op_" + OP_MAP[fnName];
	}
	const auto last = fnName.back();
	if (last == '=') {
		fnName.pop_back();
		return fnName + "_assign";
	}
	else if (last == '-') {
		fnName.pop_back();
		return fnName + "_neg";
	}
	else if (last == '!') {
		fnName.pop_back();
		return fnName + "_not";
	}

	switch (dartFn.Kind()) {
	case DartFunction::CONSTRUCTOR: {
		std::string name = dartFn.IsStatic() ? "factory_ctor" : "ctor";
		ASSERT(fnName.starts_with(cls_prefix));
		if (fnName[cls_prefix.length()] == '.') {
			name += '_';
			name += &fnName[cls_prefix.length() + 1];
		}
		return name;
	}
	case DartFunction::SETTER:
		return "set_" + fnName;
	case DartFunction::GETTER:
		return "get_" + fnName;
	default:
		break;
	}

	return fnName;
}

const std::string& DartDumper::getQuoteString(dart::Object& obj)
{
	static std::string empty = "?";
	return empty;
}

void DartDumper::Dump4Ida(std::filesystem::path outDir)
{
	std::filesystem::create_directory(outDir);
	std::ofstream of((outDir / "addNames.py").string());
	of << "import ida_funcs\n";
	of << "import idaapi\n\n";

	// Process native lib functions
	for (auto cls : app.nativeLib.classes) {
		for (auto dartFn : cls->Functions()) {
			try {
				const auto ep = dartFn->Address();
				if (ep == 0 || dartFn->Size() == 0) continue;
				std::string name = dartFn->Name();
				std::replace(name.begin(), name.end(), '<', '_');
				std::replace(name.begin(), name.end(), '>', '_');
				std::replace(name.begin(), name.end(), ' ', '_');
				of << std::format("ida_funcs.add_func({:#x}, {:#x})\n", ep, ep + dartFn->Size());
				of << std::format("idaapi.set_name({:#x}, \"{}_{:x}\")\n", ep, name.c_str(), ep);
			} catch (...) {}
		}
	}

	// Process library functions
	for (auto dartLib : app.libs) {
		for (auto cls : dartLib->classes) {
			for (auto dartFn : cls->Functions()) {
				try {
					const auto ep = dartFn->Address();
					if (ep == 0 || dartFn->Size() == 0) continue;
					std::string name = dartFn->Name();
					std::replace(name.begin(), name.end(), '<', '_');
					std::replace(name.begin(), name.end(), '>', '_');
					std::replace(name.begin(), name.end(), ' ', '_');
					of << std::format("ida_funcs.add_func({:#x}, {:#x})\n", ep, ep + dartFn->Size());
					of << std::format("idaapi.set_name({:#x}, \"{}_{:x}\")\n", ep, name.c_str(), ep);
				} catch (...) {}
			}
		}
	}

	// Add stubs
	for (auto& [addr, stub] : app.stubs) {
		try {
			if (stub->Size() == 0) continue;
			of << std::format("ida_funcs.add_func({:#x}, {:#x})\n", addr, addr + stub->Size());
			of << std::format("idaapi.set_name({:#x}, \"stub_{}_{:x}\")\n", addr, stub->Name(), addr);
		} catch (...) {}
	}
}

#include <capstone/capstone.h>

static int g_total_fn = 0;
static int g_analyzed_fn = 0;

void DartDumper::DisassembleArm64(std::ostream& of, uint64_t addr, size_t size)
{
	csh handle;
	cs_insn* insn;

	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
		return;

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	size_t count = cs_disasm(handle, (const uint8_t*)addr, size, addr, 0, &insn);

	for (size_t i = 0; i < count; i++) {
		of << std::format("    //     {:#010x}: {:<10}{}\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
	}

	if (count > 0)
		cs_free(insn, count);
	cs_close(&handle);
}

void DartDumper::WriteClass(std::ostream& of, const dart::Class& cls)
{
	try {
		if (cls.IsNull()) return;

		auto cid = cls.id();
		auto& nameStr = dart::String::Handle(cls.ScrubbedName());
		auto name = nameStr.ToCString();

		of << std::format("// class id: {}, size: {:#x}\n", cid, cls.next_field_offset());
		of << std::format("class {} {{\n", name);

		// Fields
		const auto& fieldArray = dart::Array::Handle(cls.fields());
		if (!fieldArray.IsNull()) {
			for (intptr_t i = 0; i < fieldArray.Length(); i++) {
				auto fieldPtr = fieldArray.At(i);
				if (fieldPtr == nullptr) continue;
				const auto& field = dart::Field::Handle(dart::Field::RawCast(fieldPtr));
				auto& fn = dart::String::Handle(field.UserVisibleName());
				if (field.is_static()) {
					of << std::format("  static {} // offset: static\n", fn.ToCString());
				} else {
					of << std::format("  {} // offset: {:#x}\n", fn.ToCString(), field.Offset());
				}
			}
		}

		if (!fieldArray.IsNull() && fieldArray.Length() > 0)
			of << "\n";

		// Functions
		const auto& funcArray = dart::Array::Handle(cls.functions());
		if (!funcArray.IsNull()) {
			for (intptr_t i = 0; i < funcArray.Length(); i++) {
				auto funcPtr = funcArray.At(i);
				if (funcPtr == nullptr) continue;
				const auto& func = dart::Function::Handle(dart::Function::RawCast(funcPtr));
				auto& fn = dart::String::Handle(func.UserVisibleName());

				// Get the code to find entry point and size
				auto codePtr = func.CurrentCode();
				uint64_t ep = 0;
				int codeSize = 0;
				if (codePtr != nullptr && codePtr != dart::Code::null()) {
					const auto& code = dart::Code::Handle(codePtr);
					ep = code.EntryPoint();
					codeSize = code.Size();
				}

				if (ep == 0) {
					of << std::format("  {} () {{\n", fn.ToCString());
					of << "    // No code available\n";
					of << "  }\n\n";
				} else {
					of << std::format("  {} () {{\n", fn.ToCString());
					of << std::format("    // ** addr: {:#x}, size: {:#x}\n", ep, codeSize);

					// Check if we have analyzed data for this function
					g_total_fn++;
					auto fnBase = app.GetFunction(ep - app.base());
					if (fnBase && fnBase->AsFunction()) {
						auto dartFn2 = fnBase->AsFunction();
						auto analyzed = dartFn2->GetAnalyzedData();
						if (analyzed != nullptr) {
							try {
							auto& asmTexts = analyzed->asmTexts.Data();
							if (asmTexts.empty()) {
								DisassembleArm64(of, ep, codeSize);
							} else {
							g_analyzed_fn++;
							for (auto& asmText : asmTexts) {
								std::string extra;
								switch (asmText.dataType) {
								case AsmText::ThreadOffset:
									extra = "THR::" + GetThreadOffsetName(asmText.threadOffset);
									break;
								case AsmText::PoolOffset:
									extra = std::format("pool[{}]", asmText.poolOffset);
									break;
								case AsmText::Call: {
									auto* fn = app.GetFunction(asmText.callAddress);
									if (fn) {
										extra = fn->Name();
									}
									break;
								}
								}
								if (extra.empty())
									of << std::format("    {:#x}: {}\n", asmText.addr, &asmText.text[0]);
								else
									of << std::format("    {:#x}: {}  ; {}\n", asmText.addr, &asmText.text[0], extra);
							}
							} // else (not empty)
							} catch (...) {
								DisassembleArm64(of, ep, codeSize);
							}
						} else {
							DisassembleArm64(of, ep, codeSize);
						}
					} else {
						DisassembleArm64(of, ep, codeSize);
					}

					of << "  }\n\n";
				}
			}
		}

		of << "}\n\n";
	} catch (...) {
		of << "// [error printing class]\n\n";
	}
}

void DartDumper::DumpAnalysis(const char* filename)
{
	std::ofstream of(filename);
	int annotated = 0;

	// Dump IL annotations from all analyzed functions
	auto dumpClass = [&](DartClass* cls) {
		for (auto fn : cls->Functions()) {
			if (fn->Size() == 0 || !fn->GetAnalyzedData())
				continue;
			try {
				auto analyzed = fn->GetAnalyzedData();
				auto& asmTexts = analyzed->asmTexts.Data();
				if (asmTexts.empty()) continue;

				of << std::format("@ {:#x} {}\n", fn->Address(), fn->Name());
				for (auto& asmText : asmTexts) {
					std::string extra;
					switch (asmText.dataType) {
					case AsmText::ThreadOffset:
						extra = "THR::" + GetThreadOffsetName(asmText.threadOffset);
						break;
					case AsmText::PoolOffset:
						extra = std::format("pool[{}]", asmText.poolOffset);
						break;
					case AsmText::Call: {
						auto* callee = app.GetFunction(asmText.callAddress);
						if (callee) extra = callee->Name();
						break;
					}
					}
					if (extra.empty())
						of << std::format("  {:#x}: {}\n", asmText.addr, &asmText.text[0]);
					else
						of << std::format("  {:#x}: {}  ; {}\n", asmText.addr, &asmText.text[0], extra);
				}
				annotated++;
			} catch (...) {}
		}
	};

	for (auto lib : app.libs) {
		for (auto cls : lib->classes) {
			dumpClass(cls);
		}
	}
	for (auto cls : app.nativeLib.classes) {
		dumpClass(cls);
	}

	std::cerr << "DumpAnalysis: wrote " << annotated << " functions with IL annotations\n";
}

static void WriteAsmTextCommented(std::ostream& of, const AsmText& asmText, DartApp& app)
{
	std::string extra;
	switch (asmText.dataType) {
	case AsmText::ThreadOffset:
		extra = "THR::" + GetThreadOffsetName(asmText.threadOffset);
		break;
	case AsmText::PoolOffset:
		extra = std::format("pool[{}]", asmText.poolOffset);
		break;
	case AsmText::Call: {
		auto* callee = app.GetFunction(asmText.callAddress);
		if (callee) extra = callee->Name();
		break;
	}
	}
	if (extra.empty())
		of << std::format("    //     {:#x}: {}\n", asmText.addr, &asmText.text[0]);
	else
		of << std::format("    //     {:#x}: {}  ; {}\n", asmText.addr, &asmText.text[0], extra);
}

static const char* GetILKindName(ILInstr::ILKind kind)
{
	switch (kind) {
	case ILInstr::EnterFrame: return "EnterFrame";
	case ILInstr::LeaveFrame: return "LeaveFrame";
	case ILInstr::AllocateStack: return "AllocStack";
	case ILInstr::CheckStackOverflow: return "CheckStackOverflow";
	case ILInstr::LoadValue: return "LoadValue";
	case ILInstr::LoadObject: return "LoadObject";
	case ILInstr::LoadImm: return "LoadImm";
	case ILInstr::DecompressPointer: return "DecompressPointer";
	case ILInstr::SaveRegister: return "SaveRegister";
	case ILInstr::RestoreRegister: return "RestoreRegister";
	case ILInstr::SetupParameters: return "SetupParameters";
	case ILInstr::InitAsync: return "InitAsync";
	case ILInstr::GdtCall: return "GdtCall";
	case ILInstr::Call: return "Call";
	case ILInstr::Return: return "Return";
	case ILInstr::BranchIfSmi: return "BranchIfSmi";
	case ILInstr::LoadClassId: return "LoadClassId";
	case ILInstr::LoadTaggedClassIdMayBeSmi: return "LoadTaggedClassIdMayBeSmi";
	case ILInstr::BoxInt64: return "BoxInt64";
	case ILInstr::LoadInt32: return "LoadInt32";
	case ILInstr::AllocateObject: return "AllocateObject";
	case ILInstr::LoadArrayElement: return "LoadArrayElement";
	case ILInstr::StoreArrayElement: return "StoreArrayElement";
	case ILInstr::LoadField: return "LoadField";
	case ILInstr::StoreField: return "StoreField";
	case ILInstr::InitLateStaticField: return "InitLateStaticField";
	case ILInstr::LoadStaticField: return "LoadStaticField";
	case ILInstr::StoreStaticField: return "StoreStaticField";
	case ILInstr::WriteBarrier: return "WriteBarrier";
	case ILInstr::TestType: return "TestType";
	default: return "Unknown";
	}
}

static bool ILKindUsesVarValue(ILInstr::ILKind kind)
{
	// These IL kinds have ToString() that may access dangling VarValue references
	return kind == ILInstr::LoadValue || kind == ILInstr::SetupParameters ||
	       kind == ILInstr::InitAsync || kind == ILInstr::LoadObject ||
	       kind == ILInstr::AllocateObject || kind == ILInstr::LoadArrayElement ||
	       kind == ILInstr::StoreArrayElement || kind == ILInstr::LoadField ||
	       kind == ILInstr::StoreField || kind == ILInstr::TestType ||
	       kind == ILInstr::StoreStaticField || kind == ILInstr::LoadStaticField ||
	       kind == ILInstr::InitLateStaticField;
}

static std::string GetILAnnotation(ILInstr* il)
{
	if (ILKindUsesVarValue(il->Kind())) {
		return GetILKindName(il->Kind());
	}
	try {
		return il->ToString();
	} catch (...) {
		return GetILKindName(il->Kind());
	}
}

static void WriteFnAsmWithIL(std::ostream& of, AnalyzedFnData* analyzed, DartApp& app)
{
	auto& il_insns = analyzed->il_insns;
	auto& asmTexts = analyzed->asmTexts.Data();

	if (il_insns.empty() || asmTexts.empty()) {
		// No IL instructions, output all assembly as comments
		for (auto& asmText : asmTexts) {
			WriteAsmTextCommented(of, asmText, app);
		}
		return;
	}

	// Interleave IL annotations with assembly instructions
	size_t asmIdx = 0;
	for (auto& il : il_insns) {
		if (il->Kind() == ILInstr::Unknown) {
			// Skip unknown IL, assembly will be output as uncovered
			continue;
		}

		// Output assembly before this IL instruction (not covered by any IL)
		while (asmIdx < asmTexts.size() && asmTexts[asmIdx].addr < il->Start()) {
			WriteAsmTextCommented(of, asmTexts[asmIdx], app);
			asmIdx++;
		}

		// Output IL annotation (use safe annotation to avoid crashes from dangling VarValue refs)
		of << std::format("    // {:#x}: {}\n", il->Start(), GetILAnnotation(il.get()));

		// Output assembly covered by this IL instruction
		while (asmIdx < asmTexts.size() && asmTexts[asmIdx].addr < il->End()) {
			WriteAsmTextCommented(of, asmTexts[asmIdx], app);
			asmIdx++;
		}
	}

	// Output any remaining assembly after the last IL instruction
	while (asmIdx < asmTexts.size()) {
		WriteAsmTextCommented(of, asmTexts[asmIdx], app);
		asmIdx++;
	}
}

void DartDumper::DumpCodeWithAnalysis(const char* out_dir)
{
	std::filesystem::create_directory(out_dir);
	int fileCount = 0;

	// Dump classes organized by library with IL annotations
	std::cerr << "DumpCodeWithAnalysis: iterating " << app.libs.size() << " libraries\n";
	for (auto dartLib : app.libs) {
		try {
			std::string libUrl = dartLib->url;
			std::string filePath = libUrl;
			if (filePath.starts_with("package:"))
				filePath = filePath.substr(8);
			if (filePath.ends_with(".dart"))
				filePath = filePath.substr(0, filePath.size() - 5);

			std::string dirPart = std::format("{}/{}", out_dir, filePath);
			dirPart = dirPart.substr(0, dirPart.find_last_of('/'));
			std::filesystem::create_directories(dirPart);

			std::string outFile = std::format("{}/{}.dart", out_dir, filePath);

			std::ofstream of(outFile);
			of << std::format("// lib: {}, url: {}\n", libUrl, libUrl);

			for (auto dartCls : dartLib->classes) {
				try {
					dartCls->PrintHead(of);

					for (auto dartField : dartCls->Fields()) {
						try {
							dartField->Print(of);
						} catch (...) {}
					}

					if (!dartCls->Fields().empty() && !dartCls->Functions().empty())
						of << "\n";

					for (auto dartFn : dartCls->Functions()) {
						try {
							auto ep = dartFn->Address();
							auto codeSize = dartFn->Size();
							const auto& sig = dartFn->SigString().empty() ? (dartFn->Name() + "()") : dartFn->SigString();
							of << std::format("  {} {{\n", sig);
							if (ep != 0) {
								of << std::format("    // ** addr: {:#x}, size: {:#x}\n", ep, codeSize);
							}

							if (codeSize > 0 && dartFn->GetAnalyzedData()) {
								auto analyzed = dartFn->GetAnalyzedData();
								WriteFnAsmWithIL(of, analyzed, app);
							} else if (ep != 0 && codeSize > 0) {
								DisassembleArm64(of, dartFn->MemAddress(), codeSize);
							}

							of << "  }\n\n";
						} catch (...) {
							of << "  [error]\n";
						}
					}
					dartCls->PrintFoot(of);
				} catch (...) {
					of << "// [error printing class]\n\n";
				}
			}
			fileCount++;
		} catch (...) {}
	}

	// Also dump native classes with IL annotations
	{
		std::string nativeFile = std::format("{}/native.dart", out_dir);
		std::ofstream of(nativeFile);
		of << "// native classes\n\n";
		for (auto dartCls : app.nativeLib.classes) {
			try {
				dartCls->PrintHead(of);

				for (auto dartField : dartCls->Fields()) {
					try {
						dartField->Print(of);
					} catch (...) {}
				}

				if (!dartCls->Fields().empty() && !dartCls->Functions().empty())
					of << "\n";

				for (auto dartFn : dartCls->Functions()) {
					try {
						auto ep = dartFn->Address();
						auto codeSize = dartFn->Size();
						const auto& sig = dartFn->SigString().empty() ? (dartFn->Name() + "()") : dartFn->SigString();
						of << std::format("  {} {{\n", sig);
						if (ep != 0) {
							of << std::format("    // ** addr: {:#x}, size: {:#x}\n", ep, codeSize);
						}

						if (codeSize > 0 && dartFn->GetAnalyzedData()) {
							auto analyzed = dartFn->GetAnalyzedData();
							WriteFnAsmWithIL(of, analyzed, app);
						} else if (ep != 0 && codeSize > 0) {
							DisassembleArm64(of, dartFn->MemAddress(), codeSize);
						}

						of << "  }\n\n";
					} catch (...) {
						of << "  [error]\n";
					}
				}
				dartCls->PrintFoot(of);
				fileCount++;
			} catch (...) {}
		}
	}

	std::cerr << "DumpCodeWithAnalysis: wrote " << fileCount << " files\n";
}
static std::set<intptr_t> knownObjectPtrs;

void DartDumper::DumpCode(const char* out_dir)
{
	std::filesystem::create_directory(out_dir);
	int fileCount = 0;

	// Dump classes organized by library
	for (auto dartLib : app.libs) {
		try {
			// Create directory from URL
			std::string libUrl = dartLib->url;
			std::string filePath = libUrl;
			if (filePath.starts_with("package:"))
				filePath = filePath.substr(8);
			if (filePath.ends_with(".dart"))
				filePath = filePath.substr(0, filePath.size() - 5);

			std::string dirPart = std::format("{}/{}", out_dir, filePath);
			dirPart = dirPart.substr(0, dirPart.find_last_of('/'));
			std::filesystem::create_directories(dirPart);

			std::string outFile = std::format("{}/{}.dart", out_dir, filePath);

			// Handle duplicate filenames
			if (std::filesystem::exists(outFile)) {
				int dup = 1;
				while (std::filesystem::exists(std::format("{}_{}.dart", std::format("{}/{}", out_dir, filePath), dup)))
					dup++;
				outFile = std::format("{}_{}.dart", std::format("{}/{}", out_dir, filePath), dup);
			}

			std::ofstream lib_of(outFile);
			lib_of << std::format("// lib: {}, url: {}\n\n", libUrl, libUrl);

			for (auto dartCls : dartLib->classes) {
				try {
					lib_of << std::format("// class id: {}, size: {:#x}\n", dartCls->Id(), dartCls->Size());
					lib_of << std::format("class {} {{\n", dartCls->Name());

					for (auto dartField : dartCls->Fields()) {
						try {
							lib_of << std::format("  {}; // offset: {:#x}\n", dartField->Name(), dartField->Offset());
						} catch (...) {}
					}

					if (!dartCls->Fields().empty() && !dartCls->Functions().empty())
						lib_of << "\n";

					for (auto dartFn : dartCls->Functions()) {
						try {
							auto ep = dartFn->Address();
							auto codeSize = dartFn->Size();
							const auto& sig = dartFn->SigString().empty() ? (dartFn->Name() + "()") : dartFn->SigString();
							lib_of << std::format("  {} {{\n", sig);
							if (ep != 0 && codeSize > 0) {
								lib_of << std::format("    // ** addr: {:#x}, size: {:#x}\n", ep, codeSize);
								DisassembleArm64(lib_of, dartFn->MemAddress(), codeSize);
							}
							lib_of << "  }\n\n";
						} catch (...) {
							lib_of << "  [error]\n";
						}
					}
					lib_of << "}\n\n";
				} catch (...) {
					lib_of << "// [error printing class]\n\n";
				}
			}
			fileCount++;
		} catch (...) {}
	}

	// Also dump native classes (those without a library)
	{
		std::string nativeFile = std::format("{}/native.dart", out_dir);
		std::ofstream native_of(nativeFile);
		native_of << "// native classes\n\n";
		for (auto dartCls : app.nativeLib.classes) {
			try {
				native_of << std::format("// class id: {}, size: {:#x}\n", dartCls->Id(), dartCls->Size());
				native_of << std::format("class {} {{\n", dartCls->Name());

				for (auto dartField : dartCls->Fields()) {
					try {
						native_of << std::format("  {}; // offset: {:#x}\n", dartField->Name(), dartField->Offset());
					} catch (...) {}
				}

				if (!dartCls->Fields().empty() && !dartCls->Functions().empty())
					native_of << "\n";

				for (auto dartFn : dartCls->Functions()) {
					try {
						auto ep = dartFn->Address();
						auto codeSize = dartFn->Size();
						const auto& sig = dartFn->SigString().empty() ? (dartFn->Name() + "()") : dartFn->SigString();
						native_of << std::format("  {} {{\n", sig);
						if (ep != 0 && codeSize > 0) {
							native_of << std::format("    // ** addr: {:#x}, size: {:#x}\n", ep, codeSize);
							DisassembleArm64(native_of, dartFn->MemAddress(), codeSize);
						}
						native_of << "  }\n\n";
					} catch (...) {
						native_of << "  [error]\n";
					}
				}
				native_of << "}\n\n";
				fileCount++;
			} catch (...) {}
		}
	}

	std::cerr << "DumpCode: wrote " << fileCount << " files (" << app.libs.size() << " libs, " << app.nativeLib.classes.size() << " native)\n";
}
void DartDumper::DumpObjectPool(const char* filename)
{
	std::ofstream of(filename);
	of << "[Object pool - skipped]\n";
}

void DartDumper::DumpObjects(const char* filename)
{
	std::ofstream of(filename);
	of << std::format("[Objects - skipped, {} entries]\n", 0);
}
