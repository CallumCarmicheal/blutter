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
					DisassembleArm64(of, ep, codeSize);
					of << "  }\n\n";
				}
			}
		}

		of << "}\n\n";
	} catch (...) {
		of << "// [error printing class]\n\n";
	}
}

void DartDumper::DumpCode(const char* out_dir)
{
	std::filesystem::create_directory(out_dir);

	// Get all libraries from the ObjectStore
	auto isolate = dart::Isolate::Current();
	auto store = isolate->object_store();
	auto& libs = dart::GrowableObjectArray::Handle(store->libraries());
	auto& lib = dart::Library::Handle();
	auto& cls = dart::Class::Handle();
	auto& url = dart::String::Handle();

	int fileCount = 0;
	int libCount = 0;

	if (!libs.IsNull()) {
		for (intptr_t i = 0; i < libs.Length(); i++) {
			lib ^= libs.At(i);
			if (lib.IsNull()) continue;

			std::string libUrl;
			auto rawUrl = lib.url();
			if (rawUrl != nullptr && rawUrl != dart::String::null()) {
				url = rawUrl;
				libUrl = url.ToCString();
			} else {
				libUrl = std::format("lib_{}", libCount);
			}

			// Create output file from URL
			std::string filePath = libUrl;
			// Convert package: URLs to file paths
			if (filePath.starts_with("package:")) {
				filePath = filePath.substr(8); // remove "package:"
			} else if (filePath.starts_with("dart:")) {
				filePath = filePath.substr(5); // keep dart/ prefix for directory
			}
			// Remove .dart extension if already present
			if (filePath.ends_with(".dart"))
				filePath = filePath.substr(0, filePath.size() - 5);

			std::string outPath = std::format("{}/{}", out_dir, filePath);
			std::string dirPart = outPath.substr(0, outPath.find_last_of('/'));
			std::filesystem::create_directories(dirPart);

			// Handle duplicate filenames
			std::string fullOutPath = outPath + ".dart";
			if (std::filesystem::exists(fullOutPath)) {
				int dupCounter = 1;
				while (std::filesystem::exists(std::format("{}_{}.dart", outPath, dupCounter)))
					dupCounter++;
				fullOutPath = std::format("{}_{}.dart", outPath, dupCounter);
			}

			std::ofstream of(fullOutPath);
			of << std::format("// lib: {}, url: {}\n\n", libUrl, libUrl);

			// Iterate classes in this library
			auto topClsPtr = lib.toplevel_class();
			if (topClsPtr != nullptr) {
				cls = topClsPtr;
				WriteClass(of, cls);
			}

			// Get classes from the library dictionary
			dart::DictionaryIterator iter(lib);
			while (iter.HasNext()) {
				auto objPtr = iter.GetNext();
				if (objPtr == nullptr) break;
				if (objPtr->IsClass()) {
					cls = dart::Class::RawCast(objPtr);
					WriteClass(of, cls);
				}
			}

			libCount++;
			fileCount++;
		}
	}

	// Also output native classes (those without a library)
	{
		std::ofstream of(std::format("{}/native.dart", out_dir));
		of << "// native classes\n\n";
		for (auto dartCls : app.nativeLib.classes) {
			try {
				of << std::format("// class id: {}, size: {:#x}\n", dartCls->Id(), dartCls->Size());
				of << std::format("class {} {{\n", dartCls->Name());

				for (auto dartField : dartCls->Fields()) {
					try {
						of << std::format("  {}; // offset: {:#x}\n", dartField->Name(), dartField->Offset());
					} catch (...) {}
				}

				if (!dartCls->Fields().empty() && !dartCls->Functions().empty())
					of << "\n";

				for (auto dartFn : dartCls->Functions()) {
					try {
						of << std::format("  {} ({:#x}) size: {:#x}\n", dartFn->Name(), dartFn->Address(), dartFn->Size());
					} catch (...) {}
				}
				of << "}\n\n";
				fileCount++;
			} catch (...) {}
		}
	}

	std::cerr << "DumpCode: wrote " << fileCount << " files in " << libCount << " libraries\n";
}

// collect instance ptr to dump the full contents in DumpObjects()
static std::set<intptr_t> knownObjectPtrs;

std::string DartDumper::ObjectToString(dart::Object& obj, bool simpleForm, bool nestedObj, int depth)
{
	const auto cid = obj.GetClassId();
	//auto dartCls = app_.classes[obj.GetClassId()];

	if (obj.IsString()) {
		auto& val = getQuoteString(obj);
		if (simpleForm || depth > 0)
			return val;
		return "String: " + val;
	}

	// use TypedData or TypedDataBase ?
	if (obj.IsTypedData()) {
		//dart::kTypedDataInt32ArrayCid;
		auto& arr = dart::TypedData::Cast(obj);
		const auto arr_len = arr.Length();
		auto ptr = arr.DataAddr(0);
		std::string txt;
		if (arr_len > 0) {
			switch (arr.ElementType()) {
#define ACCUMLATE(type) { \
	auto data = (type*)ptr; \
	txt = std::accumulate(data + 1, data + arr_len, std::format("[{:#x}", data[0]), [](std::string x, type y) { return x + ", " + std::format("{:#x}", y); } ); \
}
			case dart::kInt8ArrayElement:
				ACCUMLATE(int8_t);
				break;
			case dart::kUint8ArrayElement:
			case dart::kUint8ClampedArrayElement:
				ACCUMLATE(uint8_t);
				break;
			case dart::kInt16ArrayElement:
				ACCUMLATE(int16_t);
				break;
			case dart::kUint16ArrayElement:
				ACCUMLATE(uint16_t);
				break;
			case dart::kInt32ArrayElement:
				ACCUMLATE(int32_t);
				break;
			case dart::kUint32ArrayElement:
				ACCUMLATE(uint32_t);
				break;
			case dart::kInt64ArrayElement:
				ACCUMLATE(int64_t);
				break;
			case dart::kUint64ArrayElement:
				ACCUMLATE(uint64_t);
				break;
#undef ACCUMLATE
#define ACCUMLATE(type) { \
	auto data = (type*)ptr; \
	txt = std::accumulate(data + 1, data + arr_len, std::format("[{}", data[0]), [](std::string x, type y) { return x + ", " + std::format("{}", y); } ); \
}
			case dart::kFloat32ArrayElement:
				ACCUMLATE(float);
				break;
			case dart::kFloat64ArrayElement:
				ACCUMLATE(double);
				break;
#undef ACCUMLATE
			case dart::kFloat32x4ArrayElement:
			case dart::kInt32x4ArrayElement:
			case dart::kFloat64x2ArrayElement:
				FATAL("TODO: simd array");
			}

			txt += ']';
		}
		//arr.ElementSizeInBytes();
		return std::format("{}({}) {}", app.GetClass(cid)->Name(), arr_len, txt);
	}

	switch (cid) {
	case dart::kSmiCid:
		if (simpleForm || depth > 0)
			return std::format("{:#x}", dart::Smi::Cast(obj).Value());
		return std::format("Smi: {:#x}", dart::Smi::Cast(obj).Value());
	case dart::kMintCid:
		if (simpleForm || depth > 0)
			return std::format("{:#x}", dart::Mint::Cast(obj).value());
		return std::format("Mint: {:#x}", dart::Mint::Cast(obj).value());
	case dart::kDoubleCid:
		if (simpleForm || depth > 0)
			return std::format("{}", dart::Double::Cast(obj).value());
		return std::format("Double: {}", dart::Double::Cast(obj).value());
	case dart::kBoolCid:
		return dart::Bool::Cast(obj).value() ? "true" : "false";
	case dart::kNullCid:
		return "Null";
	case dart::kSubtypeTestCacheCid:
		return "SubtypeTestCache";
	case dart::kFunctionCid: {
		// stub never be in Object Pool
		const auto& func = dart::Function::Cast(obj);
		const auto& code = dart::Code::Handle(func.CurrentCode());
		auto ep = code.EntryPoint() - app.base();
		auto fnBase = app.GetFunction(ep);
		if (!fnBase) {
			return std::format("Function({:#x})", ep);
		}
		auto dartFn = fnBase->AsFunction();
		if (dartFn && dartFn->IsClosure()) {
			auto parentFn = dartFn->GetOutermostFunction();
			if (parentFn) {
				return std::format("AnonymousClosure: ({:#x})", dartFn->Address());
			}
		}
		if (dartFn) {
			return std::format("Function: ({:#x})", dartFn->Address());
		}
		return std::format("Function({:#x})", ep);
	}
	case dart::kClosureCid: {
		// TODO: show owner
		const auto& closure = dart::Closure::Cast(obj);
		const auto& closureFn = dart::Function::Handle(closure.function());
		const auto& closureCode = dart::Code::Handle(closureFn.CurrentCode());
		const auto closureEp = closureCode.EntryPoint();
		if (!app.functions.contains(closureEp - app.base())) {
			std::cout << std::format("[!] missing closure at {:#x}\n", closureEp - app.base());
		}
		//RELEASE_ASSERT(app.functions.contains(closure.entry_point() - app.base()));
		return std::format("{} ({:#x})", closure.ToCString(), closureEp);
	}
	case dart::kCodeCid: {
		const auto& code = dart::Code::Cast(obj);
		const auto ep = code.EntryPoint() - app.base();
		if (app.stubs.contains(ep)) {
			const auto stub = app.stubs[ep];
			return std::format("Stub: {} ({:#x})", stub->Name().c_str(), ep);
		}
		return std::format("Code: {} ({:#x})", code.ToCString(), ep);
	}
	case dart::kImmutableArrayCid: {
		// Objects in Object Pool immutable, so only immutable array is used for array
		// Most of no type arguments in Object Pool are Argument Descriptor
		const auto& arr = dart::Array::Cast(obj);
		const auto arr_len = arr.Length();
		const auto typeArg = app.typeDb->FindOrAdd(arr.GetTypeArguments());
		// without type arguments, assume it is argument descriptor. show it even simple form is true.
		if (simpleForm && typeArg->Length() > 0)
			return std::format("List{}({})", typeArg->ToString(), arr_len);

		std::ostringstream ss;
		if (arr_len > 0) {
			// in ImmutableList here, only Dart type (native type is not used)
			auto arrPtr = dart::Array::DataOf(arr.raw());
			for (intptr_t i = 0; i < arr_len; i++) {
				if (i != 0)
					ss << ", ";

				if (arrPtr[i]->IsHeapObject()) {
					obj = arrPtr[i]; // No decompression in 2.7.2
					ss << ObjectToString(obj, simpleForm, nestedObj, depth + 1);
				}
				else {
					obj = dart::Smi::RawCast(arrPtr[i]);
					ss << std::hex << std::showbase << dart::Smi::Cast(obj).Value();
				}
			}
		}
		return std::format("List{}({}) [{}]", typeArg->ToString(), arr_len, ss.str());
	}
#ifdef HAS_RECORD_TYPE
	case dart::kRecordCid: {
		const auto& record = dart::Record::Cast(obj);
		std::ostringstream ss;
		const auto type = app.typeDb->FindOrAdd(record.GetRecordType());
		ss << "Record" << type->ToString() << " = (";
		auto& field = dart::Object::Handle();
		const auto num_fields = record.num_fields();
		for (intptr_t i = 0; i < num_fields; i++) {
			if (i != 0) ss << ", ";
			field = record.FieldAt(i);
			ss << ObjectToString(field, simpleForm, nestedObj, depth + 1);
		}
		ss << ")";
		return ss.str();
	}
#endif
	case dart::kTypeArgumentsCid:
		return "TypeArguments: " + app.typeDb->FindOrAdd(dart::TypeArguments::RawCast(obj.raw()))->ToString();
	case dart::kTypeCid:
		return "Type: " + app.typeDb->FindOrAdd(dart::Type::RawCast(obj.raw()))->ToString();
#ifdef HAS_RECORD_TYPE
	case dart::kRecordTypeCid:
		return "RecordType: " + app.typeDb->FindOrAdd(dart::RecordType::RawCast(obj.raw()))->ToString();
#endif
	case dart::kTypeParameterCid:
		return "TypeParameter: " + app.typeDb->FindOrAdd(dart::TypeParameter::RawCast(obj.raw()))->ToString();
	// In 2.7.2 kFunctionTypeCid == kTypeCid so no separate case needed
#ifdef HAS_TYPE_REF
	case dart::kTypeRefCid:
#endif
#if defined(kTypeParametersCid)
	case dart::kTypeParametersCid:
#endif
		// might be in a Type but not in Object Pool directly
		return std::format("{} (ptr: {:#x})", obj.ToCString(), (uint64_t)obj.raw());
	case dart::kFieldCid: {
		const auto& field = dart::Field::Cast(obj);
		return std::format("{} (offset: {:#x})", field.ToCString(), field.Offset());
	}
	case dart::kConstMapCid: {
		auto& map = dart::Map::Cast(obj);
		const auto typeArg = app.typeDb->FindOrAdd(map.GetTypeArguments());
		if (simpleForm)
			return std::format("Map{}({})", typeArg->ToString(), map.Length());

		std::ostringstream ss;
		std::string indent(depth * 2 + 2, ' ');
		ss << std::format("Map{}({}) {{\n", typeArg->ToString(), map.Length());
		dart::Map::Iterator iter(map);
		auto& key = dart::Object::Handle();
		auto& val = dart::Object::Handle();
		int cnt = 0;
		while (iter.MoveNext()) {
			if (cnt++) ss << ",\n";
			key = iter.CurrentKey();
			val = iter.CurrentValue();
			// key always be simple form
			ss << indent << ObjectToString(key, true, false, depth + 1) << ": " << ObjectToString(val, simpleForm, nestedObj, depth + 1);
		}
		if (cnt) ss << "\n";
		ss << std::string(depth * 2, ' ') << "}";
		return ss.str();
	}
#if defined(kConstSetCid)
	case dart::kConstSetCid: {
		auto& set = dart::Set::Cast(obj);
		const auto typeArg = app.typeDb->FindOrAdd(set.GetTypeArguments());
		if (simpleForm)
			return std::format("Set{}({})", typeArg->ToString(), set.Length());

		std::ostringstream ss;
		ss << std::format("Set{}({}) {{ ", typeArg->ToString(), set.Length());
		dart::Set::Iterator iter(set);
		auto& key = dart::Object::Handle();
		int cnt = 0;
		while (iter.MoveNext()) {
			if (cnt++)
				ss << ", ";
			key = iter.CurrentKey();
			ss << ObjectToString(key, simpleForm, nestedObj, depth + 1);
		}
		ss << " }";
		return ss.str();
	}
#endif
	case dart::kLibraryPrefixCid: {
		const auto& libPrefix = dart::LibraryPrefix::Cast(obj);
		const auto& name = dart::String::Handle(libPrefix.name());
		RELEASE_ASSERT(libPrefix.num_imports() == 1);
		// don't know what importer is
		//const auto& importer = dart::Library::Handle(libPrefix.importer());
		const auto& imports = dart::Array::Handle(libPrefix.imports());
		const auto& importObj = dart::Object::Handle(imports.At(0));
		RELEASE_ASSERT(importObj.GetClassId() == dart::kNamespaceCid);
		const auto& ns = dart::Namespace::Cast(importObj);
		const auto& lib = dart::Library::Handle(ns.library());
		const auto& libName = dart::String::Handle(lib.url());
		return std::format("LibraryPrefix: {}, target lib: {} ({})", name.ToCString(), libName.ToCString(), dart::Class::Handle(lib.toplevel_class()).id());
	}
	case dart::kInstanceCid:
		return std::format("Obj!Object@{:x}", (uint32_t)(intptr_t)obj.raw());
	// TODO: enum subclass
	}

	// many cids are instance. handling them after special classes.
	ASSERT(obj.IsInstance());

	if (cid < dart::kNumPredefinedCids) {
		return std::format("[internal {} cid={}]", app.GetClass(cid)->Name(), cid);
	}

	// TODO: print library and package prefix
	knownObjectPtrs.insert((intptr_t)obj.raw());
	return dumpInstance(obj, simpleForm, nestedObj, depth);
}

std::string DartDumper::dumpInstance(dart::Object& obj, bool simpleForm, bool nestedObj, int depth)
{
	auto cid = obj.GetClassId();
	if (cid >= (intptr_t)app.classes.size() || app.classes[cid] == nullptr) {
		return std::format("[unknown instance cid={}]", cid);
	}
	auto dartCls = app.classes[cid];

	std::string closeIndent(depth * 2, ' ');
	std::string indent(closeIndent.length() + 2, ' ');

	const auto ptr = dart::RawObject::ToAddr(obj.raw());
	DartType* dtype = app.typeDb->FindOrAdd(*dartCls, dart::Instance::Cast(obj));
	if (simpleForm || (!nestedObj && depth > 0)) {
		return std::format("Obj!{}@{:x}", dtype->ToString(), (uint32_t)(intptr_t)obj.raw());
	}

	std::vector<DartClass*> parents;
	auto superCls = dartCls->Parent();
	while (superCls && superCls->Id() != dart::kInstanceCid) {
		parents.push_back(superCls);
		superCls = superCls->Parent();
	}

	std::ostringstream ss;
	int fieldCnt = 0;
	ss << std::format("Obj!{}@{:x} : {{\n", dtype->ToString(), (uint32_t)(intptr_t)obj.raw());
	auto offset = dart::Instance::NextFieldOffset();
	for (auto parent : parents | std::views::reverse) {
		if (offset < parent->Size()) {
			// parent fields depth MUST increment by 2 because 1 is for "Super!..."
			auto txt = dumpInstanceFields(obj, *parent, ptr, offset, simpleForm, nestedObj, depth + 2);
			offset = parent->Size();
			if (!txt.empty()) {
				if (fieldCnt++)
					ss << ",\n";
				ss << indent << "Super!" << parent->FullName() << " : {\n";
				ss << txt << "\n";
				ss << indent << "}";
			}
		}
	}

	auto fieldTxt = dumpInstanceFields(obj, *dartCls, ptr, offset, simpleForm, nestedObj, depth + 1);
	if (!fieldTxt.empty()) {
		if (fieldCnt++)
			ss << ",\n";
		ss << fieldTxt;
	}
	if (fieldCnt)
		ss << "\n";
	ss << closeIndent << "}";

	return ss.str();
}

std::string DartDumper::dumpInstanceFields(dart::Object& obj, DartClass& dartCls, intptr_t ptr, intptr_t offset, bool simpleForm, bool nestedObj, int depth)
{
	std::stringstream ss;
	std::string indent(depth * 2, ' ');

	const auto bitmap = dartCls.UnboxedFieldsBitmap();
	while (offset < dartCls.Size()) {
		std::string txtField;
		// TODO: match the offset to field name if possible
		if (bitmap.At(offset / dart::kCompressedWordSize)) {
			// AOT uses native integer if it is less than 31 bits (compressed pointer)
			// integer (4/8 bytes) or double (8 bytes)
			if (dart::kCompressedWordSize == 4)
				RELEASE_ASSERT(bitmap.At((offset + dart::kCompressedWordSize) / dart::kCompressedWordSize));
			auto p = reinterpret_cast<uint64_t*>(ptr + offset);
			// it is rare to find integer that larger than 0x1000_0000_0000_0000
			if (*p <= 0x1000000000000000 || *p >= 0xffffffffffff0000) {
				txtField = std::format("off_{:x}: int({:#x})", offset, *p);
			}
			else {
				txtField = std::format("off_{:x}: double({})", offset, *((double*)p));
			}
			offset += dart::kCompressedWordSize;
		}
		else if (offset != dartCls.TypeArgumentsOffset()) {
			// object ptr (no compression in 2.7.2)
			auto p = reinterpret_cast<dart::RawObject**>(ptr + offset);
			auto objPtr2 = *p;
			if (objPtr2 != nullptr) {
				if (objPtr2->IsHeapObject()) {
					if (objPtr2->GetClassId() != dart::kNullCid) {
						obj = objPtr2;
						if (simpleForm || objPtr2->GetClassId() < dart::kNumPredefinedCids)
							txtField = std::format("off_{:x}: {}", offset, ObjectToString(obj, simpleForm, nestedObj, depth));
						else
							txtField = std::format("off_{:x}_{}", offset, ObjectToString(obj, simpleForm, nestedObj, depth));
					}
				}
				else {
					obj = dart::Smi::RawCast(objPtr2);
					txtField = std::format("off_{:x}_Smi: {:#x}", offset, dart::Smi::Cast(obj).Value());
				}
			}
		}
		offset += dart::kCompressedWordSize;

		if (!txtField.empty()) {
			if (ss.tellp() != 0)
				ss << ",\n";
			ss << indent << txtField;
		}
	}

	return ss.str();
}

std::string DartDumper::getPoolObjectDescription(intptr_t offset, bool simpleForm)
{
	const auto& pool = app.GetObjectPool();
	intptr_t idx = dart::ObjectPool::IndexFromOffset(offset);
	auto objType = pool.TypeAt(idx);
	// see how the EntryType is handled from vm/object_service.cc - ObjectPool::PrintJSONImpl()
	if (objType == dart::ObjectPool::EntryType::kTaggedObject) {
		auto& obj = dart::Object::Handle(pool.ObjectAt(idx));
		if (obj.IsUnlinkedCall()) {
			ASSERT(pool.TypeAt(idx + 1) == dart::ObjectPool::EntryType::kImmediate);
			const auto imm = pool.RawValueAt(idx + 1);
			auto dartFn = app.GetFunction(imm - app.base());
			return std::format("[pp+{:#x}] UnlinkedCall: {:#x} - {}", offset, dartFn->Address(), dartFn->FullName().c_str());
		}
		return std::format("[pp+{:#x}] {}", offset, ObjectToString(obj, simpleForm));
	}
	else if (objType == dart::ObjectPool::EntryType::kImmediate) {
		dart::uword imm = pool.RawValueAt(idx);
		if (imm <= 0x1000000000000000 || imm >= 0xffffffffffff0000) {
			return std::format("[pp+{:#x}] IMM: {:#x}", offset, imm);
		}
		else {
			return std::format("[pp+{:#x}] IMM: double({}) from {:#x}", offset, *((double*)&imm), imm);
		}
	}
	else if (objType == dart::ObjectPool::EntryType::kNativeFunction) {
		auto pc = pool.RawValueAt(idx);
		uintptr_t start = 0;
		char* name = dart::NativeSymbolResolver::LookupSymbolName(pc, &start);
		if (name != NULL) {
			auto txt = std::format("[pp+{:#x}] NativeFn: {} at {:#x}", offset, name, pc);
			dart::NativeSymbolResolver::FreeSymbolName(name);
			return txt;
		}
		else {
			return std::format("[pp+{:#x}] NativeFn: [no name] at {:#x}", offset, pc);
		}
	}
	else {
		throw std::runtime_error(std::format("unknown pool object type: {}", (int)objType).c_str());
	}
}

void DartDumper::DumpObjectPool(const char* filename)
{
	std::ofstream of(filename);
	const auto& pool = app.GetObjectPool();
	intptr_t num = pool.Length();

	const auto raw_addr = dart::RawObject::ToAddr(pool.raw());
	of << std::format("pool heap offset: {:#x}\n", raw_addr - app.heap_base());
	of << std::format("pool entries: {}\n", num);

	// Skip detailed object processing for 2.7.2 due to heap corruption issues
	of << "[Object pool dumping skipped for Dart 2.7.2 compatibility]\n";
}

void DartDumper::DumpObjects(const char* filename)
{
	std::ofstream of(filename);
	of << std::format("[Object dumping skipped for Dart 2.7.2 compatibility, {} objects]\n", knownObjectPtrs.size());
}