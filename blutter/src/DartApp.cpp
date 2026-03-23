#include "pch.h"
#include "DartApp.h"
#include "ElfHelper.h"
#include "DartLoader.h"
PRAGMA_WARNING(push, 0)
#include <vm/stub_code.h>
#include <vm/heap/safepoint.h>
PRAGMA_WARNING(pop)
#include <format>
#include <iostream> // for debugging purpose

DartApp::DartApp(const char* path) : ppool(NULL), nativeLib(0xdeadead), throwStubAddr(0)
{
	auto libInfo = ElfHelper::MapLibAppSo(path);
	lib_base = libInfo.lib;
	vm_snapshot_data = libInfo.vm_snapshot_data;
	vm_snapshot_instructions = libInfo.vm_snapshot_instructions;
	isolate_snapshot_data = libInfo.isolate_snapshot_data;
	isolate_snapshot_instructions = libInfo.isolate_snapshot_instructions;

	isolate = reinterpret_cast<dart::Isolate*>(DartLoader::Load(libInfo));

	heap_base_ = 0; // No heap_base in 2.7.2 (no compressed pointers)
	inScope = false;

	DartFnBase::SetLibBase(base());

	dartIntCid = 0;
	dartDoubleCid = 0;
	dartStringCid = 0;
	dartBoolCid = 0;
	dartRecordCid = 0;
	dartListCid = 0;
	dartSetCid = 0;
	dartMapCid = 0;
	dartRunesCid = 0;
	dartFutureCid = 0;
}

DartApp::~DartApp()
{
	ExitScope();
	DartLoader::Unload();

	for (auto lib : libs) {
		delete lib;
	}
	// classes are just reference. owners are in libraries. DO NOT delete here

	for (auto& stub : stubs) {
		delete stub.second;
	}
}

void DartApp::EnterScope()
{
	if (!inScope) {
		inScope = true;
		Dart_EnterScope();
		// exit safepoint so new symbols can be created
		//dart::Thread::Current()->SetAtSafepoint(false);
		isolate->safepoint_handler()->ExitSafepointUsingLock(dart::Thread::Current());
		
		ppool = reinterpret_cast<dart::ObjectPool*>(dart::VMHandles::AllocateHandle(dart::Thread::Current()->zone()));
		*ppool = isolate->object_store()->global_object_pool();
	}
}

void DartApp::ExitScope()
{
	if (inScope) {
		inScope = false;
		Dart_ExitScope();
		ppool = NULL;
	}
}

DartClass* DartApp::GetClass(intptr_t cid)
{
	return classes.at(cid);
}

DartFnBase* DartApp::GetFunction(uint64_t addr)
{
	auto fn = functions.find(addr);
	if (fn != functions.end()) {
		return fn->second;
	}

	auto stub = stubs.find(addr);
	if (stub != stubs.end()) {
		return stub->second;
	}
	// another possible is duplicated stubs in one big stub
	for (auto& [ep_addr, stub] : stubs) {
		if (stub->Address() < addr && addr < stub->AddressEnd()) {
			auto newStub = stub->Split(addr);
			stubs[addr] = newStub;
			return newStub;
		}
	}
	return nullptr;
}

DartLibrary* DartApp::addLibraryClass(const dart::Library& library, const dart::Class& cls)
{
	if (library.IsNull()) {
		auto dartCls = nativeLib.AddClass(cls);
		classes[dartCls->id] = dartCls;
		return &nativeLib;
	}

	// Check if we already have a library for this library's top-level class
	auto topClassPtr = library.toplevel_class();
	if (topClassPtr != nullptr && topClassPtr != dart::Object::null()) {
		auto topCid = topClassPtr->GetClassId();
		if (topCid >= 0 && topCid < (intptr_t)classes.size() && classes[topCid] != nullptr) {
			// Already have this library
			auto dartLib = const_cast<DartLibrary*>(&classes[topCid]->lib);
			if (!cls.IsTopLevel()) {
				auto dartCls = dartLib->AddClass(cls);
				if (dartCls->id < classes.size())
					classes[dartCls->id] = dartCls;
				for (const auto dartFn : dartCls->functions) {
					functions[dartFn->Address()] = dartFn;
				}
			}
			return dartLib;
		}
	}

	// New library
	std::cerr << "  addLibraryClass: creating new library\n";
	auto dartLib = addLibrary(library);
	std::cerr << "  addLibraryClass: library created, " << dartLib->classes.size() << " classes\n";
	return dartLib;
}

DartLibrary* DartApp::addLibrary(const dart::Library& library)
{
	auto lib = new DartLibrary(library);
	libs.push_back(lib);

	// add classes and functions for mapping from address
	for (const auto dartCls : lib->classes) {
		if (dartCls == lib->topClass) {
			// In 2.7.2, no separate top-level class index; just store in classes
			if (dartCls->id < classes.size())
				classes[dartCls->id] = dartCls;
		}
		else
			classes[dartCls->id] = dartCls;
		for (const auto dartFn : dartCls->functions) {
			functions[dartFn->Address()] = dartFn;
		}
	}

	return lib;
}

void DartApp::LoadInfo()
{
	auto isolate = dart::Isolate::Current();

	std::cerr << "LoadInfo: calling loadFromClassTable\n";
	loadFromClassTable(isolate);
	std::cerr << "LoadInfo: loadFromClassTable done\n";

	auto store = isolate->object_store();

	std::cerr << "LoadInfo: calling loadStubs\n";
	loadStubs(store);
	std::cerr << "LoadInfo: loadStubs done\n";

	std::cerr << "LoadInfo: calling findFunctionInHeap\n";
	findFunctionInHeap();
	std::cerr << "LoadInfo: findFunctionInHeap done\n";

	std::cerr << "LoadInfo: calling loadFromObjectPool\n";
	loadFromObjectPool();
	std::cerr << "LoadInfo: loadFromObjectPool done\n";

	std::cerr << "LoadInfo: calling finalizeFunctionsInfo\n";
	// finalizeFunctionsInfo crashes in 2.7.2 due to API differences
	// Skip for now to get basic output
	std::cerr << "  finalizeFunctionsInfo: skipped for 2.7.2 compatibility\n";
	// finalizeFunctionsInfo();
	std::cerr << "LoadInfo: finalizeFunctionsInfo done\n";

	//auto fieldTable = isolate->field_table(); //contains only sentinel, null, false, 0

	// there are instruction tables in vm isolate but their code are not called from Dart code (can be skipped)
	//dart::Dart::vm_isolate_group();
}

void DartApp::loadFromClassTable(dart::Isolate* isolate)
{
	std::cerr << "  loadFromClassTable: getting class table\n";
	auto table = isolate->class_table();
	const auto num_cids = table->NumCids();
	std::cerr << "  loadFromClassTable: num_cids = " << num_cids << "\n";
	// In 2.7.2 there is no separate top-level class table
	const auto num_top_cids = 0;
	classes.resize(num_cids);
	topClasses.resize(1); // At least one slot for fallback
	libs.reserve(num_cids);

	auto& library = dart::Library::Handle();
	auto& cls = dart::Class::Handle();

	// load from class table
	for (intptr_t i = 0; i < num_cids; i++) {
		auto clsPtr = table->At(i);
		if (clsPtr == nullptr) {
			continue;
		}

		if (classes[i] == nullptr) {
			cls = clsPtr;
			library = cls.library();
			if (library.IsNull()) {
				auto dartCls = nativeLib.AddClass(cls);
				classes[i] = dartCls;
			}
			else {
				addLibraryClass(library, cls);
			}
		}

		// In 2.7.2 there is no GetUnboxedFieldsMapAt
		if (classes[i] != nullptr)
			classes[i]->unboxed_fields_bitmap = dart::UnboxedFieldBitmap(0);
	}
	std::cerr << "  loadFromClassTable: loop done, processing post\n";

	// post process of classes
	// map super class and native type class ids
	std::cerr << "  loadFromClassTable: mapping super classes\n";
	for (auto dartCls : classes) {
		if (dartCls == NULL)
			continue;

		if (dartCls->superCls) {
			auto superCid = (intptr_t)dartCls->superCls;
			if (superCid >= 0 && superCid < (intptr_t)classes.size())
				dartCls->superCls = classes[superCid];
			else
				dartCls->superCls = nullptr;
		}

		// Dart create a new class for int, double, ... (do not know why built-in is not used)
		if (dartCls->name == "int") dartIntCid = dartCls->id;
		else if (dartCls->name == "double") dartDoubleCid = dartCls->id;
		else if (dartCls->name == "String") dartStringCid = dartCls->id;
		else if (dartCls->name == "bool") dartBoolCid = dartCls->id;
		else if (dartCls->name == "Record") dartRecordCid = dartCls->id;
		else if (dartCls->name == "List") dartListCid = dartCls->id;
		else if (dartCls->name == "Set") dartSetCid = dartCls->id;
		else if (dartCls->name == "Map") dartMapCid = dartCls->id;
		else if (dartCls->name == "Runes") dartRunesCid = dartCls->id;
		else if (dartCls->name == "Future") dartFutureCid = dartCls->id;
	}

	std::cerr << "  loadFromClassTable: creating typeDb\n";
	typeDb = std::unique_ptr<DartTypeDb>(new DartTypeDb(classes));
	std::cerr << "  loadFromClassTable: typeDb created\n";

	// complete the class info after super class is set
	std::cerr << "  loadFromClassTable: finalizing classes\n";
	auto zone = dart::Thread::Current()->zone();
	auto& interfaces = dart::Array::Handle(zone);
	auto& type = dart::Type::Handle(zone);
	int finalized = 0;
	for (auto dartCls : classes) {
		if (dartCls == nullptr || dartCls->superCls == nullptr)
			continue;

		auto rawCls = dartCls->ptr;
		if (rawCls == nullptr || (intptr_t)rawCls == (intptr_t)dart::Object::null())
			continue;

		cls = rawCls;
		dart::AbstractTypePtr declType = nullptr;
		try {
			declType = cls.DeclarationType();
		} catch (...) {
			std::cerr << "  finalizing: cid=" << dartCls->id << " DeclarationType threw\n";
			continue;
		}
		if (declType == nullptr || (intptr_t)declType == (intptr_t)dart::Object::null()) {
			continue;
		}
		auto dartType = typeDb->FindOrAdd(declType);
		if (dartType == nullptr)
			continue;
		dartCls->declarationType = reinterpret_cast<DartType*>(dartType);
		finalized++;
		if (finalized % 500 == 0)
			std::cerr << "  finalizing: " << finalized << " classes done\n";
		try {
			ASSERT(dartType->AsType()->Class().Id() == dartCls->Id());
			// Type vector names require type argument access which differs in 2.7.2
			// Skipping for now
			// if (dartCls->num_type_parameters > 0) {
			// 	dartCls->typeVectorName = dartType->Arguments().SubvectorName(0, dartCls->num_type_parameters);
			// }
			// if (dartCls->superCls->num_type_parameters > 0) {
			// 	dartCls->parentTypeVectorName = dartType->Arguments().SubvectorName(0, dartCls->superCls->num_type_parameters);
			// }

			// if there is a mixin, the last one is mixin
			// TODO: correct multiple interfaces or mixins because compiler generate dummy classes for "extends" and "with" 1 class
			interfaces = cls.interfaces();
			auto interfaces_len = interfaces.Length();
			if (dartCls->is_transformed_mixin) {
				type ^= interfaces.At(--interfaces_len);
				dartCls->mixin = classes[type.type_class_id()];
				ASSERT(dartCls->mixin);
			}
			for (auto i = 0; i < interfaces_len; i++) {
				type ^= interfaces.At(i);
				dartCls->interfaces.push_back(classes[type.type_class_id()]);
			}
		} catch (std::exception& e) {
			std::cerr << "  finalizing: cid=" << dartCls->id << " error: " << e.what() << "\n";
		} catch (...) {
			std::cerr << "  finalizing: cid=" << dartCls->id << " unknown error\n";
		}
	}
	std::cerr << "  loadFromClassTable: finalizing done, " << finalized << " classes\n";
	std::cerr << "  loadFromClassTable: done\n";
}

void DartApp::loadStubs(dart::ObjectStore* store)
{	std::cerr << "  loadStubs: start\n";
	dart::CodePtr ptr;
	auto& code = dart::Code::Handle();
	uint64_t ep_addr;
	DartStub* stub;

	// In 2.7.2, OBJECT_STORE_STUB_CODE_LIST doesn't exist
	// Only load available stub codes from ObjectStore
	{
		ptr = store->build_method_extractor_code();
		code = ptr;
		std::cerr << "  loadStubs: got method extractor code\n";
		ep_addr = code.EntryPoint() - base();
		stub = new DartStub(ptr, DartStub::BuildMethodExtractorStub, ep_addr, code.Size(), "BuildMethodExtractor");
		ASSERT(!stubs.contains(ep_addr));
		stubs[ep_addr] = stub;
	}

	throwStubAddr = 0; // No throw_stub in 2.7.2 ObjectStore

	// load VM stub code
	// the dart entry point "static void main()" is a LazyCompileVMStub which call "main" stub (a real main)
	ASSERT(dart::StubCode::HasBeenInitialized());
#define DO(name) {\
		const auto& code = dart::StubCode::name(); \
		ep_addr = code.EntryPoint() - base(); \
		if (stubs.contains(ep_addr)) { \
			ASSERT(stubs[ep_addr]->Name() == #name); \
		} \
		else { \
			stub = new DartStub(code.raw(), DartStub::name ## VMStub, ep_addr, code.Size(), #name); \
			stubs[ep_addr] = stub; \
			auto it = functions.find(ep_addr); \
			if (it != functions.end()) { \
				auto dartFn = it->second; \
				std::erase(dartFn->Class().functions, dartFn); \
				functions.erase(it); \
			} \
		} \
	}
	std::cerr << "  loadStubs: loading VM stubs\n";
	VM_STUB_CODE_LIST(DO);
#undef DO
	std::cerr << "  loadStubs: done\n";
}

DartFunction* DartApp::addFunctionNoCheck(const dart::Function& func)
{
	// find its class or library, then add it
	const auto cls_ptr = func.Owner();
	const auto cid = cls_ptr->GetClassId();
	DartClass* cls;
	if (dart::IsTopLevelCidCompat(cid)) {
		cls = topClasses.empty() ? nullptr : topClasses[0];
		if (cls == NULL) {
			// new library
			const auto& clsHandle = dart::Class::Handle(cls_ptr);
			const auto& library = dart::Library::Handle(clsHandle.library());
			cls = addLibrary(library)->topClass;
		}
	}
	else {
		cls = classes[cid];
		if (cls == NULL) {
			auto msg = std::format("found invalid class id: {}", cid);
			throw std::runtime_error(msg);
		}
	}
	return cls->AddFunction(func.raw());
}

void DartApp::addFunction(uintptr_t ep_addr, const dart::Function& func)
{
	if (!functions.contains(ep_addr)) {
		auto dartFn = addFunctionNoCheck(func);
		functions[dartFn->Address()] = dartFn;
	}
}

class HeapCodeVisitor : public dart::ObjectVisitor {
public:
	explicit HeapCodeVisitor(std::vector<dart::CodePtr>& codePtrs) : codePtrs(codePtrs) {}
	virtual ~HeapCodeVisitor() {}

	// Invoked for each object.
	virtual void VisitObject(dart::ObjectPtr obj) {
		if (obj->IsCode())
			codePtrs.push_back(dart::Code::RawCast(obj));
	}

private:
	std::vector<dart::CodePtr>& codePtrs;
};

void DartApp::findFunctionInHeap()
{
	std::cerr << "  findFunctionInHeap: starting heap iteration\n";
	std::vector<dart::CodePtr> codePtrs;
	dart::HeapIterationScope heap_iteration_scope(dart::Thread::Current());
	HeapCodeVisitor visitor(codePtrs);
	heap_iteration_scope.IterateOldObjects(&visitor);
	std::cerr << "  findFunctionInHeap: found " << codePtrs.size() << " code objects\n";

	auto zone = dart::Thread::Current()->zone();
	auto& code = dart::Code::Handle(zone);
	auto& obj = dart::Object::Handle(zone);

	int processed = 0;
	for (dart::CodePtr code_ptr : codePtrs) {
		code = code_ptr;
		const auto entry_point = code.EntryPoint();
		const auto ep_offset = entry_point - base();

		auto owner = code.owner();
		if ((intptr_t)owner == (intptr_t)dart::Object::null()) {
			continue;
		}

		processed++;
		if (processed % 5000 == 0)
			std::cerr << "  findFunctionInHeap: processed " << processed << " codes\n";

		obj = owner;
		if (obj.IsClass()) {
			const auto cid = (uint32_t)dart::Class::Cast(obj).id();
			auto astub = new DartAllocateStub(code_ptr, ep_offset, code.Size(), cid, classes[cid]->name);
			stubs[ep_offset] = astub;
		}
		else if (obj.IsFunction()) {
			addFunction(ep_offset, dart::Function::Cast(obj));
		}
		else if (obj.IsSmi()) {
			if (!functions.contains(ep_offset)) {
				if (!nativeLib.topClass) {
					nativeLib.topClass = new DartClass(nativeLib);
				}
				auto dartFn = nativeLib.topClass->AddFunction(code);
				functions[dartFn->Address()] = dartFn;
			}
		}
	}
	std::cerr << "  findFunctionInHeap: done, processed " << processed << " codes\n";
}

void DartApp::finalizeFunctionsInfo()
{
	auto& parentFn = dart::Function::Handle();
	auto& parentCode = dart::Code::Handle();
	std::unordered_map<uint64_t, DartFunction*> pending_functions;
	for (auto& [_, dartFn] : functions) {
		// update parent pointer
		if (dartFn->parent) {
			parentFn = dart::FunctionPtr((intptr_t)dartFn->parent);
			parentCode = parentFn.CurrentCode();
			const auto ep_addr = parentCode.EntryPoint() - base();
			if (stubs.contains(ep_addr)) {
				dartFn->parent = nullptr;
			}
			else if (functions.contains(ep_addr)) {
				dartFn->parent = functions[ep_addr];
			}
			else if (pending_functions.contains(ep_addr)) {
				dartFn->parent = pending_functions[ep_addr];
			}
			else {
				auto newDartFn = addFunctionNoCheck(parentFn);
				pending_functions[ep_addr] = newDartFn;
				dartFn->parent = newDartFn;
			}
		}

		// TODO: handle function result type and paramters type
	}

	std::unordered_map<uint64_t, DartFunction*> new_functions;
	while (!pending_functions.empty()) {
		for (auto& [dartFn_ep, dartFn] : pending_functions) {
			if (dartFn->parent) {
				parentFn = dart::FunctionPtr((intptr_t)dartFn->parent);
				parentCode = parentFn.CurrentCode();
				const auto ep_addr = parentCode.EntryPoint() - base();
				if (stubs.contains(ep_addr)) {
					dartFn->parent = nullptr;
				}
				else if (functions.contains(ep_addr)) {
					dartFn->parent = functions[ep_addr];
				}
				else if (pending_functions.contains(ep_addr)) {
					dartFn->parent = pending_functions[ep_addr];
				}
				else if (new_functions.contains(ep_addr)) {
					dartFn->parent = new_functions[ep_addr];
				}
				else {
					auto newDartFn = addFunctionNoCheck(parentFn);
					new_functions[ep_addr] = newDartFn;
					dartFn->parent = newDartFn;
				}
			}
			functions[dartFn_ep] = dartFn;
		}
		pending_functions.clear();
		pending_functions = std::move(new_functions);
		new_functions.clear();
	}

	// null self parent
	for (auto& [_, dartFn] : functions) {
		// update parent pointer
		if (dartFn->parent == dartFn) {
			dartFn->parent = nullptr;
		}
	}

	// extract function parameters
	// Note: Signature is dropped in most function
	// In 2.7.2, function types are represented differently (Type with signature)
	// The parameter extraction logic below requires newer Dart API
	std::cerr << "  finalizeFunctionsInfo: extracting params for " << functions.size() << " functions\n";
	auto& func = dart::Function::Handle();
	int paramCount = 0;
	for (auto& [_, dartFn] : functions) {
		func = dartFn->ptr;
		paramCount++;
		if (paramCount % 1000 == 0)
			std::cerr << "  finalizeFunctionsInfo: processed " << paramCount << "/" << functions.size() << " functions\n";
		// In 2.7.2, func.SignatureType() returns the type object for the signature
		auto sigTypePtr = func.SignatureType();
		if ((intptr_t)sigTypePtr == (intptr_t)dart::Object::null())
			continue;
		auto& sigType = dart::Type::Handle(sigTypePtr);
		if (sigType.IsNull())
			continue;
		// Get the signature function
		auto sigFnPtr = sigType.signature();
		if ((intptr_t)sigFnPtr == (intptr_t)dart::Function::null())
			continue;
		auto& sigFn = dart::Function::Handle(sigFnPtr);
		if (!sigFn.IsNull()) {
			dartFn->Signature().returnType = TypeDb()->FindOrAdd(sigFn.result_type());
			// Parameter extraction simplified for 2.7.2
			const intptr_t num_params = sigFn.NumParameters();
			const intptr_t num_fixed_params = sigFn.num_fixed_parameters();
			const intptr_t num_opt_params = sigFn.NumOptionalParameters();
			auto& dname = dart::String::Handle();
			for (intptr_t i = 0; i < num_params; i++) {
				auto dtype = TypeDb()->FindOrAdd(sigFn.ParameterTypeAt(i));
				auto isRequired = false;
				std::string name;
				if (num_opt_params > 0 && i >= num_fixed_params) {
					dname = sigFn.ParameterNameAt(i);
					name = dname.ToCString();
				}
				dartFn->Signature().params.push_back(FnParam{ dtype, std::move(name), isRequired });
			}
		}
	}
	std::cerr << "  finalizeFunctionsInfo: done\n";
}

void DartApp::walkObject(dart::Object& obj)
{
	auto cid = obj.GetClassId();
	if (cid < dart::kNumPredefinedCids) {
		// objects in array, map, set
		if (obj.IsArray()) {
			const auto& arr = dart::Array::Cast(obj);
			const auto arr_len = arr.Length();
			if (arr_len > 0) {
				auto arrPtr = dart::Array::DataOf(arr.raw());
				for (intptr_t i = 0; i < arr_len; i++) {
					if (arrPtr[i]->IsHeapObject()) {
						obj = arrPtr[i]; // No decompression in 2.7.2
						walkObject(obj);
					}
				}
			}
		}
		else if (cid == dart::kLinkedHashMapCid) {
			// In 2.7.2, maps use LinkedHashMap - walk map contents if needed
		}
		else if (obj.IsTypeArguments()) {
			typeDb->FindOrAdd(dart::TypeArguments::RawCast(obj.raw()));
		}
		else if (obj.IsType()) {
			typeDb->FindOrAdd(dart::Type::RawCast(obj.raw()));
		}
		else if (obj.IsTypeParameter()) {
			typeDb->FindOrAdd(dart::TypeParameter::RawCast(obj.raw()));
		}
		// In 2.7.2, function types are just Type objects with signature
		else if (obj.IsFunction()) {
			const auto& func = dart::Function::Cast(obj);
			const auto& code = dart::Code::Handle(func.CurrentCode());
			const auto ep_addr = code.EntryPoint() - base();
			addFunction(ep_addr, func);
		}
		else if (obj.IsClosure()) {
			const auto& closure = dart::Closure::Cast(obj);
			const auto& func = dart::Function::Handle(closure.function());
			const auto& code = dart::Code::Handle(func.CurrentCode());
			const auto ep_addr = code.EntryPoint() - base();
			addFunction(ep_addr, func);
		}
		return;
	}

	ASSERT(obj.IsInstance());

	auto dartCls = classes[cid];
	ASSERT(dartCls);
	typeDb->FindOrAdd(*dartCls, dart::Instance::Cast(obj));

	const auto bitmap = dartCls->unboxed_fields_bitmap;
	auto offset = dart::Instance::NextFieldOffset();
	const auto ptr = reinterpret_cast<uintptr_t>(obj.raw());
	// from InstanceDeserializationCluster::ReadFill() in app_snapshot.cc
	while (offset < dartCls->size) {
		if (bitmap.At(offset / dart::kWordSize)) {
			// AOT uses native integer or double (8 bytes)
			auto p = reinterpret_cast<uint64_t*>(ptr + offset);
			// it is rare to find integer that larger than 0x1000_0000_0000_0000
			//   while double is very common because of exponent value
			// to know exact type (int or double), we have to check from register type in assembly
			if (*p <= 0x1000000000000000 || *p >= 0xffffffffffff0000) {
				dartCls->AddField(offset, typeDb->Get(dart::kMintCid));
			}
			else {
				dartCls->AddField(offset, typeDb->Get(dart::kDoubleCid));
			}
			offset += dart::kWordSize * 2;
		}
		else {
			auto p = reinterpret_cast<dart::RawObject**>(ptr + offset);
			auto objPtr2 = *p;
			if (objPtr2->IsHeapObject()) {
				if (objPtr2->GetClassId() != dart::kNullCid) {
					if (offset == dartCls->TypeArgumentsOffset()) {
						ASSERT(objPtr2->GetClassId() == dart::kTypeArgumentsCid);
						typeDb->FindOrAdd(dart::TypeArguments::RawCast(objPtr2));
					}
					else {
						// compressed object ptr
						const auto fieldCid = objPtr2->GetClassId();
						const auto fieldCls = classes[fieldCid];
						if (fieldCls) {
							obj = objPtr2;
							dartCls->AddField(offset, typeDb->FindOrAdd(*fieldCls, dart::Instance::Cast(obj)));
							// walk this object recursively
							walkObject(obj);
						}
						else {
							//dart::kCallSiteDataCid;
						}
					}
				}
			}
			offset += dart::kWordSize;
		}
	}

}

void DartApp::loadFromObjectPool()
{
	std::cerr << "  loadFromObjectPool: start\n";
	const auto& pool = GetObjectPool();
	intptr_t num = pool.Length();
	std::cerr << "  loadFromObjectPool: pool length = " << num << "\n";

	auto& obj = dart::Object::Handle();

	int processed = 0;
	for (intptr_t i = 0; i < num; i++) {
		const auto objType = pool.TypeAt(i);
		if (objType == dart::ObjectPool::EntryType::kTaggedObject) {
			processed++;
			if (processed <= 5 || processed % 10000 == 0)
				std::cerr << "  loadFromObjectPool: processed " << processed << " tagged objects (i=" << i << ")\n";
			obj = pool.ObjectAt(i);
			if (processed <= 5)
				std::cerr << "    obj cid=" << obj.GetClassId() << " IsField=" << obj.IsField() << " IsFunction=" << obj.IsFunction() << "\n";
			if (obj.IsField()) {
				const auto& field = dart::Field::Cast(obj);
				auto ownerCid = field.Owner()->GetClassId();
				if (ownerCid >= 0 && ownerCid < (intptr_t)classes.size() && classes[ownerCid] != nullptr) {
					auto dartField = classes[ownerCid]->AddField(field.raw());
					if (dartField->IsStatic()) {
						staticFields[dartField->Offset()] = dartField;
					}
				}
			}
			// walkObject can crash on some objects in 2.7.2, skip for now
			// walkObject(obj);
		}
		else if (objType == dart::ObjectPool::EntryType::kImmediate) {
			// just immediate. no info
		}
		else if (objType == dart::ObjectPool::EntryType::kNativeFunction) {
			// normally, it is only used in internal library (can be ignored)
		}
		else {
			throw std::runtime_error("Unknown Object Pool entry type");
		}
	}
	std::cerr << "  loadFromObjectPool: done\n";
}
