#ifndef BLUTTER_COMPAT_DART27_H_
#define BLUTTER_COMPAT_DART27_H_

#include "vm/object.h"
#include "vm/raw_object.h"
#include "vm/class_table.h"

#if !defined(DART_PRECOMPILED_RUNTIME)
#define DART_PRECOMPILED_RUNTIME 1
#endif

namespace dart {

#if !defined(TAGGED_POINTER_H_PRESENT)
#define TAGGED_POINTER_H_PRESENT 1

using RawCompressed = RawObject*;

template <class T>
class CompressedPointer {
 public:
  CompressedPointer() : value_(0) {}
  explicit CompressedPointer(RawObject* raw) : value_(reinterpret_cast<intptr_t>(raw)) {}
  RawObject* Decompress(intptr_t base) const { return reinterpret_cast<RawObject*>(value_); }
  RawObject* ptr() const { return reinterpret_cast<RawObject*>(value_); }
 private:
  intptr_t value_;
};

template <class T>
class UntaggedPointer {
 public:
  UntaggedPointer() : value_(0) {}
  explicit UntaggedPointer(RawObject* raw) : value_(reinterpret_cast<intptr_t>(raw)) {}
  RawObject* Decompress(intptr_t base) const { return reinterpret_cast<RawObject*>(value_); }
  RawObject* ptr() const { return reinterpret_cast<RawObject*>(value_); }
 private:
  intptr_t value_;
};

#endif

// Pointer type aliases for newer Dart API
#if !defined(CodePtr)
using CodePtr = RawCode*;
#endif
#if !defined(FunctionPtr)
using FunctionPtr = RawFunction*;
#endif
#if !defined(FieldPtr)
using FieldPtr = RawField*;
#endif
#if !defined(TypePtr)
using TypePtr = RawType*;
#endif
#if !defined(ObjectPtr)
using ObjectPtr = RawObject*;
#endif
#if !defined(ClassPtr)
using ClassPtr = RawClass*;
#endif
#if !defined(LibraryPtr)
using LibraryPtr = RawLibrary*;
#endif
#if !defined(TypeArgumentsPtr)
using TypeArgumentsPtr = RawTypeArguments*;
#endif
#if !defined(AbstractTypePtr)
using AbstractTypePtr = RawAbstractType*;
#endif
#if !defined(TypeParameterPtr)
using TypeParameterPtr = RawTypeParameter*;
#endif
#if !defined(FunctionTypePtr)
using FunctionTypePtr = RawObject*;
#endif
#if !defined(ArrayPtr)
using ArrayPtr = RawArray*;
#endif
#if !defined(RecordTypePtr)
using RecordTypePtr = RawObject*;
#endif

// UnboxedFieldBitmap shim
class UnboxedFieldBitmap {
 public:
  UnboxedFieldBitmap() : value_(0) {}
  explicit UnboxedFieldBitmap(uint64_t val) : value_(val) {}
  uint64_t Value() const { return value_; }
  bool At(intptr_t idx) const { return (value_ >> idx) & 1; }
 private:
  uint64_t value_;
};

// In 2.7.2 there is no ClassTable::IsTopLevelCid; provide a free function.
// Top-level classes in 2.7.2 cannot be identified by cid alone.
inline bool IsTopLevelCidCompat(intptr_t cid) { return false; }

// HEAP_BITS doesn't exist in 2.7.2 (no compressed pointers)
// Use BARRIER_MASK as a substitute (same register R28)
const Register HEAP_BITS = BARRIER_MASK;

// Missing class id constants in 2.7.2
// Function types are just Type objects with a non-null signature() in 2.7.2
#if !defined(kFunctionTypeCid)
static const intptr_t kFunctionTypeCid = kTypeCid;
#endif
// Sentinel objects don't have a dedicated cid in 2.7.2; use kIllegalCid as fallback
#if !defined(kSentinelCid)
static const intptr_t kSentinelCid = kIllegalCid;
#endif

// kCompressedWordSize doesn't exist (no compressed pointers in 2.7.2)
#if !defined(kCompressedWordSize)
static const intptr_t kCompressedWordSize = kWordSize;
#endif
// kCompressedWordSizeLog2 doesn't exist in 2.7.2 (no compressed pointers)
#if !defined(kCompressedWordSizeLog2)
static const intptr_t kCompressedWordSizeLog2 = kWordSizeLog2;
#endif

// TypeParameters class doesn't exist in 2.7.2; function type params use different API
// Provide a minimal stub so compilation succeeds
class TypeParametersStub {
 public:
  TypeParametersStub() : raw_(nullptr) {}
  explicit TypeParametersStub(RawObject* raw) : raw_(raw) {}
  bool IsNull() const { return raw_ == nullptr; }
  intptr_t Length() const { return 0; }
  RawAbstractType* BoundAt(intptr_t i) const { return nullptr; }
 private:
  RawObject* raw_;
};
using TypeParameters = TypeParametersStub;

// FunctionType stub: in 2.7.2 function types are represented as Type with signature()
// We provide a minimal stub so FindOrAdd compiles
class FunctionTypeStub {
 public:
  FunctionTypeStub() : type_(Type::Handle()) {}
  explicit FunctionTypeStub(const Type& type) : type_(type) {}
  explicit FunctionTypeStub(RawObject* raw) : type_(Type::Handle()) {}
  static FunctionTypeStub* RawCast(RawObject* raw) { return new FunctionTypeStub(raw); }
  bool IsNullable() const { return type_.IsNull(); }
  intptr_t NumTypeParameters() const { return 0; }
  intptr_t NumParentTypeArguments() const { return 0; }
  RawObject* type_parameters() const { return Object::null(); }
  intptr_t num_implicit_parameters() const { return 0; }
  bool HasOptionalNamedParameters() const { return false; }
  RawAbstractType* result_type() const { return Type::DynamicType(); }
  intptr_t num_fixed_parameters() const { return 0; }
  intptr_t NumOptionalParameters() const { return 0; }
  RawAbstractType* ParameterTypeAt(intptr_t i) const { return Type::DynamicType(); }
  RawString* ParameterNameAt(intptr_t i) const { return String::null(); }
 private:
  const Type& type_;
};
using FunctionType = FunctionTypeStub;

}  // namespace dart

// AOT_* prefix constants don't exist in 2.7.2 - map to non-AOT versions
// Thread offsets
#if !defined(AOT_Thread_stack_limit_offset)
#define AOT_Thread_stack_limit_offset dart::Thread::stack_limit_offset()
#endif

// Thread::field_table_values_offset() doesn't exist in 2.7.2
// Use a placeholder value
namespace dart {
inline intptr_t Thread_field_table_values_offset_compat() { return 0x88; }
}
#if !defined(AOT_Thread_field_table_values_offset)
#define AOT_Thread_field_table_values_offset dart::Thread_field_table_values_offset_compat()
#endif
// Double value
#if !defined(AOT_Double_value_offset)
#define AOT_Double_value_offset dart::Double::value_offset()
#endif
// ArgumentsDescriptor offsets
#if !defined(AOT_ArgumentsDescriptor_first_named_entry_offset)
#define AOT_ArgumentsDescriptor_first_named_entry_offset dart::ArgumentsDescriptor::first_named_entry_offset()
#endif
#if !defined(AOT_ArgumentsDescriptor_named_entry_size)
#define AOT_ArgumentsDescriptor_named_entry_size dart::ArgumentsDescriptor::named_entry_size()
#endif
#if !defined(AOT_ArgumentsDescriptor_name_offset)
#define AOT_ArgumentsDescriptor_name_offset dart::ArgumentsDescriptor::name_offset()
#endif
#if !defined(AOT_ArgumentsDescriptor_position_offset)
#define AOT_ArgumentsDescriptor_position_offset dart::ArgumentsDescriptor::position_offset()
#endif
#if !defined(AOT_ArgumentsDescriptor_type_args_len_offset)
#define AOT_ArgumentsDescriptor_type_args_len_offset dart::ArgumentsDescriptor::type_args_len_offset()
#endif
#if !defined(AOT_ArgumentsDescriptor_size_offset)
#define AOT_ArgumentsDescriptor_size_offset dart::ArgumentsDescriptor::count_offset()
#endif
#if !defined(AOT_ArgumentsDescriptor_count_offset)
#define AOT_ArgumentsDescriptor_count_offset dart::ArgumentsDescriptor::count_offset()
#endif
// Closure offsets
#if !defined(AOT_Closure_context_offset)
#define AOT_Closure_context_offset dart::Closure::context_offset()
#endif
#if !defined(AOT_Closure_delayed_type_arguments_offset)
#define AOT_Closure_delayed_type_arguments_offset dart::Closure::delayed_type_arguments_offset()
#endif
// AbstractType type_test_stub_entry_point
#if !defined(AOT_AbstractType_type_test_stub_entry_point_offset)
#define AOT_AbstractType_type_test_stub_entry_point_offset dart::AbstractType::type_test_stub_entry_point_offset()
#endif
// Code entry_point - in 2.7.2 it's a function, not an array
#if !defined(AOT_Code_entry_point_offset)
// Provide array-like access since the analyzer uses AOT_Code_entry_point_offset[kind]
namespace dart {
  struct CompatCodeEntryPoint {
    intptr_t operator[](int kind) const {
      return dart::Code::entry_point_offset(static_cast<dart::CodeEntryKind>(kind));
    }
  };
}
#define AOT_Code_entry_point_offset dart::CompatCodeEntryPoint{}
#endif
// Thread write barrier offsets - used as array in analyzer
#if !defined(AOT_Thread_array_write_barrier_entry_point_offset)
namespace dart {
  struct CompatWriteBarrierOffset {
    intptr_t value;
    const intptr_t* begin() const { return &value; }
    const intptr_t* end() const { return &value + 1; }
    bool operator==(int32_t other) const { return value == other; }
    bool operator!=(int32_t other) const { return value != other; }
  };
}
#define AOT_Thread_array_write_barrier_entry_point_offset dart::CompatWriteBarrierOffset{0x100}
#endif
#if !defined(AOT_Thread_write_barrier_wrappers_thread_offset)
#define AOT_Thread_write_barrier_wrappers_thread_offset dart::CompatWriteBarrierOffset{0x108}
#endif

// UntaggedObject doesn't exist in 2.7.2 - use RawObject
namespace dart {
  using UntaggedObject = RawObject;
  using UntaggedTypedData = RawTypedData;
}

// Missing ABI classes in 2.7.2
// Provide stubs for code analysis compatibility - register values are ARM64 capstone register numbers
#include <capstone/capstone.h>
namespace dart {
struct TypeTestABI {
  static constexpr arm64_reg kInstanceReg = ARM64_REG_X0;
  static constexpr arm64_reg kDstTypeReg = ARM64_REG_X1;
  static constexpr arm64_reg kSubtypeTestCacheReg = ARM64_REG_X2;
  static constexpr arm64_reg kFunctionTypeArgumentsReg = ARM64_REG_X3;
  static constexpr arm64_reg kInstantiatorTypeArgumentsReg = ARM64_REG_X4;
  static constexpr arm64_reg kScratchReg = ARM64_REG_X5;
};
struct InitStaticFieldABI {
  static constexpr arm64_reg kFieldReg = ARM64_REG_X0;
};
struct LateInitializationErrorABI {
  static constexpr arm64_reg kFieldReg = ARM64_REG_X0;
};
struct DispatchTableNullErrorABI {
  static constexpr arm64_reg kInstanceReg = ARM64_REG_X0;
  static constexpr arm64_reg kClassIdReg = ARM64_REG_X1;
};
}

// Missing DartStub kinds
// These are defined in newer Dart versions' OBJECT_STORE_STUB_CODE_LIST
// We add them manually for 2.7.2 since they're used in code analysis

// Elf SectionHeaderType shim
namespace dart { namespace elf {
enum class SectionHeaderType : uint32_t {
  SHT_PROGBITS = 1,
  SHT_SYMTAB = 2,
  SHT_STRTAB = 3,
  SHT_RELA = 4,
  SHT_HASH = 5,
  SHT_DYNAMIC = 6,
  SHT_NOTE = 7,
  SHT_NOBITS = 8,
  SHT_REL = 9,
  SHT_SHLIB = 10,
  SHT_DYNSYM = 11,
  SHT_DYNSTR = 26,
};
}  }  // namespace dart::elf

// Arm64 register shims
#if defined(TARGET_ARCH_ARM64) && !defined(DISPATCH_TABLE_REG)
#define DISPATCH_TABLE_REG R17
#endif
#if defined(TARGET_ARCH_ARM64) && !defined(HEAP_BITS)
#define HEAP_BITS R18
#endif

#endif  // BLUTTER_COMPAT_DART27_H_
