#include "pch.h"
#include "DartField.h"
#include "DartClass.h"
#include "DartLibrary.h"

DartField::DartField(const DartClass& cls_, dart::FieldPtr ptr_) : cls(cls_), type(nullptr), ptr(ptr_)
{
	ASSERT(ptr_ != nullptr);
	const auto& field = dart::Field::Handle(ptr_);
	auto& str = dart::String::Handle(field.UserVisibleName());
	name = str.ToCString();
	// static field has no offset in object. it is offset of static list
	is_static = field.is_static();
	is_late = field.is_late();
	is_final = field.is_final();
	is_const = field.is_const();

	if (field.is_static()) {
		offset = 0;
	} else {
		offset = (uint32_t)field.Offset();
	}

	typePtr = field.type();
	const auto& abType = dart::AbstractType::Handle(typePtr);
	str = abType.UserVisibleName();
	typeName = str.ToCString();
}

DartField::DartField(const DartClass& cls, uint32_t offset, DartAbstractType* type, std::string name) :
	cls(cls), type(type), name(std::move(name)), offset(offset), is_static(false), is_late(false), is_final(false), is_const(false)
{
}

void DartField::Print(std::ostream& of) const
{
	of << "  ";
	if (ptr == nullptr) {
		// use concrete type
		ASSERT(type);
		of << type->ToString();
		of << std::format(" field_{:x};\n", offset);
	}
	else {
		if (is_static)
			of << "static ";
		if (is_late)
			of << "late ";
		if (is_final)
			of << "final ";
		if (is_const)
			of << "const ";
		of << typeName << " " << name;
		of << std::format("; // offset: {:#x}\n", offset);
	}
}

std::string DartField::FullName() const
{
	return "[" + cls.Library().url + "] " + cls.FullName() + "::" + name;
}
