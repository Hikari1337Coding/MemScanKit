#pragma once
#include <wtypes.h>
#include <string>

struct ModuleInfo {
	uintptr_t base;
	SIZE_T size;
};

DWORD getProcIdByName(const std::string& name);

ModuleInfo getModuleInfoById(DWORD pid);