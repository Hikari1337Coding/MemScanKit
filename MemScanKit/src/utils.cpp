#include "utils.h"
#include <TlHelp32.h>
#include <sstream>
#include <algorithm>

DWORD getProcIdByName(const std::string& name) {
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) return 0;

	if (Process32First(snap, &pe)) {
		do {
			if (_stricmp(pe.szExeFile, name.c_str()) == 0) {
				CloseHandle(snap);
				return pe.th32ProcessID;
			}
		} while (Process32Next(snap, &pe));
	}

	CloseHandle(snap);
	return 0;
}

ModuleInfo getModuleInfoById(DWORD pid) {
	ModuleInfo m{ 0,0 };

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

	if (snap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 me;
		me.dwSize = sizeof(me);
		if (Module32First(snap, &me)) {
			do {
				m.base = (uintptr_t)me.modBaseAddr;
				m.size = (SIZE_T)me.modBaseSize;
			} while (Module32Next(snap, &me));
		}
	}

	CloseHandle(snap);
	return m;
}

// Helper to format an address
std::string addrToHex(uintptr_t a) {
	std::ostringstream ss;
	ss << "0x" << std::hex << std::uppercase << a;
	return ss.str();
}

// mem-search helper
static const char* memmem_const(const char* hay, size_t haylen, const char* needle, size_t nlen) {
	if (!nlen || nlen > haylen) return nullptr;
	for (size_t i = 0; i + nlen <= haylen; ++i)
		if (memcmp(hay + i, needle, nlen) == 0) return hay + i;
	return nullptr;
}

void stringScan(const std::string& needle) {
	value_scanning = true;
	{
		std::lock_guard<std::mutex> lock(value_matches_mutex);
		value_matches.clear();
	}
	if (!target_handle) { value_scanning = false; return; }

	SYSTEM_INFO si; GetSystemInfo(&si);
	LPCVOID addr = si.lpMinimumApplicationAddress;
	const SIZE_T chunk = 1 << 20;

	while ((SIZE_T)addr < (SIZE_T)si.lpMaximumApplicationAddress && value_scanning) {
		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQueryEx(target_handle, addr, &mbi, sizeof(mbi))) break;
		if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ))) {
			SIZE_T regionSize = mbi.RegionSize;
			SIZE_T offset = 0;
			while (offset < regionSize && value_scanning) {
				SIZE_T toRead = (SIZE_T)min(chunk, regionSize - offset);
				std::vector<char> buffer(toRead);
				SIZE_T bytesRead = 0;
				LPCVOID readAddr = (LPCVOID)((SIZE_T)mbi.BaseAddress + offset);
				if (ReadProcessMemory(target_handle, readAddr, buffer.data(), toRead, &bytesRead) > 0) {
					const char* p = buffer.data();
					while (true) {
						const char* found = memmem_const(p, bytesRead - (p - buffer.data()), needle.data(), needle.size());
						if (!found || !value_scanning) break;
						uintptr_t foundAddr = (uintptr_t)mbi.BaseAddress + offset + (found - buffer.data());
						{
							std::lock_guard<std::mutex> lock(value_matches_mutex);
							value_matches.push_back(foundAddr);
						}
						p = found + 1; // continue search after this match
					}
				}
				offset += toRead;
			}
		}
		addr = (LPCVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
	}
	value_scanning = false;
}

void stringNarrow(const std::string& needle) {
	value_scanning = true;
	if (!target_handle) { value_scanning = false; return; }
	std::vector<uintptr_t> keep;
	{
		std::lock_guard<std::mutex> lock(value_matches_mutex);
		for (auto a : value_matches) {
			// read a small window from the process and check for needle
			const size_t bufSz = 512;
			std::vector<char> tmp(bufSz);
			SIZE_T bytesRead = 0;
			if (ReadProcessMemory(target_handle, (LPCVOID)a, tmp.data(), bufSz, &bytesRead) && bytesRead > 0) {
				if (memmem_const(tmp.data(), bytesRead, needle.data(), needle.size()))
					keep.push_back(a);
			}
		}
		value_matches.swap(keep);
	}
	value_scanning = false;
}

bool readStringFromProcess(uintptr_t addr, std::string& out, size_t maxLen) {
	std::vector<char> buf(maxLen);
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(target_handle, (LPCVOID)addr, buf.data(), maxLen, &bytesRead) || bytesRead == 0) return false;
	// terminate at first NUL or end
	size_t len = 0;
	while (len < bytesRead && buf[len]) ++len;
	out.assign(buf.data(), len);
	return true;
}

void pointerScanLevel1(uintptr_t targetAddr, uintptr_t maxOffset)
{
	value_scanning = true;
	{
		std::lock_guard<std::mutex> lock(pointer_results_mutex);
		pointer_results.clear();
	}

	if (!target_handle) { value_scanning = false; return; }

	SYSTEM_INFO si; GetSystemInfo(&si);
	LPCVOID addr = si.lpMinimumApplicationAddress;

	while ((SIZE_T)addr < (SIZE_T)si.lpMaximumApplicationAddress && value_scanning) {
		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQueryEx(target_handle, addr, &mbi, sizeof(mbi))) break;

		if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ))) {
			SIZE_T count = mbi.RegionSize / sizeof(uintptr_t);
			std::vector<uintptr_t> buffer(count);
			SIZE_T bytesRead = 0;

			if (ReadProcessMemory(target_handle, mbi.BaseAddress, buffer.data(),
				count * sizeof(uintptr_t), &bytesRead)) {
				for (SIZE_T i = 0; i < bytesRead / sizeof(uintptr_t); ++i) {
					uintptr_t val = buffer[i];
					if (val <= targetAddr && targetAddr - val <= maxOffset) {
						uintptr_t offset = targetAddr - val;
						uintptr_t base = (uintptr_t)mbi.BaseAddress + i * sizeof(uintptr_t);
						std::lock_guard<std::mutex> lock(pointer_results_mutex);
						pointer_results.push_back({ base, offset });
					}
				}
			}
		}
		addr = (LPCVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
	}
	value_scanning = false;
}

uintptr_t resolveLevel1(const PointerResult& r) {
	uintptr_t tmp = 0;
	if (!ReadProcessMemory(
		target_handle,
		(LPCVOID)r.base,
		&tmp,
		sizeof(tmp),
		nullptr))
		return 0;

	return tmp + r.offset;
}

bool readValueAsString(uintptr_t addr, DisplayType type, std::string& out) {
	if (!addr) return false;

	switch (type) {
	case DisplayType::Int32: {
		int32_t v;
		if (!readFromTarget<int32_t>(addr, v)) return false;
		out = std::to_string(v);
		return true;
	}
	case DisplayType::Float: {
		float v;
		if (!readFromTarget<float>(addr, v)) return false;
		out = std::to_string(v);
		return true;
	}
	case DisplayType::String: {
		std::string v;
		if (!readStringFromProcess(addr, v)) return false;
		out = v;
		return true;
	}
	}
	return false;
}
