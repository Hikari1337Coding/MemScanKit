#pragma once
#include <wtypes.h>
#include <string>
#include <atomic>
#include <mutex>
#include <vector>

struct ModuleInfo {
	uintptr_t base;
	SIZE_T size;
};

inline DWORD target_pid = 0;
inline HANDLE target_handle = nullptr;
inline ModuleInfo target_module_info { 0,0 };

inline std::vector<uintptr_t> value_matches;
inline std::mutex value_matches_mutex;

inline std::atomic_bool value_scanning{ false };

inline std::thread valueScanThread;
inline std::mutex target_mutex;

DWORD getProcIdByName(const std::string& name);

ModuleInfo getModuleInfoById(DWORD pid);

// same as pointer scanning but instead of checking base + offset == targetAddr, check *addr == needle
template<typename T, typename Cmp>
void valueScan(const T& needle, Cmp cmp) {
	value_scanning = true;
	{
		std::lock_guard<std::mutex> lock(value_matches_mutex);
		value_matches.clear();
	}
	if (!target_handle) {
		value_scanning = false;
		return;
	}

	SYSTEM_INFO si;
	GetSystemInfo(&si);

	LPCVOID addr = si.lpMinimumApplicationAddress;
	const SIZE_T chunk = 1 << 20; // 1 MiB

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
					// scan buffer for matches of sizeof(T) aligned at each byte
					for (SIZE_T i = 0; i + sizeof(SIZE_T) <= bytesRead && value_scanning; ++i) {
						T val;
						memcpy(&val, &buffer[i], sizeof(T));
						if (cmp(val, needle)) {
							uintptr_t found = (uintptr_t)mbi.BaseAddress + offset + i;
							std::lock_guard<std::mutex> lock(value_matches_mutex);
							value_matches.push_back(found);
						}
					}
				}
				offset += toRead;
			}
		}
		addr = (LPCVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
	}

	value_scanning = false;

}

template<typename T>
bool readValueFromProcess(LPCVOID addr, T& out) {
	SIZE_T numOfBtyesRead = 0;
	return ReadProcessMemory(target_handle, addr, &out, sizeof(T), &numOfBtyesRead) && numOfBtyesRead == sizeof(T);
}

// Narrowing scan (checks existing addresses only)
template<typename T, typename Cmp>
void valueNarrow(const T& needle, Cmp cmp) {
	value_scanning = true;
	if (!target_handle) { value_scanning = false; return; }

	std::vector<uintptr_t> keep;
	{
		std::lock_guard<std::mutex> lock(value_matches_mutex);
		for (auto a : value_matches) {
			T tmp;
			if (readValueFromProcess((LPCVOID)a, tmp) && cmp(tmp, needle)) keep.push_back(a);
		}
		value_matches.swap(keep);
	}

	value_scanning = false;
}


// Helper to format an address
std::string addrToHex(uintptr_t a);


template<typename T>
bool readFromTarget(uintptr_t addr, T& out) {
	std::lock_guard<std::mutex> lock(target_mutex);
	if (!target_handle) return false;
	SIZE_T numSizeRead = 0;
	return ReadProcessMemory(target_handle, (LPCVOID)addr, &out, sizeof(T), &numSizeRead) && numSizeRead == sizeof(T);
}

// for string scanning
void stringScan(const std::string& needle);
void stringNarrow(const std::string& needle);
bool readStringFromProcess(uintptr_t addr, std::string& out, size_t maxLen = 256);

struct PointerResult {
	uintptr_t base;
	uintptr_t offset;
};

void pointerScanLevel1(uintptr_t targetAddr, uintptr_t maxOffset = 0x1000);

inline std::vector<PointerResult> pointer_results;
inline std::mutex pointer_results_mutex;

uintptr_t resolveLevel1(const PointerResult& r);

enum class DisplayType {
	Int32,
	Float,
	String
};

bool readValueAsString(uintptr_t addr, DisplayType type, std::string& out);

struct WatchItem {
	uintptr_t addr; 
	std::string value;
	std::string lastValue;
	bool freeze{ false };
	std::string frozenValue;
};
inline std::vector<WatchItem> watchlist;


template <typename T>
bool writeMemory(uintptr_t addr, const T& value) {
	std::lock_guard<std::mutex> lock(target_mutex);
	if (!target_handle) return false;
	size_t bytesWritten = 0;
	return WriteProcessMemory(target_handle, (LPVOID)addr, &value, sizeof(T), &bytesWritten) && bytesWritten == sizeof(T);
}

bool writeValueFromString(uintptr_t addr, DisplayType type, std::string value);

inline std::atomic<bool> freeze_running{ true };
inline int watchlistDisplayType = 0;
inline std::mutex watchlist_mutex;

inline uintptr_t memViewAddr{};
inline uint8_t memBuffer[0x100]; // 256 bytes