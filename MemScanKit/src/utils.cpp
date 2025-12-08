#include "utils.h"
#include <TlHelp32.h>

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
