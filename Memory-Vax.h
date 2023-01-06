#pragma once
#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
typedef unsigned long ulong;
typedef unsigned long long ulongl;
typedef unsigned int uint;
uint pID;
uint GetPID(const char * processname) {
    uint pID = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (!strcmp(entry.szExeFile, processname))
            {
                pID = entry.th32ProcessID;
                break;
            }
        }
    }
        CloseHandle(snapshot);
        return pID;
}

ulongl GetModuleAddress(const char * modulename) {
    ulongl ModuleBaseAddress;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pID);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);

        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!strcmp(modEntry.szModule, modulename))
                {
                    ModuleBaseAddress = (ulongl)modEntry.modBaseAddr;
                    break;
                }

            } while (Module32Next(hSnap, &modEntry));
        }
    }
    //free the handle
    CloseHandle(hSnap);
    return ModuleBaseAddress;
}

// ex valueread = "float"
double RPM(HANDLE handle_game, ulongl address, const char* valueread) {
    
    if (strcmp(valueread, "int") == 0) {
        int value = 0;
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READ, &oldprotect);
        bool rpm = ReadProcessMemory(handle_game, (const void*)address, &value, sizeof(value), NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (rpm == false) {
            printf("RPM Failed at this address : 0x%lX\n", address);
        }
        else {
            return value;
        }
    }

    if (strcmp(valueread, "float") == 0) {
       float value = 0;
       ulongl oldprotect = 0;
       ulongl oldprotect_one = 0;
       VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READ, &oldprotect);
       bool rpm = ReadProcessMemory(handle_game, (const void*)address, &value, sizeof(value), NULL);
       VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
       if (rpm == false) {
           printf("RPM Failed at this address : 0x%lX\n", address);
       }
       else {
           return value;
       }
   }

    if (strcmp(valueread, "double") == 0) {
        double value = 0;
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READ, &oldprotect);
        bool rpm = ReadProcessMemory(handle_game, (const void*)address, &value, sizeof(value), NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (rpm == false) {
            printf("RPM Failed at this address : 0x%lX\n", address);
        }
        else {
            return value;
        }
    }

    if (strcmp(valueread, "ulongl") == 0) {
        ulongl value = 0;
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READ, &oldprotect);
        bool rpm = ReadProcessMemory(handle_game, (const void*)address, &value, sizeof(value), NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (rpm == false) {
            printf("RPM Failed at this address : 0x%lX\n", address);
        }
        else {
            return value;
        }
    }

    if (strcmp(valueread, "ulong") == 0) {
        ulong value = 0;
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READ, &oldprotect);
        bool rpm = ReadProcessMemory(handle_game, (const void*)address, &value, sizeof(value), NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (rpm == false) {
            printf("RPM Failed at this address : 0x%lX\n", address);
        }
        else {
            return value;
        }
    }

    else {
       printf("Not a valid valueread ! \n");
       void* value;
    }
}
//put valueofwrite with &before it
bool WPM(HANDLE handle_game, ulongl address, void * valueofwrite, const char* valuewrite) {
    if (strcmp(valuewrite, "int") == 0) {
        int value = *(int*)valueofwrite;
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);
        bool wpm = WriteProcessMemory(handle_game, (const void*)address, &value, sizeof(value), NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (wpm == false) {
            printf("WPM Failed at this address : 0x%lX\n", address);
        }
        else {
            return true;
        }
    }

    if (strcmp(valuewrite, "float") == 0) {
        float value = *(float*)valueofwrite;
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);
        bool wpm = WriteProcessMemory(handle_game, (const void*)address, &value, sizeof(value), NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (wpm == false) {
            printf("WPM Failed at this address : 0x%lX\n", address);
        }
        else {
            return true;
        }
    }

    if (strcmp(valuewrite, "double") == 0) {
        double value = *(double*)valueofwrite;
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);
        bool wpm = WriteProcessMemory(handle_game, (const void*)address, &value, sizeof(value), NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (wpm == false) {
            printf("WPM Failed at this address : 0x%lX\n", address);
        }
        else {
            return true;
        }
    }

    if (strcmp(valuewrite, "ulongl") == 0) {
        ulongl value = *(ulongl*)valueofwrite;
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);
        bool wpm = WriteProcessMemory(handle_game, (const void*)address, &value, sizeof(value), NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (wpm == false) {
            printf("WPM Failed at this address : 0x%lX\n", address);
        }
        else {
            return true;
        }
    }

    if (strcmp(valuewrite, "ulong") == 0) {
        ulong value = *(ulong*)valueofwrite;
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);
        bool wpm = WriteProcessMemory(handle_game, (const void*)address, &value, sizeof(value), NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (wpm == false) {
            printf("WPM Failed at this address : 0x%lX\n", address);
        }
        else {
            return true;
        }
    }

    else {
        printf("Not a valid valueread ! \n");
    }
}

// sizeofoffsets = sizeof(offsets) / sizeof(offsets[0])
ulongl GetptrAddress(HANDLE handle_game, ulong baseaddress, uint offsets[], SIZE_T sizeofoffsets) {
    ulong address = baseaddress;
    ulong currentreading = 0;

    for (int i = 0; i < sizeofoffsets; i++) {
        ulong oldprotect = 0;
        ulong oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void *)address, sizeof(address), PAGE_EXECUTE_READ, &oldprotect);
        ReadProcessMemory(handle_game, (const void*)address, &currentreading, sizeof(currentreading), NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        currentreading += offsets[i];
        address = currentreading;
        currentreading = 0;
    }
    return address;
}