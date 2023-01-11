#pragma once
#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdbool.h>
#include <string.h>
typedef unsigned long ulong;
typedef unsigned long long ulongl;
typedef unsigned int uint;

uint pID;
HANDLE handle_game;

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
                handle_game = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
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
// ex read_size = sizeof(address) ex : ulongl * addr = RPM(parameters) to define float value = *(float*)addr
void * RPM(ulongl address, size_t read_size) {
        void* value = malloc(read_size);
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);;
        bool rpm = ReadProcessMemory(handle_game, (const void*)address, value, read_size, NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (rpm == false) {
            printf("RPM Failed at this address : 0x%p\n", address);
            free(value);
            return false;
        }
        else {
            return value;
        }
}
//put valueofwrite with &before it
bool WPM(ulongl address, void * valueofwrite, size_t write_size) {
        void* value = valueofwrite;
        ulongl oldprotect = 0;
        ulongl oldprotect_one = 0;
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), PAGE_EXECUTE_READWRITE, &oldprotect);
        bool wpm = WriteProcessMemory(handle_game, (const void*)address, value, write_size, NULL);
        VirtualProtectEx(handle_game, (void*)address, sizeof(address), oldprotect, &oldprotect_one);
        if (wpm == false) {
            printf("WPM Failed at this address : 0x%p\n", address);
            return false;
        }
        else {
            return true;
        }
}
// sizeofoffsets = sizeof(offsets) / sizeof(offsets[0])
ulongl GetptrAddress(ulong baseaddress, uint offsets[], SIZE_T sizeofoffsets) {
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
