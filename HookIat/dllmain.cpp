#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdlib.h>
#include <iostream>

// https://snoozy.hatenablog.com/entry/2020/03/28/001631
// https://qiita.com/cha1aza/items/f64dc4351517a2477ef1
// https://tech.blog.aerie.jp/entry/2016/01/13/013206

typedef struct Entry
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
};
typedef NTSTATUS(WINAPI* NtQuerySystemInformationCallback)(SYSTEM_INFORMATION_CLASS infoClass, Entry* entry, ULONG numEntry, PULONG requierNumEntry);

NTSTATUS WINAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS infoClass, Entry* entry, ULONG numEntry, PULONG requierNumEntry)
{

    static NtQuerySystemInformationCallback base = nullptr;
    if (base == nullptr)
    {
#pragma warning(suppress : 6387 )
        base = reinterpret_cast<NtQuerySystemInformationCallback>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation"));
    }
    NTSTATUS status = base(infoClass, entry, numEntry, requierNumEntry);
    if (SystemProcessInformation != infoClass) return status;
    if (STATUS_SUCCESS != status) return status; // no success

    do
    {
        auto next = (Entry*)((SIZE_T)entry + (SIZE_T)entry->NextEntryOffset);
        if (0 == wcsncmp(next->ImageName.Buffer, L"notepad.exe", next->ImageName.Length))
        {
            //static WCHAR fakeName[] = L"らくがき帖";
            //next->ImageName = UNICODE_STRING{ _countof(fakeName), _countof(fakeName) + 1, fakeName };
            entry->NextEntryOffset = next->NextEntryOffset == 0 ? 0 : (entry->NextEntryOffset + next->NextEntryOffset);
            return status;
        }
        entry = next;
    }     while (entry->NextEntryOffset != 0);
}

template<typename T>
T* RvaToVa(SIZE_T rva)
{
    auto base = (SIZE_T)GetModuleHandle(0);
    auto va = base + rva;
    return reinterpret_cast<T*>(va);
}

IMAGE_THUNK_DATA* IATfind(const char* function)
{
    PIMAGE_DOS_HEADER pImgDosHeaders = (PIMAGE_DOS_HEADER)GetModuleHandle(0);
    PIMAGE_NT_HEADERS pImgNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImgDosHeaders + pImgDosHeaders->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImgImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pImgDosHeaders + pImgNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (pImgDosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
        std::cout << "libPE Error : e_magic is no valid DOS signature" << std::endl;

    for (IMAGE_IMPORT_DESCRIPTOR* iid = pImgImportDesc; iid->Name != NULL; iid++) {
        auto dllName = RvaToVa<char>(iid->Name);

        for (int funcIdx = 0; ; funcIdx++) {
            auto ia = RvaToVa<IMAGE_THUNK_DATA>(iid->OriginalFirstThunk)[funcIdx];
            if (ia.u1.Function == NULL) break;
            if (ia.u1.Ordinal >> (sizeof(ia.u1.Ordinal) * 8 - 1)) continue;
            if (0 != _stricmp(function, RvaToVa<IMAGE_IMPORT_BY_NAME>(ia.u1.Function)->Name)) continue;
            return RvaToVa<IMAGE_THUNK_DATA>(iid->FirstThunk) + funcIdx;
        }
    }
    return nullptr;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, LPVOID _)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        MessageBox(NULL, TEXT("DLL attached."), TEXT("HookIat"), MB_OK);

        auto funcptr = IATfind("NtQuerySystemInformation");
        DWORD oldrights, newrights = PAGE_READWRITE;
        VirtualProtect(funcptr, sizeof(LPVOID), newrights, &oldrights);
        funcptr->u1.Function = (LONGLONG)HookedNtQuerySystemInformation;
        VirtualProtect(funcptr, sizeof(LPVOID), oldrights, &newrights);
    }
    return TRUE;
}