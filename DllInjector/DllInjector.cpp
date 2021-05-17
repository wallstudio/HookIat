#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <vector>
#include <array>
#include <sstream>
#include <regex>
#include <tchar.h>
#include <filesystem>


HANDLE FindProcess(LPTSTR pattern)
{
    std::wcout << TEXT("Search process, ") << pattern << std::endl;
    auto targetProcessRegex = std::wregex(pattern);

    DWORD sizeInByte;
    DWORD processeIds[2048];
    EnumProcesses(processeIds, sizeof(processeIds), &sizeInByte);

    HANDLE handle;
    for (size_t i = 0; i < sizeInByte / sizeof(DWORD); i++)
    {
        handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processeIds[i]);
        auto nameBuff = std::array<TCHAR, MAX_PATH>();
        GetProcessImageFileName(handle, nameBuff.data(), nameBuff.size());
        auto name = std::wstring(nameBuff.data());
        if (std::regex_match(name, targetProcessRegex))
        {
            std::wcout << TEXT("Found process, ") << name << TEXT(" ") << handle << std::endl;
            return handle;
        }
    }
    std::wcout << TEXT("Not Found process") << std::endl;
    return 0;
}

bool InjectRoutine(HANDLE target, std::filesystem::path& dllPath)
{
    auto targetHeap = VirtualAllocEx(target, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (targetHeap == nullptr) return false;

    SIZE_T written;
    WriteProcessMemory(target, targetHeap, dllPath.wstring().c_str(), (dllPath.wstring().size() + 1) * sizeof(TCHAR), &written);

#pragma warning(suppress : 6387 )
    auto fpLoadLibraryW = GetProcAddress(GetModuleHandle(TEXT("kernel32")), "LoadLibraryW");
    auto thread = CreateRemoteThread(target, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(fpLoadLibraryW), targetHeap, 0, nullptr);
    if (thread == nullptr) return false;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(target, targetHeap, 0, MEM_RELEASE);
    
    return true;
}

int main(int argc, char* argv[])
{
    auto targetProcessName = std::wstring();
    //std::wcin >> targetProcessName;
    targetProcessName = TEXT("Taskmgr");
#pragma warning(suppress : 6387 )
    auto targetPattern = std::vector<TCHAR>(targetProcessName.size() + 10);
    _stprintf_s(targetPattern.data(), targetPattern.size(), TEXT(".*%s.*"), targetProcessName.c_str());

    auto target = FindProcess(targetPattern.data());
    if (target == 0) exit(-1);

    auto exePath = std::array<TCHAR, MAX_PATH>();
    GetModuleFileName(GetModuleHandle(nullptr), exePath.data(), exePath.size());
    auto dir = std::filesystem::path(exePath.data()).parent_path();
    auto dllPath = dir.append(TEXT("HookIat.dll"));
    InjectRoutine(target, dllPath);
}