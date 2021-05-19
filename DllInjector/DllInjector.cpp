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
#include <fmt/format.h>

// https://github.com/i-saint/RemoteTalk/blob/89fa111/.RemoteTalk/Plugin/RemoteTalkVOICEROID/RemoteTalkVOICEROIDEx.cpp#L7
// http://titech-ssr.blog.jp/archives/1047454763.html

HANDLE FindProcess(std::wstring& pattern)
{
    std::wcout << fmt::format(L"Search process, {0}", pattern) << std::endl;
    auto targetProcessRegex = std::wregex(pattern);

    DWORD sizeInByte;
    auto processeIds = std::vector<DWORD>(2048);
    EnumProcesses(processeIds.data(), processeIds.size() * sizeof(DWORD), &sizeInByte);
    processeIds.resize(sizeInByte / sizeof(DWORD));

    HANDLE handle;
    for (auto processId : processeIds)
    {
        handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        auto name = std::wstring(MAX_PATH, L'\0');
        GetProcessImageFileNameW(handle, name.data(), name.size());
        if (std::regex_match(name, targetProcessRegex))
        {
            std::wcout << fmt::format(L"Found process, {0} ({1})", name, handle)<< std::endl;
            return handle;
        }
    }
    std::wcout << L"Not Found process" << std::endl;
    return 0;
}

bool InjectRoutine(HANDLE target, std::filesystem::path& dllPath)
{
    auto targetHeap = VirtualAllocEx(target, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (targetHeap == nullptr) return false;

    SIZE_T written;
    WriteProcessMemory(target, targetHeap, dllPath.wstring().c_str(), (dllPath.wstring().size() + 1) * sizeof(TCHAR), &written);

#pragma warning(suppress : 6387 )
    auto fpLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW");
    auto thread = CreateRemoteThread(target, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(fpLoadLibraryW), targetHeap, 0, nullptr);
    if (thread == nullptr) return false;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(target, targetHeap, 0, MEM_RELEASE);
    
    return true;
}

int main(int argc, char* argv[])
{
    auto targetName = std::wstring();
    auto targetPattern = fmt::format(L".*{0}.*", L"Taskmgr");

    auto target = FindProcess(targetPattern);
    if (target == 0) exit(-1);

    auto exePath = std::wstring(MAX_PATH, L'\0');
    GetModuleFileNameW(GetModuleHandle(nullptr), exePath.data(), exePath.size());
    auto dllPath = std::filesystem::path(exePath.c_str()).parent_path().append(TEXT("HookIat.dll"));
    InjectRoutine(target, dllPath);
}
