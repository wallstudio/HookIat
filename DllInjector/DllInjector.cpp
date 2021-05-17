#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <vector>
#include <array>
#include <sstream>
#include <regex>
#include <tchar.h>


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
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, processeIds[i]);
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
}