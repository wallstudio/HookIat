#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <memory>

// https://github.com/processhacker/processhacker/blob/e96989/ProcessHacker/memprv.c#L757

enum MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation = 0x0,
    MemoryWorkingSetInformation = 0x1,
    MemoryMappedFilenameInformation = 0x2,
    MemoryRegionInformation = 0x3,
    MemoryWorkingSetExInformation = 0x4,
    MemorySharedCommitInformation = 0x5,
    MemoryImageInformation = 0x6,
    MemoryRegionInformationEx = 0x7,
    MemoryPrivilegedBasicInformation = 0x8,
    MemoryEnclaveImageInformation = 0x9,
    MemoryBasicInformationCapped = 0xA,
    MemoryPhysicalContiguityInformation = 0xB,
};
typedef NTSTATUS(NTAPI* NtQueryVirtualMemoryCallbacl)(
    HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass,
    MEMORY_BASIC_INFORMATION* MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

template<typename T>
T* RvaToVa(T* base, SIZE_T rva)
{
    auto va = (SIZE_T)base + rva;
    return reinterpret_cast<T*>(va);
}

int main(int argc, char* argv[])
{
    // heapの一部にマーキング
    auto data = std::unique_ptr<char>(new char[1024*1024]);
    auto text = std::string("MakiMakiKawaiiYatta!");
    memcpy(data.get(), text.data(), text.size());
    std::cout << "store to [" << std::hex << (SIZE_T)data.get() << "]" << std::endl;

    auto nt = LoadLibrary(TEXT("ntdll.dll"));
    if (nt == nullptr) exit(-1);
    
    auto fpNtQueryVirtualMemory = reinterpret_cast<NtQueryVirtualMemoryCallbacl>(GetProcAddress(nt, "NtQueryVirtualMemory"));
    auto base = (void*)0;
    MEMORY_BASIC_INFORMATION basicInfo;
    for(auto base = (void*)0; ; base = RvaToVa(base, basicInfo.RegionSize))
    {
        auto handle = GetCurrentProcess();
        auto status = fpNtQueryVirtualMemory(handle, base, MEMORY_INFORMATION_CLASS::MemoryBasicInformation, &basicInfo, sizeof(MEMORY_BASIC_INFORMATION), nullptr);
        if (!NT_SUCCESS(status)) break;

        std::cout << "[" << std::hex << basicInfo.BaseAddress << "] " << std::dec << basicInfo.RegionSize << "B" << std::endl;
    }
}