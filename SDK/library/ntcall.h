#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>

#include <Zydis/Zydis.h>
#include <asmjit/asmjit.h>
#include "util.h"
#include "jit.hpp"
#include "xorstr.h"

namespace sys {
    inline util::SafeMap<std::string, DWORD> ssn_map;

    inline auto get_module_base(const std::wstring& _module_name) -> HMODULE {
        MUTATE_START_ASM64();
        const auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
        if (!peb || !peb->Ldr) {
            throw std::runtime_error(XORSTR("PEB or Ldr is null"));
        }

        const LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
        LIST_ENTRY* curr = head->Flink;
        std::wstring target = _module_name;
        std::ranges::transform(target, target.begin(), towlower);

        while (curr != head) {
            const auto entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(reinterpret_cast<BYTE*>(curr) - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

            if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
                std::wstring name(entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(WCHAR));
                name = std::filesystem::path(name).filename();
                std::ranges::transform(name, name.begin(), towlower);
                if (name == target) {
                    return static_cast<HMODULE>(entry->DllBase);
                }
            }
            curr = curr->Flink;
        }
        MUTATE_END_ASM64();
        throw std::runtime_error(XORSTR("Module not found in PEB"));
    }

    inline auto get_export_function(const HMODULE _h_module, const std::string& _func_name) -> void* {
        MUTATE_START_ASM64();
        if (!_h_module) {
            throw std::runtime_error(XORSTR("Module base is null"));
        }

        const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(_h_module);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            throw std::runtime_error(XORSTR("Invalid DOS signature"));
        }

        const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(_h_module) + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            throw std::runtime_error(XORSTR("Invalid NT signature"));
        }

        const auto export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!export_dir_rva) {
            throw std::runtime_error(XORSTR("No export directory"));
        }

        const auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(_h_module) + export_dir_rva);

        const auto names = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(_h_module) + export_dir->AddressOfNames);
        const auto ords = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(_h_module) + export_dir->AddressOfNameOrdinals);
        const auto funcs = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(_h_module) + export_dir->AddressOfFunctions);

        for (DWORD i = 0; i < export_dir->NumberOfNames; ++i) {
            const auto name = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(_h_module) + names[i]);
            if (_func_name == name) {
                const WORD ordinal = ords[i];
                const DWORD rva = funcs[ordinal];
                return reinterpret_cast<BYTE*>(_h_module) + rva;
            }
        }

        MUTATE_END_ASM64();
        throw std::runtime_error(XORSTR("Function not found in export table"));
    }

    inline auto build_ssn_table() -> void {
        MUTATE_START_ASM64();
        HMODULE hinstance = get_module_base(XORWSTR(L"ntdll.dll"));
        if (!hinstance) {
            throw std::runtime_error(XORSTR("ntdll hinstance is nullptr"));
        }

        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hinstance);
        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hinstance) + dos->e_lfanew);
        auto exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(hinstance) + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        auto names = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(hinstance) + exp_dir->AddressOfNames);
        auto ords = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(hinstance) + exp_dir->AddressOfNameOrdinals);
        auto funcs = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(hinstance) + exp_dir->AddressOfFunctions);

        ZydisDecoder dec;
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

        for (DWORD i = 0; i < exp_dir->NumberOfNames; ++i) {
            auto name = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(hinstance) + names[i]);
            if (name[0] != 'N' || name[1] != 't') {
                continue;
            }

            PVOID fn = reinterpret_cast<BYTE*>(hinstance) + funcs[ords[i]];

            ZydisDecodedInstruction ins;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];

            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, fn, 16, &ins, ops))) {
                continue;
            }

            if (ins.mnemonic != ZYDIS_MNEMONIC_MOV || ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER || ops[0].reg.value != ZYDIS_REGISTER_R10 || ops[1].type != ZYDIS_OPERAND_TYPE_REGISTER || ops[1].reg.
                value != ZYDIS_REGISTER_RCX) {
                continue;
            }

            BYTE* next = static_cast<BYTE*>(fn) + ins.length;
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, next, 16, &ins, ops))) {
                continue;
            }
            if (ins.mnemonic == ZYDIS_MNEMONIC_MOV && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ops[0].reg.value == ZYDIS_REGISTER_EAX && ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                DWORD ssn = static_cast<DWORD>(ops[1].imm.value.u);
                ssn_map[name] = ssn;
            }
        }
        MUTATE_END_ASM64();
    }

    template<typename... Args>
    auto syscall(const char* _func_name, Args... _args) -> NTSTATUS {
        MUTATE_START_ASM64();
        if (ssn_map.empty()) {
            build_ssn_table();
        }

        if (!ssn_map.contains(_func_name)) {
            throw std::runtime_error(std::format("Function not found in SSN map : {}", _func_name));
        }

        asmjit::JitRuntime rt;
        asmjit::CodeHolder code;
        code.init(rt.environment());
        asmjit::x86::Assembler a(&code);

        a.mov(asmjit::x86::r10, asmjit::x86::rcx);
        a.mov(asmjit::x86::eax, ssn_map[_func_name]);
        a.syscall();
        a.ret();

        void* fn_ptr = nullptr;
        rt.add(&fn_ptr, &code);
        NTSTATUS status = reinterpret_cast<NTSTATUS(__fastcall*)(Args...)>(fn_ptr)(_args...);
        rt.release(fn_ptr);

        MUTATE_END_ASM64();
        return status;
    }

    enum SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 };

    inline auto NtMapViewOfSection(const HANDLE SectionHandle,
                                   const HANDLE ProcessHandle,
                                   void** BaseAddress,
                                   const ULONG_PTR ZeroBits,
                                   const SIZE_T CommitSize,
                                   const PLARGE_INTEGER SectionOffset,
                                   const PSIZE_T ViewSize,
                                   const SECTION_INHERIT InheritDisposition,
                                   const ULONG AllocationType,
                                   const ULONG Win32Protect) -> NTSTATUS {
        return syscall(XORSTR("NtMapViewOfSection"), SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
    }

    inline auto NtUnmapViewOfSection(const HANDLE ProcessHandle, void* BaseAddress) -> NTSTATUS {
        return syscall(XORSTR("NtUnmapViewOfSection"), ProcessHandle, BaseAddress);
    }

    inline auto NtCreateSection(const PHANDLE SectionHandle,
                                const ACCESS_MASK DesiredAccess,
                                const POBJECT_ATTRIBUTES ObjectAttributes,
                                const PLARGE_INTEGER MaximumSize,
                                const ULONG SectionPageProtection,
                                const ULONG AllocationAttributes,
                                const HANDLE FileHandle) -> NTSTATUS {
        return syscall(XORSTR("NtCreateSection"), SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    }

    inline auto NtMapViewOfSectionEx(const HANDLE SectionHandle,
                                     const HANDLE ProcessHandle,
                                     PVOID* BaseAddress,
                                     const PLARGE_INTEGER SectionOffset,
                                     const PSIZE_T ViewSize,
                                     const ULONG AllocationType,
                                     const ULONG PageProtection,
                                     const PMEM_EXTENDED_PARAMETER ExtendedParameters,
                                     const ULONG ExtendedParameterCount) -> NTSTATUS {
        return syscall(XORSTR("NtMapViewOfSectionEx"), SectionHandle, ProcessHandle, BaseAddress, SectionOffset, ViewSize, AllocationType, PageProtection, ExtendedParameters, ExtendedParameterCount);
    }

    inline auto NtCreateSectionEx(const PHANDLE SectionHandle,
                                  const ACCESS_MASK DesiredAccess,
                                  const POBJECT_ATTRIBUTES ObjectAttributes,
                                  const PLARGE_INTEGER MaximumSize,
                                  const ULONG SectionPageProtection,
                                  const ULONG AllocationAttributes,
                                  const HANDLE FileHandle,
                                  const PMEM_EXTENDED_PARAMETER ExtendedParameters,
                                  const ULONG ExtendedParameterCount) -> NTSTATUS {
        return syscall(XORSTR("NtCreateSectionEx"),
                       SectionHandle,
                       DesiredAccess,
                       ObjectAttributes,
                       MaximumSize,
                       SectionPageProtection,
                       AllocationAttributes,
                       FileHandle,
                       ExtendedParameters,
                       ExtendedParameterCount);
    }

    inline auto NtUnmapViewOfSectionEx(const HANDLE ProcessHandle, const PVOID BaseAddress, const ULONG Flags) -> NTSTATUS {
        return syscall(XORSTR("NtUnmapViewOfSectionEx"), ProcessHandle, BaseAddress, Flags);
    }

    inline auto NtCreateThreadEx(const PHANDLE ThreadHandle,
                                 const ACCESS_MASK DesiredAccess,
                                 const POBJECT_ATTRIBUTES ObjectAttributes,
                                 const HANDLE ProcessHandle,
                                 const PVOID StartRoutine,
                                 const PVOID Argument,
                                 const ULONG CreateFlags,
                                 const SIZE_T ZeroBits,
                                 const SIZE_T StackSize,
                                 const SIZE_T MaximumStackSize,
                                 const PVOID AttributeList) -> NTSTATUS {
        return syscall(XORSTR("NtCreateThreadEx"),
                       ThreadHandle,
                       DesiredAccess,
                       ObjectAttributes,
                       ProcessHandle,
                       StartRoutine,
                       Argument,
                       CreateFlags,
                       ZeroBits,
                       StackSize,
                       MaximumStackSize,
                       AttributeList);
    }

    inline auto NtCreateThread(const PHANDLE ThreadHandle,
                               const ACCESS_MASK DesiredAccess,
                               const POBJECT_ATTRIBUTES ObjectAttributes,
                               const HANDLE ProcessHandle,
                               const PVOID StartRoutine,
                               const PVOID Argument,
                               const ULONG CreateSuspended) -> NTSTATUS {
        return syscall(XORSTR("NtCreateThread"), ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateSuspended);
    }

    inline auto NtDelayExecutionRaw(const BOOLEAN Alertable, const LARGE_INTEGER* Interval) -> NTSTATUS {
        return syscall("NtDelayExecution", Alertable, Interval);
    }

    template<typename Rep, typename Period>
    auto NtDelayExecution(const BOOLEAN Alertable, std::chrono::duration<Rep, Period> duration) -> NTSTATUS {
        constexpr int64_t hundred_ns_per_second = 10'000'000;
        const auto duration_in_100ns = -std::chrono::duration_cast<std::chrono::duration<int64_t, std::ratio<1, hundred_ns_per_second>>>(duration).count();
        LARGE_INTEGER interval;
        interval.QuadPart = duration_in_100ns;
        return NtDelayExecutionRaw(Alertable, &interval);
    }

    inline auto NtTerminateProcess(const HANDLE ProcessHandle, const NTSTATUS ExitStatus) -> NTSTATUS {
        return syscall(XORSTR("NtTerminateProcess"), ProcessHandle, ExitStatus);
    }

    inline auto NtProtectVirtualMemory(const HANDLE ProcessHandle, PVOID* BaseAddress, const PSIZE_T RegionSize, const ULONG NewProtect, const PULONG OldProtect) -> NTSTATUS {
        return syscall(XORSTR("NtProtectVirtualMemory"), ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }

    enum MEMORY_INFORMATION_CLASS {
        MemoryBasicInformation,
        // q: MEMORY_BASIC_INFORMATION
        MemoryWorkingSetInformation,
        // q: MEMORY_WORKING_SET_INFORMATION
        MemoryMappedFilenameInformation,
        // q: UNICODE_STRING
        MemoryRegionInformation,
        // q: MEMORY_REGION_INFORMATION
        MemoryWorkingSetExInformation,
        // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
        MemorySharedCommitInformation,
        // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
        MemoryImageInformation,
        // q: MEMORY_IMAGE_INFORMATION
        MemoryRegionInformationEx,
        // q: MEMORY_REGION_INFORMATION
        MemoryPrivilegedBasicInformation,
        // q: MEMORY_BASIC_INFORMATION
        MemoryEnclaveImageInformation,
        // q: MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
        MemoryBasicInformationCapped,
        // q: 10
        MemoryPhysicalContiguityInformation,
        // q: MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
        MemoryBadInformation,
        // q: since WIN11
        MemoryBadInformationAllProcesses,
        // qs: not implemented // since 22H1
        MemoryImageExtensionInformation,
        // q: MEMORY_IMAGE_EXTENSION_INFORMATION // since 24H2
        MaxMemoryInfoClass
    };

    inline auto NtQueryVirtualMemory(const HANDLE ProcessHandle,
                                     const PVOID BaseAddress,
                                     const MEMORY_INFORMATION_CLASS MemoryInformationClass,
                                     const PVOID MemoryInformation,
                                     const SIZE_T MemoryInformationLength,
                                     const PSIZE_T ReturnLength) -> NTSTATUS {
        return syscall(XORSTR("NtQueryVirtualMemory"), ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
    }

    inline auto NtReadVirtualMemory(const HANDLE ProcessHandle, const PVOID BaseAddress, const PVOID Buffer, const SIZE_T NumberOfBytesToRead, const PSIZE_T NumberOfBytesRead) -> NTSTATUS {
        return syscall(XORSTR("NtReadVirtualMemory"), ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    }

    inline auto NtWriteVirtualMemory(const HANDLE ProcessHandle, const PVOID BaseAddress, const void* Buffer, const SIZE_T NumberOfBytesToWrite, const PSIZE_T NumberOfBytesWritten) -> NTSTATUS {
        return syscall(XORSTR("NtWriteVirtualMemory"), ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    }

    inline auto NtAllocateVirtualMemory(const HANDLE ProcessHandle,
                                        PVOID* BaseAddress,
                                        const ULONG_PTR ZeroBits,
                                        const PSIZE_T RegionSize,
                                        const ULONG AllocationType,
                                        const ULONG Protect) -> NTSTATUS {
        return syscall(XORSTR("NtAllocateVirtualMemory"), ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }

    inline auto NtFreeVirtualMemory(const HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* RegionSize, const ULONG FreeType) -> NTSTATUS {
        return syscall(XORSTR("NtFreeVirtualMemory"), ProcessHandle, BaseAddress, RegionSize, FreeType);
    }

    inline auto NtClose(const HANDLE _handle) -> NTSTATUS {
        return syscall(XORSTR("NtClose"), _handle);
    }
}
