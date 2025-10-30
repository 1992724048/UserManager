#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#include "MiniVM/MiniVM.h"
#include "main.h"
#include "encode.h"
#include "plugin/Obfuscated.h"

__declspec(noinline) auto check_protection() -> void {
    int check_value_protection{0};

    VM_LION_BLACK_START_ASM64();
    CHECK_PROTECTION_ASM64(&check_value_protection, 0x01);
    if (check_value_protection != 0x01) {
        std::thread(sys::NtTerminateProcess, GetCurrentProcess(), 0).detach();
        std::thread(std::terminate).detach();
    }
    VM_LION_BLACK_END_ASM64();
}

__declspec(noinline) auto check_debugger() -> void {
    int check_value_debug{0};

    VM_LION_BLACK_START_ASM64();
    CHECK_DEBUGGER_ASM64(&check_value_debug, 0x01);
    if (check_value_debug != 0x01) {
        std::thread(sys::NtTerminateProcess, GetCurrentProcess(), 0).detach();
        std::thread(std::terminate).detach();
    }
    VM_LION_BLACK_END_ASM64();
}

auto start() -> void {
    MUTATE_START_ASM64();
    auto& main = Main::instance();
    const auto& jit = main.get_main_jit();
    bool (*fn)(const char*) = nullptr;
    fn = jit->lookup<decltype(fn)>(XORSTR("check_password"));
    std::cout << Encode::utf8_to_gbk(XORSTR("[JIT] 函数地址: ")) << std::hex << reinterpret_cast<std::uintptr_t>(fn) << "\n";
    std::string pd;
    do {
        std::cout << Encode::utf8_to_gbk(XORSTR("请输入密码: "));
        std::cin >> pd;
    } while (!fn(pd.data()));
    MUTATE_END_ASM64();
}

auto APIENTRY DllMain(HMODULE _h_module, const DWORD _ul_reason_for_call, LPVOID _lp_reserved) -> BOOL try {
    MUTATE_START_ASM64();
    check_protection();
    switch (_ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            std::cout << Encode::utf8_to_gbk(XORSTR("[VER] 构建时间: ")) << BUILD_TIME << "\n";
            std::cout << Encode::utf8_to_gbk(XORSTR("[JIT] 预热中，请稍等...\n"));
            auto& main = Main::instance();
            main.run();
            break;
        }
        case DLL_THREAD_ATTACH: {
            check_debugger();
            break;
        }
        case DLL_THREAD_DETACH: {
            break;
        }
        case DLL_PROCESS_DETACH: {
            Main::instance().close();
            break;
        }
    }
    MUTATE_END_ASM64();
    return TRUE;
} catch (std::exception& exception) {
    MessageBoxA(nullptr, exception.what(), XORSTR("Exception"), MB_OK | MB_ICONERROR);
} catch (...) {
    MessageBoxW(nullptr, XORWSTR(L"未知错误"), XORWSTR(L"Exception"), MB_OK | MB_ICONERROR);
}

inline Main::Main() {
    ippInit();
    MiniVM::initialize();
    sys::build_ssn_table();
    init_llvm();
    MH_Initialize();
}

inline Main::~Main() = default;

inline auto Main::instance() -> Main& {
    static Main main;
    return main;
}

inline auto Main::run() -> void {
    init_hook();
    init_jit();
    init_thread();
}

inline auto Main::close() -> void {
    exit_flag = true;
    if (th_jit_check.joinable()) {
        th_jit_check.join();
    }
    if (th_check_code.joinable()) {
        th_check_code.join();
    }
    if (th_check_time.joinable()) {
        th_check_time.join();
    }
    MH_DisableHook(nullptr);
}

inline auto Main::get_main_jit() -> std::unique_ptr<JIT>& {
    return jit;
}

inline auto Main::add_jit(std::unique_ptr<JIT>& _jit) -> void {
    user_jit.push_back(std::move(_jit));
}

inline auto Main::init_jit() -> void {
    jit = std::make_unique<JIT>();
    jit->add_plugin<Obfuscated>();
    jit->parse(util::read_file_hex(util::app_path() / XORSTR("IR") / XORSTR("main.bc")));

    for (const auto& jit_ : user_jit) {
        jit_->add_plugin<Obfuscated>();
    }
}

inline auto Main::init_thread() -> void {
    th_check_time = std::thread(&Main::check_time, this);
    th_check_time.detach();

    th_check_code = std::thread(&Main::check_code, this);
    th_check_code.detach();

    th_jit_check = std::move(std::thread(&Main::jit_check, this));
    th_jit_check.detach();
}

inline auto Main::init_hook() -> void {
    PVOID ptr;
    const auto ntdll = sys::get_module_base(XORWSTR(L"ntdll.dll"));
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtCreateThreadEx")), sys::NtCreateThreadEx, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtCreateThread")), sys::NtCreateThread, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtCreateSectionEx")), sys::NtCreateSectionEx, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtMapViewOfSectionEx")), sys::NtMapViewOfSectionEx, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtUnmapViewOfSectionEx")), sys::NtUnmapViewOfSectionEx, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtUnmapViewOfSection")), sys::NtUnmapViewOfSection, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtMapViewOfSection")), sys::NtMapViewOfSection, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtCreateSection")), sys::NtCreateSection, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtQueryVirtualMemory")), sys::NtQueryVirtualMemory, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtClose")), sys::NtClose, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtDelayExecution")), sys::NtDelayExecutionRaw, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtWriteVirtualMemory")), sys::NtWriteVirtualMemory, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtReadVirtualMemory")), sys::NtReadVirtualMemory, &ptr);
    MH_CreateHook(sys::get_export_function(ntdll, XORSTR("NtTerminateProcess")), sys::NtTerminateProcess, &ptr);
    MH_EnableHook(nullptr);
}

inline auto Main::jit_check() const -> void {
    jit->lock_page();
    for (const auto& jit_ : user_jit) {
        jit_->lock_page();
    }

    while (!exit_flag) {
        jit->verify();
        for (const auto& jit_ : user_jit) {
            jit_->verify();
        }
        sys::NtDelayExecution(false, 1min);
    }
}

inline auto Main::check_time() const -> void {
    using Clock = std::chrono::steady_clock;
    using Seconds = std::chrono::duration<double>;
    MUTATE_START_ASM64();
    auto last = Clock::now();
    do {
        auto now = Clock::now();
        Seconds elapsed = now - last;
        last = now;

        if (elapsed.count() > 1.0) {
            std::terminate();
        }

        sys::NtDelayExecution(false, 500ms);
        MUTATE_END_ASM64();
    } while (!exit_flag);
}

inline auto Main::check_code() const -> void {
    int check_value_code{0};

    do {
        VM_LION_BLACK_START_ASM64();
        CHECK_CODE_INTEGRITY_ASM64(&check_value_code, 0x01);
        if (check_value_code != 0x01) {
            std::terminate();
        }

        sys::NtDelayExecution(false, 1min);
        VM_LION_BLACK_END_ASM64();
    } while (!exit_flag);
}
