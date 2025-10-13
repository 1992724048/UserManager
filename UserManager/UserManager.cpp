#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <boost/stacktrace/frame.hpp>
#include <boost/stacktrace/stacktrace.hpp>

#include "Service.h"
#include "DbgHelp.h"

#include "opencv2/opencv.hpp"
#pragma comment(lib, "dbghelp.lib")

static auto WINAPI UnhandledExceptionFilter_(const PEXCEPTION_POINTERS p_exception_info) -> LONG {
    if (p_exception_info->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS | SEM_NOALIGNMENTFAULTEXCEPT);

    char symbol_info[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {0};
    const auto p_symbol = reinterpret_cast<PSYMBOL_INFO>(symbol_info);
    p_symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    p_symbol->MaxNameLen = MAX_SYM_NAME;

    DWORD64 displacement = 0;
    if (SymFromAddr(GetCurrentProcess(), p_exception_info->ContextRecord->Rip, &displacement, p_symbol)) {
        LOG_DEBUG << "指令所属模块:" << p_symbol->Name << " 0x" << std::hex << displacement;
    }

    const std::string dump_path = (util::app_path() / "dump.dmp").string();

    LOG_DEBUG << "线程ID: " << GetCurrentThreadId() << "错误码:" << p_exception_info->ExceptionRecord->ExceptionCode;
    LOG_DEBUG << "内存转存储目录:" << dump_path;
    const std::shared_ptr<void> h_file(CreateFileA(dump_path.data(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr), CloseHandle);
    if (h_file.get() != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION dump_info;
        dump_info.ThreadId = GetCurrentThreadId();
        dump_info.ExceptionPointers = p_exception_info;
        dump_info.ClientPointers = TRUE;

        constexpr auto dump_type = static_cast<MINIDUMP_TYPE>(MiniDumpWithFullMemory | // 包含所有可访问进程内存
            MiniDumpWithHandleData | // 记录所有句柄信息
            MiniDumpWithUnloadedModules | // 包含已卸载模块信息
            MiniDumpWithProcessThreadData | // 进程/线程扩展信息
            MiniDumpWithTokenInformation | // 安全令牌信息
            MiniDumpWithThreadInfo | // 线程上下文详细信息
            MiniDumpWithFullMemoryInfo | // 内存区域元数据
            MiniDumpWithPrivateReadWriteMemory | // 私有读写内存段
            MiniDumpIgnoreInaccessibleMemory // 跳过不可访问内存防止崩溃
        );

        const BOOL stus = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), h_file.get(), dump_type, &dump_info, nullptr, nullptr);
        LOG_DEBUG << "内存转存储:" << (stus ? "成功" : "失败");
    } else {
        LOG_DEBUG << "无法创建内存转存储文件!";
    }

    LOG_CRIT << "致命错误! 程序即将退出!";
    std::this_thread::sleep_for(std::chrono::seconds(60));
    return EXCEPTION_CONTINUE_SEARCH;
}

auto main() -> int {
    SymInitialize(GetCurrentProcess(), nullptr, TRUE);
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    SymSetSearchPathW(GetCurrentProcess(), L"srv*C:\\symbols*https://msdl.microsoft.com/download/symbols");
    SetUnhandledExceptionFilter(UnhandledExceptionFilter_);
    system("chcp 65001");

    setLogLevel(cv::utils::logging::LOG_LEVEL_SILENT);
    config::Initialize(util::app_path() / "config.json");
    Logger::PrepareFileLogging(util::app_path() / "logs");

    try {
        return Service::Instance().Run();
    } catch (std::exception& exception) {
        LOG_ERROR << exception.what();
        std::this_thread::sleep_for(std::chrono::minutes(1));
        return -1;
    }
}
