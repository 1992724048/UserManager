#pragma once
#include <string>
#include <sstream>
#include <filesystem>
#include <iostream>
#include <expected>
#include <random>

#include <Windows.h>

#include <llvm/Support/InitLLVM.h>
#include <llvm/Support/TargetSelect.h>
#include "llvm/Config/llvm-config.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/Registry.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/Core.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h"
#include "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/ExecutionEngine/Orc/ThreadSafeModule.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Error.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/StandardInstrumentations.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/IR/PassManager.h"
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/Interpreter.h>
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/RandomNumberGenerator.h"

#include <magic_enum/magic_enum_all.hpp>
#include <utility>
#include <parallel_hashmap/phmap.h>

#include <themida/SecureEngineMacros.h>
#include <themida/SecureEngineCustomVMsMacros.h>

#include "NoPageMemory.h"
#include "encrypt.h"
#include "thread_pool.hpp"
#include "xorstr.h"
#include "tbb/tbb.h"

auto init_llvm() -> void;

class Plugin {
public:
    Plugin() = default;
    virtual ~Plugin() = default;

    /**
     * @brief 添加模块回调
     * @param _m 模块指针
     */
    virtual auto on_add_module(std::unique_ptr<llvm::Module>& _m) -> void;
};

class JIT final {
public:
    JIT();
    ~JIT();

    /**
     * @brief 解析 .ll 数据内容
     * @param _ir_code LL数据内容
     */
    auto parse(const std::string& _ir_code) -> void;
    /**
     * @brief 解析.bc 数据内容
     * @param _ir_code BC数据
     */
    auto parse(const std::vector<std::uint8_t>& _ir_code) -> void;
    /**
     * @brief 锁定分配内存页面
     */
    auto lock_page() -> void;
    /**
     * @brief 校验内存区域
     */
    auto verify() -> void;

    /**
     * @brief 获取函数地址
     * @tparam FuncPtr 函数定义
     * @param _name 函数名称
     * @return 函数指针
     */
    template<typename FuncPtr>
    [[nodiscard]] auto lookup(const std::string_view _name) const -> FuncPtr {
        static_assert(std::is_function_v<std::remove_pointer_t<FuncPtr>>, "FuncPtr must be a function pointer");
        llvm::Expected<llvm::orc::ExecutorAddr> sym = jit->lookup(_name);
        llvm::cantFail(sym.takeError(), XORSTR("[JIT] lookup failed"));
        return reinterpret_cast<FuncPtr>(sym->getValue());
    }

    /**
     * @brief 添加插件
     * @tparam T 插件指针
     */
    template<typename T> requires std::is_base_of_v<Plugin, T>
    auto add_plugin() -> void {
        plugins.push_back(std::make_unique<T>());
    }

    /**
     * @brief 获取添加的插件指针
     * @tparam T 插件类
     * @return 插件指针
     */
    template<typename T> requires std::is_base_of_v<Plugin, T>
    auto get_plugin() -> std::shared_ptr<T> {
        for (const auto& plugin : plugins) {
            if (auto* derived = dynamic_cast<T*>(plugin.get())) {
                return std::static_pointer_cast<T>(plugin);
            }
        }
        return nullptr;
    }

    /**
     * @brief 添加解析后的IR模块
     * @param _m 模块指针
     */
    auto add_module(std::unique_ptr<llvm::Module> _m) const -> void;
    /**
     * @brief 添加动态库符号 (.dll)
     * @param _path 动态库路径
     */
    auto add_dynamic_library(const std::filesystem::path& _path) const -> void;
    /**
     * @brief 添加静态库符号 (.lib、.o、.a)
     * @param _path 静态库路径
     */
    auto add_static_library(const std::filesystem::path& _path) const -> void;

    /**
     * @brief 将模块IR输出到.ll文件中
     * @param _module 模块指针
     * @param _filename 输出文件名称
     */
    static auto dump_module_to_file(const std::unique_ptr<llvm::Module>& _module, const std::string& _filename) -> void;

private:
    struct SyncPair {
        bool done;
        std::unique_ptr<std::mutex> mtx;
        std::unique_ptr<std::condition_variable> cv;

        SyncPair() : done(false), mtx(std::make_unique<std::mutex>()), cv(std::make_unique<std::condition_variable>()) {}
    };

    std::unique_ptr<llvm::orc::LLJIT> jit;
    llvm::LLVMContext ctx;
    llvm::ExitOnError exit_on_error;
    std::vector<std::unique_ptr<Plugin>> plugins;
    inline static util::SafeMap<void*, SyncPair> re_mmap;

    /**
     * @brief 映射节句柄
     */
    HANDLE section_handle = nullptr;
    /**
     * @brief ZIP CRC32校验
     */
    NoPageMemory<std::uint32_t> crc;
    /**
     * @brief ZIP后数据
     */
    std::vector<std::uint8_t> zip;
    /**
     * @brief AES加密
     */
    encrypt::AES aes;

    static auto initialize() -> void;
    static auto WINAPI vectored_exception_handler(PEXCEPTION_POINTERS _ep) -> LONG;
    friend auto init_llvm() -> void;
};
