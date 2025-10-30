#pragma once
#include <atomic>
#include <Windows.h>
#include <thread>
#include <format>

#include <themida/SecureEngineMacros.h>
#include <themida/SecureEngineCustomVMsMacros.h>

#include "SDK.h"
#include "encrypt.h"
#include "ipp.h"
#include "minhook/MinHook.h"
#include "jit.hpp"
#include "ntcall.h"
#include "xorstr.h"
#include "util.h"

class Main {
public:
    Main();

    ~Main();

    /**
     * @brief 获取Main单例
     * @return 单例引用
     */
    static auto instance() -> Main& ;

    /**
     * @brief 开始运行
     */
    auto run() -> void;

    /**
     * @brief 关闭程序
     */
    auto close() -> void;

    /**
     * @brief 获取主jit
     * @return jit指针
     */
    auto get_main_jit() -> std::unique_ptr<JIT>&;
    /**
     * @brief 添加jit
     * @param _jit jit指针
     */
    auto add_jit(std::unique_ptr<JIT>& _jit) -> void ;

private:
    std::unique_ptr<JIT> jit;
    std::vector<std::unique_ptr<JIT>> user_jit;

    std::atomic<bool> exit_flag{ false };

    std::thread th_check_code;
    std::thread th_check_time;
    std::thread th_jit_check;

    auto init_jit() -> void ;
    auto init_thread() -> void ;
    static auto init_hook() -> void ;

    auto jit_check() const -> void ;
    auto check_time() const -> void ;
    auto check_code() const -> void ;
};
