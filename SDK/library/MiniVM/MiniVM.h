#pragma once
#include <themida/SecureEngineMacros.h>
#include <themida/SecureEngineCustomVMsMacros.h>

#include <Windows.h>
#include <thread>
#include <optional>
#include <random>
#include <string>
#include "util.h"

#include "magic_enum/magic_enum.hpp"

class MiniVM {
public:
    enum class Opcode : std::uint8_t {
        Nop,
        Jmp,
        Mov,
        Add,
        Sub,
        Xor,
        Or,
        Cmp,
    };

    inline static util::SafeMap<std::string, std::uint8_t> string_opcode;
    inline static util::SafeMap<std::uint8_t, std::string> opcode_string;

    static auto initialize() -> void;
    static auto run(CONTEXT& _context) -> std::optional<CONTEXT>;

private:
    static auto WINAPI vectored_exception_handler(PEXCEPTION_POINTERS _ep) -> LONG;
};
