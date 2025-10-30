#include "MiniVM.h"

static constexpr auto fnv1a_32(const std::string_view _s) noexcept -> std::uint32_t {
    std::uint32_t hash = 0x811c9dc5u;
    for (const char c : _s) {
        hash ^= static_cast<unsigned char>(c);
        hash *= 0x01000193u;
    }
    return hash;
}

static constexpr auto operator"" _h(const char* _str, std::size_t _len) noexcept -> std::uint32_t {
    return fnv1a_32({ _str, _len });
}

auto MiniVM::initialize() -> void {
    AddVectoredExceptionHandler(1, vectored_exception_handler);
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution code_rand(static_cast<int>(Opcode::Nop), static_cast<int>(Opcode::Cmp));

    for (auto& opcode : magic_enum::enum_names<Opcode>()) {
        std::uint8_t code;
        do {
            code = static_cast<std::uint8_t>(code_rand(rng));
        } while (opcode_string.contains(code));

        string_opcode[opcode] = code;
        opcode_string[code] = opcode;
    }
}

auto MiniVM::run(CONTEXT& _context) -> std::optional<CONTEXT> {
    auto rip = reinterpret_cast<std::uint8_t*>(_context.Rip);
    while (*rip == 0xD6) {
        rip++;

        if (!opcode_string.contains(*rip)) {
            break;
        }

        switch (fnv1a_32(opcode_string[*rip])) {
            case "Nop"_h:
                rip++;
                break;
            case "Jmp"_h: {
                rip++;
                _context.Rip = *reinterpret_cast<std::uintptr_t*>(rip);
                rip += sizeof(std::uintptr_t);
                break;
            }
            case "Mov"_h:
                break;
            case "Add"_h:
                break;
            case "Sub"_h:
                break;
            case "Xor"_h:
                break;
            case "Or"_h:
                break;
            case "Cmp"_h:
                break;
            default: ;
        }
    }

    _context.Rip = reinterpret_cast<std::uintptr_t>(rip);
    return _context;
}

auto MiniVM::vectored_exception_handler(const PEXCEPTION_POINTERS _ep) -> LONG {
    VM_TIGER_RED_START_ASM64();
#define REG(reg) _ep->ContextRecord->reg
    if (REG(Dr0) || REG(Dr1) || REG(Dr2) || REG(Dr3) || REG(Dr6) || REG(Dr7)) {
        std::thread(std::terminate).detach();
    }

    switch (_ep->ExceptionRecord->ExceptionCode) {
        case EXCEPTION_SINGLE_STEP: {
            std::thread(std::terminate).detach();
            break;
        }
        case EXCEPTION_ILLEGAL_INSTRUCTION: {
            const auto ret = run(*_ep->ContextRecord);
            if (!ret) {
                std::thread(std::terminate).detach();
            }
            *_ep->ContextRecord = ret.value();
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        default:
            break;
    }

    REG(Dr0) = 0;
    REG(Dr1) = 0;
    REG(Dr2) = 0;
    REG(Dr3) = 0;
    REG(Dr6) = 0;
    REG(Dr7) = 0;
    VM_TIGER_RED_END_ASM64();
    return EXCEPTION_CONTINUE_SEARCH;
}