#include "Obfuscated.h"

#include "MiniVM/MiniVM.h"

auto Obfuscated::on_add_module(std::unique_ptr<llvm::Module>& _m) -> void {
    MUTATE_START_ASM64();
    if (ontrol_flow) {
        //control_flow_flattening(_m);
    }
    if (random_asm) {
        insert_random_asm(_m);
    }
    MUTATE_END_ASM64();
    verifyModule(*_m, &llvm::errs());
}

auto Obfuscated::insert_random_asm(const std::unique_ptr<llvm::Module>& _m) const -> void {
    for (llvm::Function& function : *_m) {
        if (function.isDeclaration() && function.empty()) {
            continue;
        }

        for (llvm::BasicBlock& bb : function) {
            if (bb.empty()) {
                continue;
            }

            for (llvm::Instruction& instruction : bb) {
                if (llvm::isa<llvm::PHINode>(instruction)) {
                    continue;
                }

                llvm::FunctionType* asm_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(bb.getContext()), false);
                llvm::InlineAsm* inline_asm = llvm::InlineAsm::get(asm_ty, generate_random_asm(), "", true, false, llvm::InlineAsm::AD_Intel);
                llvm::CallInst::Create(inline_asm, "", &instruction);
            }
        }
    }
}

auto Obfuscated::generate_random_bytes() const -> std::string {
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<size_t> num(random_bytes_min, random_bytes_max);
    std::uniform_int_distribution<size_t> byte(0, 255);

    std::ostringstream oss;
    const int count = num(rng);
    for (int i = 0; i <= count; ++i) {
        oss << XORSTR(".byte 0x") << std::hex << byte(rng) << XORSTR("\n");
    }
    return oss.str();
}

auto Obfuscated::generate_random_asm() const -> std::string {
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<size_t> num(random_asm_min, random_asm_max);

    std::ostringstream oss;
    const auto count = num(rng);
    for (int i = 0; std::cmp_less(i, count); ++i) {
        oss << XORSTR(".byte 0xD6\n");
        oss << XORSTR(".byte 0x") << std::hex << static_cast<int>(MiniVM::string_opcode[XORSTR("Nop")]) << XORSTR("\n");
        oss << XORSTR("jmp ") << std::dec << i << XORSTR("f\n");
        oss << generate_random_bytes();
        oss << std::dec << i << XORSTR(":\n");
    }
    return oss.str();
}
