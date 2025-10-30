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

auto Obfuscated::control_flow_flattening(const std::unique_ptr<llvm::Module>& _m) -> void {
    using namespace llvm;

    std::vector<Function*> funcs;
    funcs.reserve(_m->size());

    // 收集所有非声明函数
    for (Function& f : *_m) {
        if (f.isDeclaration() || f.empty()) {
            continue;
        }
        funcs.push_back(&f);
    }

    LLVMContext& ctx = _m->getContext();

    for (Function* func : funcs) {
        // 跳过太小或只有一个基本块的函数
        if (func->size() < 2) {
            continue;
        }

        IRBuilder<> builder(ctx);

        // 创建新的 entry 块
        BasicBlock* oldEntry = &func->getEntryBlock();
        BasicBlock* newEntry = BasicBlock::Create(ctx, "entry_flat", func, oldEntry);

        // 创建循环块和分发块
        BasicBlock* loopBB = BasicBlock::Create(ctx, "loop_flat", func);
        BasicBlock* endBB = BasicBlock::Create(ctx, "end_flat", func);

        // 插入状态变量 (i32)
        builder.SetInsertPoint(newEntry);
        AllocaInst* stateVar = builder.CreateAlloca(builder.getInt32Ty(), nullptr, "state");
        builder.CreateStore(builder.getInt32(0), stateVar);
        builder.CreateBr(loopBB);

        // 插入 loop 体
        builder.SetInsertPoint(loopBB);
        LoadInst* stateVal = builder.CreateLoad(builder.getInt32Ty(), stateVar, "state_val");
        SwitchInst* switchInst = builder.CreateSwitch(stateVal, endBB, func->size());

        // 将原始基本块编号
        std::vector<BasicBlock*> origBlocks;
        for (BasicBlock& bb : *func) {
            if (&bb == newEntry || &bb == loopBB || &bb == endBB) {
                continue;
            }
            origBlocks.push_back(&bb);
        }

        // 建立映射：基本块 -> 状态值
        std::unordered_map<BasicBlock*, int> block_index;
        for (size_t i = 0; i < origBlocks.size(); ++i) {
            block_index[origBlocks[i]] = static_cast<int>(i);
        }

        // 把原始入口块的跳转指向 loopBB
        builder.SetInsertPoint(oldEntry);
        builder.CreateStore(builder.getInt32(block_index[oldEntry]), stateVar);
        builder.CreateBr(loopBB);

        // 处理每个基本块，修改其 terminator
        for (BasicBlock* bb : origBlocks) {
            if (auto* term = bb->getTerminator()) {
                builder.SetInsertPoint(term);

                if (auto* br = dyn_cast<BranchInst>(term)) {
                    if (br->isUnconditional()) {
                        BasicBlock* succ = br->getSuccessor(0);
                        builder.CreateStore(builder.getInt32(block_index[succ]), stateVar);
                        builder.CreateBr(loopBB);
                        term->eraseFromParent();
                    }
                    else if (br->isConditional()) {
                        BasicBlock* tSucc = br->getSuccessor(0);
                        BasicBlock* fSucc = br->getSuccessor(1);

                        // 插入条件跳转
                        Value* cond = br->getCondition();
                        BasicBlock* tBlock = BasicBlock::Create(ctx, "true_flat", func);
                        BasicBlock* fBlock = BasicBlock::Create(ctx, "false_flat", func);

                        // True path
                        IRBuilder<> tBuilder(tBlock);
                        tBuilder.CreateStore(builder.getInt32(block_index[tSucc]), stateVar);
                        tBuilder.CreateBr(loopBB);

                        // False path
                        IRBuilder<> fBuilder(fBlock);
                        fBuilder.CreateStore(builder.getInt32(block_index[fSucc]), stateVar);
                        fBuilder.CreateBr(loopBB);

                        builder.CreateCondBr(cond, tBlock, fBlock);
                        term->eraseFromParent();
                    }
                }
            }
        }

        // 添加 case 分支
        for (auto& [bb, idx] : block_index) {
            switchInst->addCase(builder.getInt32(idx), bb);
        }

        // End block
        builder.SetInsertPoint(endBB);
        builder.CreateRetVoid();
    }
}
