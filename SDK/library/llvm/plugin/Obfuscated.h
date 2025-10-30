#pragma once
#include "jit.hpp"

class Obfuscated final : public Plugin {
    bool random_asm{ true };
    int random_asm_max{ 32 };
    int random_asm_min{ 16 };
    int random_bytes_max{ 32 };
    int random_bytes_min{ 16 };

    bool ontrol_flow{ true };

public:
    auto on_add_module(std::unique_ptr<llvm::Module>& _m) -> void override;

private:
    auto insert_random_asm(const std::unique_ptr<llvm::Module>& _m) const -> void;
    [[nodiscard]] auto generate_random_bytes() const -> std::string;
    [[nodiscard]] auto generate_random_asm() const -> std::string;

    static auto control_flow_flattening(const std::unique_ptr<llvm::Module>& _m) -> void;
};
