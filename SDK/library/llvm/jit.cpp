#include "jit.hpp"
#include "zlib/zip.h"
#include "ntcall.h"

auto init_llvm() -> void {
    LLVMInitializeX86AsmParser();
    LLVMInitializeX86AsmPrinter();
    LLVMInitializeX86Disassembler();
    LLVMInitializeX86Target();
    LLVMInitializeX86TargetInfo();
    LLVMInitializeX86TargetMC();
    LLVMInitializeX86TargetMCA();
    llvm::sys::DynamicLibrary::LoadLibraryPermanently(nullptr);
    JIT::initialize();
}

auto Plugin::on_add_module(std::unique_ptr<llvm::Module>& _m) -> void {}

JIT::JIT() {
    auto jtmb = cantFail(llvm::orc::JITTargetMachineBuilder::detectHost());

    jtmb.setCPU(XORSTR("generic"));
    jtmb.addFeatures({XORSTR("+avx2")});

    auto dl = llvm::cantFail(jtmb.getDefaultDataLayoutForTarget());
    llvm::orc::LLJITBuilder builder;
    builder.setDataLayout(dl).setJITTargetMachineBuilder(std::move(jtmb));

    jit = llvm::cantFail(builder.create());
}

JIT::~JIT() = default;

auto JIT::parse(const std::string& _ir_code) -> void {
    llvm::SMDiagnostic err;
    const llvm::MemoryBufferRef buf(_ir_code, XORSTR("<string>"));
    auto m = parseIR(buf, err, ctx);
    if (!m) {
        std::string msg;
        llvm::raw_string_ostream os(msg);
        err.print(XORSTR("JIT"), os);
        throw std::runtime_error(os.str());
    }
    add_module(std::move(m));
}

auto JIT::parse(const std::vector<std::uint8_t>& _ir_code) -> void {
    const llvm::MemoryBufferRef buf(llvm::StringRef(reinterpret_cast<const char*>(_ir_code.data()), _ir_code.size()), "<bitcode>");
    auto m = cantFail(llvm::parseBitcodeFile(buf, ctx));
    add_module(std::move(m));
}

auto JIT::lock_page() -> void {
    const auto start = lookup<int(*)()>(XORSTR("start_address"));
    std::ostringstream oss;

    SIZE_T return_size = 0;
    MEMORY_BASIC_INFORMATION memory_info{};
    NTSTATUS status = sys::NtQueryVirtualMemory(GetCurrentProcess(), start, sys::MemoryBasicInformation, &memory_info, sizeof(MEMORY_BASIC_INFORMATION), &return_size);
    if (status != 0) {
        oss << XORSTR("[JIT] NtQueryVirtualMemory failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    LARGE_INTEGER maximum_size;
    maximum_size.QuadPart = memory_info.RegionSize;
    OBJECT_ATTRIBUTES obj;
    InitializeObjectAttributes(&obj, nullptr, 0, nullptr, nullptr);
    status = sys::NtCreateSection(&section_handle, SECTION_ALL_ACCESS, &obj, &maximum_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
    if (status != 0) {
        oss << XORSTR("[JIT] NtCreateSection failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    PVOID base_address = nullptr;
    SIZE_T view_size = memory_info.RegionSize;
    LARGE_INTEGER offset_size;
    offset_size.QuadPart = 0;
    status = sys::NtMapViewOfSection(section_handle, GetCurrentProcess(), &base_address, 0, 0, &offset_size, &view_size, sys::ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        oss << XORSTR("[JIT] NtMapViewOfSection failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    std::memcpy(base_address, memory_info.BaseAddress, memory_info.RegionSize);

    status = sys::NtUnmapViewOfSection(GetCurrentProcess(), base_address);
    if (status != 0) {
        oss << XORSTR("[JIT] NtUnmapViewOfSection failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    status = sys::NtFreeVirtualMemory(GetCurrentProcess(), &memory_info.BaseAddress, &memory_info.RegionSize, MEM_RELEASE);
    if (status != 0) {
        oss << XORSTR("[JIT] NtVirtualFree failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    base_address = memory_info.BaseAddress;
    status = sys::NtMapViewOfSection(section_handle, GetCurrentProcess(), &base_address, 0, memory_info.RegionSize, &offset_size, &view_size, sys::ViewUnmap, 0, PAGE_EXECUTE_READ);
    if (status != 0) {
        oss << XORSTR("[JIT] Re NtMapViewOfSection failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    std::vector<std::uint8_t> data(memory_info.RegionSize);
    std::memcpy(data.data(), base_address, data.size());

    aes.key_generate();
    zip = ZipWrapper::compress(data);
    crc = encrypt::CRC32::compute(zip);
    zip = aes.encrypt(zip);
}

auto JIT::verify() -> void {
    const auto start = lookup<int(*)()>(XORSTR("start_address"));

    SIZE_T return_size = 0;
    MEMORY_BASIC_INFORMATION memory_info{};
    NTSTATUS status = sys::NtQueryVirtualMemory(GetCurrentProcess(), start, sys::MemoryBasicInformation, &memory_info, sizeof(MEMORY_BASIC_INFORMATION), &return_size);
    if (status != 0) {
        std::ostringstream oss;
        oss << XORSTR("[JIT] NtQueryVirtualMemory failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    std::vector<std::uint8_t> data = aes.decrypt(zip);
    if (crc != encrypt::CRC32::compute(data)) {
        std::thread(std::terminate).detach();
    }

    data = ZipWrapper::decompress(data);
    if (!std::memcmp(data.data(), memory_info.BaseAddress, data.size())) {
        return;
    }

    auto& [done, mutex, cv] = re_mmap[memory_info.BaseAddress];
    std::unique_lock lock(*mutex);
    done = false;

    std::ostringstream oss;
    status = sys::NtUnmapViewOfSection(GetCurrentProcess(), memory_info.BaseAddress);
    if (status != 0) {
        oss << XORSTR("[JIT] NtUnmapViewOfSection failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    SIZE_T view_size = memory_info.RegionSize;
    LARGE_INTEGER offset_size;
    offset_size.QuadPart = 0;
    status = sys::NtMapViewOfSection(section_handle, GetCurrentProcess(), &memory_info.BaseAddress, 0, 0, &offset_size, &view_size, sys::ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        oss << XORSTR("[JIT] NtMapViewOfSection failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    std::memcpy(memory_info.BaseAddress, data.data(), data.size());
    status = sys::NtUnmapViewOfSection(GetCurrentProcess(), memory_info.BaseAddress);
    if (status != 0) {
        oss << XORSTR("[JIT] NtUnmapViewOfSection failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    status = sys::NtMapViewOfSection(section_handle, GetCurrentProcess(), &memory_info.BaseAddress, 0, 0, &offset_size, &view_size, sys::ViewUnmap, 0, PAGE_EXECUTE_READ);
    if (status != 0) {
        oss << XORSTR("[JIT] NtMapViewOfSection failed : ") << std::hex << status;
        throw std::runtime_error(oss.str());
    }

    done = true;
    cv->notify_one();
}

auto JIT::add_module(std::unique_ptr<llvm::Module> _m) const -> void {
    if (verifyModule(*_m, &llvm::errs())) {
        llvm::report_fatal_error(XORSTR("Broken module!"));
    }

    for (auto& f : _m->functions()) {
        f.addFnAttr(XORSTR("target-features"), XORSTR("+avx2"));
    }

    for (const auto& plugin : plugins) {
        plugin->on_add_module(_m);
    }

    llvm::orc::ThreadSafeModule tsm(std::move(_m), std::make_unique<llvm::LLVMContext>());
    llvm::cantFail(jit->addIRModule(std::move(tsm)));
}

auto JIT::add_dynamic_library(const std::filesystem::path& _path) const -> void {
    if (!exists(_path)) {
        llvm::errs() << XORSTR("Dynamic library not found: ") << _path.string() << "\n";
        return;
    }

    auto& jd = jit->getMainJITDylib();
    auto dylib = cantFail(llvm::orc::DynamicLibrarySearchGenerator::Load(_path.string().data(), jit->getDataLayout().getGlobalPrefix()));
    jd.addGenerator(std::move(dylib));
}

auto JIT::add_static_library(const std::filesystem::path& _path) const -> void {
    if (!exists(_path)) {
        llvm::errs() << XORSTR("Static library not found: ") << _path.string() << "\n";
        return;
    }

    const auto buffer = exit_on_error(llvm::errorOrToExpected(llvm::MemoryBuffer::getFile(_path.string())));
    auto archive_or_err = llvm::object::Archive::create(*buffer);
    const llvm::object::Archive& archive = **archive_or_err;

    auto err = llvm::Error::success();
    for (const auto& child : archive.children(err)) {
        auto child_buffer_or_err = child.getMemoryBufferRef();
        if (!child_buffer_or_err) {
            consumeError(child_buffer_or_err.takeError());
            continue;
        }

        auto buffer_ref = *child_buffer_or_err;
        auto owned_buf = llvm::MemoryBuffer::getMemBufferCopy(buffer_ref.getBuffer(), buffer_ref.getBufferIdentifier());
        auto obj_or_err = llvm::object::ObjectFile::createObjectFile(owned_buf->getMemBufferRef());
        if (!obj_or_err) {
            consumeError(obj_or_err.takeError());
            continue;
        }

        exit_on_error(jit->addObjectFile(std::move(owned_buf)));
    }
}

auto JIT::dump_module_to_file(const std::unique_ptr<llvm::Module>& _module, const std::string& _filename) -> void {
    std::error_code ec;
    llvm::raw_fd_ostream out(_filename, ec, llvm::sys::fs::OF_Text);
    if (ec) {
        llvm::errs() << "Error opening file " << _filename << ": " << ec.message() << "\n";
        return;
    }

    _module->print(out, nullptr);
    out.close();
}

auto JIT::initialize() -> void {
    AddVectoredExceptionHandler(1, vectored_exception_handler);
}

auto JIT::vectored_exception_handler(const PEXCEPTION_POINTERS _ep) -> LONG {
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
        case EXCEPTION_ACCESS_VIOLATION: {
            if (re_mmap.empty()) {
                break;
            }

            SIZE_T return_size = 0;
            MEMORY_BASIC_INFORMATION memory_info{};
            const NTSTATUS status = sys::NtQueryVirtualMemory(GetCurrentProcess(),
                                                        reinterpret_cast<void*>(_ep->ContextRecord->Rip),
                                                        sys::MemoryBasicInformation,
                                                        &memory_info,
                                                        sizeof(MEMORY_BASIC_INFORMATION),
                                                        &return_size);
            if (status != 0) {
                std::ostringstream oss;
                oss << XORSTR("[VEH] NtQueryVirtualMemory failed : ") << std::hex << status;
                throw std::runtime_error(oss.str());
            }

            if (re_mmap.contains(memory_info.BaseAddress)) {
                auto& [done, mutex, cv] = re_mmap[memory_info.BaseAddress];
                std::unique_lock lock(*mutex);
                cv->wait(lock, [&] { return done; });
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            break;
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
