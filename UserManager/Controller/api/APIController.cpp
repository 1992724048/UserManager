#include "APIController.h"

APIController::APIController() {
    apis["APIController::timestamp"] = {
        .name = "APIController::timestamp",
        .note = "服务器时间戳",
        .url = "/api/timestamp",
        .method = "GET",
        .type = httplib::ALL,
        .desc = "API",
        .params = {
            {
                .name = "timestamp",
                .type = "int",
                .required = false,
                .desc = "时间戳"
            }
        }
    };

    apis["APIController::ip"] = {
        .name = "APIController::ip",
        .note = "获取访问者IP",
        .url = "/api/ip",
        .method = "GET",
        .type = httplib::ALL,
        .desc = "API",
        .params = {
            {
                .name = "ip",
                .type = "string",
                .required = false,
                .desc = "访问者IP"
            },
            {
                .name = "port",
                .type = "int",
                .required = false,
                .desc = "访问者端口"
            }
        }
    };

    apis["APIController::info"] = {
        .name = "APIController::info",
        .note = "获取系统信息",
        .url = "/api/info",
        .method = "GET",
        .type = httplib::COOKIE,
        .desc = "API",
        .params = {
            {
                .name = "cpu",
                .type = "string",
                .required = false,
                .desc = "CPU使用率"
            },
            {
                .name = "memory",
                .type = "string",
                .required = false,
                .desc = "内存使用率"
            },
            {
                .name = "disk",
                .type = "string",
                .required = false,
                .desc = "磁盘使用率"
            },
            {
                .name = "network",
                .type = "string",
                .required = false,
                .desc = "网络使用率"
            }
        }
    };

    apis["APIController::get_all"] = {
        .name = "APIController::get_all",
        .note = "获取所有接口",
        .url = "/api/get_all",
        .method = "GET",
        .type = httplib::COOKIE,
        .desc = "API",
        .params = {
            {
                .name = "data",
                .type = "array",
                .required = false,
                .desc = "接口数据"
            }
        }
    };

    apis["APIController::set_api"] = {
        .name = "APIController::set_api",
        .note = "设置接口",
        .url = "/api/set_api",
        .method = "POST",
        .type = httplib::COOKIE,
        .desc = "API",
        .params = {
            {
                .name = "name",
                .type = "string",
                .required = true,
                .desc = "接口名称"
            },
            {
                .name = "type",
                .type = "string",
                .required = true,
                .desc = "接口类型"
            }
        }
    };

    apis["APIController::get_doc"] = {
        .name = "APIController::get_doc",
        .note = "获取接口文档",
        .url = "/api/get_doc",
        .method = "POST",
        .type = httplib::COOKIE,
        .desc = "API",
        .params = {
            {
                .name = "data",
                .type = "object",
                .required = false,
                .desc = "接口文档"
            }
        }
    };
}

auto APIController::timestamp(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json;
    json["timestamp"] = duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    res.set_content(json.dump(), "application/json");
}

auto APIController::ip(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json;
    json["ip"] = req.remote_addr;
    json["port"] = req.remote_port;
    res.set_content(json.dump(), "application/json");
}

auto APIController::info(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json;
    PDH_HQUERY query = nullptr;
    PDH_HCOUNTER cpuTotalCounter = nullptr;
    std::vector<PDH_HCOUNTER> cpuCoreCounters;
    PDH_HCOUNTER memAvailableCounter = nullptr;
    PDH_HCOUNTER diskReadCounter = nullptr;
    PDH_HCOUNTER diskWriteCounter = nullptr;
    PDH_HCOUNTER netRecvCounter = nullptr;
    PDH_HCOUNTER netSendCounter = nullptr;

    PDH_STATUS status = PdhOpenQuery(nullptr, 0, &query);
    if (status != ERROR_SUCCESS) {
        LOG_ERROR << "PdhOpenQuery failed";
        json["success"] = false;
        json["message"] = "无法打开 PDH 查询";
        res.set_content(json.dump(), "application/json");
        return;
    }

    // 添加 CPU 总利用率计数器
    status = PdhAddCounter(query, TEXT("\\Processor(_Total)\\% Processor Time"), 0, &cpuTotalCounter);
    if (status != ERROR_SUCCESS) {
        LOG_ERROR << "添加 CPU 总计数器失败";
    }

    // 获取系统 CPU 核心数
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    int numCores = sysInfo.dwNumberOfProcessors;
    for (int i = 0; i < numCores; i++) {
        auto path = util::Encode::s2w(fmt::format("\\Processor({})\\% Processor Time", i));
        PDH_HCOUNTER coreCounter = nullptr;
        status = PdhAddCounter(query, path.data(), 0, &coreCounter);
        if (status == ERROR_SUCCESS) {
            cpuCoreCounters.push_back(coreCounter);
        } else {
            LOG_ERROR << "添加 CPU 核心计数器失败: Core " << i;
        }
    }

    // 内存可用计数器（单位 MB）
    status = PdhAddCounter(query, TEXT("\\Memory\\Available MBytes"), 0, &memAvailableCounter);
    if (status != ERROR_SUCCESS) {
        LOG_ERROR << "添加内存计数器失败";
    }

    // 磁盘读写计数器（针对 _Total 实例）
    status = PdhAddCounter(query, TEXT("\\PhysicalDisk(_Total)\\Disk Read Bytes/sec"), 0, &diskReadCounter);
    status = PdhAddCounter(query, TEXT("\\PhysicalDisk(_Total)\\Disk Write Bytes/sec"), 0, &diskWriteCounter);

    // 网络计数器（这里简单使用第一个匹配的接口，实际可遍历所有接口）
    status = PdhAddCounter(query, TEXT("\\Network Interface(*)\\Bytes Received/sec"), 0, &netRecvCounter);
    status = PdhAddCounter(query, TEXT("\\Network Interface(*)\\Bytes Sent/sec"), 0, &netSendCounter);

    // 首次采集数据
    status = PdhCollectQueryData(query);
    if (status != ERROR_SUCCESS) {
        LOG_ERROR << "PdhCollectQueryData 第一次采集失败";
    }
    // 为保证差分计算，等待 1 秒
    std::this_thread::sleep_for(std::chrono::seconds(1));
    status = PdhCollectQueryData(query);

    PDH_FMT_COUNTERVALUE counterVal;
    // 获取 CPU 总利用率
    double cpuTotal = -1.0;
    status = PdhGetFormattedCounterValue(cpuTotalCounter, PDH_FMT_DOUBLE, nullptr, &counterVal);
    if (status == ERROR_SUCCESS) {
        cpuTotal = counterVal.doubleValue;
    }

    // 获取每核心 CPU 利用率
    std::vector<double> cpuPerCore;
    for (auto counter : cpuCoreCounters) {
        status = PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, nullptr, &counterVal);
        double usage = (status == ERROR_SUCCESS) ? counterVal.doubleValue : -1.0;
        cpuPerCore.push_back(usage);
    }

    // 获取内存可用量（MB）
    double memAvailableMB = -1.0;
    status = PdhGetFormattedCounterValue(memAvailableCounter, PDH_FMT_DOUBLE, nullptr, &counterVal);
    if (status == ERROR_SUCCESS) {
        memAvailableMB = counterVal.doubleValue;
    }
    // 通过 GlobalMemoryStatusEx 获取总物理内存
    MEMORYSTATUSEX memStatus = {
        0
    };
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    double totalMemoryMB = memStatus.ullTotalPhys / (1024.0 * 1024.0);
    double usedMemoryMB = totalMemoryMB - memAvailableMB;

    // 获取磁盘读写速率
    double diskReadBytes = -1.0, diskWriteBytes = -1.0;
    status = PdhGetFormattedCounterValue(diskReadCounter, PDH_FMT_DOUBLE, nullptr, &counterVal);
    if (status == ERROR_SUCCESS) {
        diskReadBytes = counterVal.doubleValue;
    }
    status = PdhGetFormattedCounterValue(diskWriteCounter, PDH_FMT_DOUBLE, nullptr, &counterVal);
    if (status == ERROR_SUCCESS) {
        diskWriteBytes = counterVal.doubleValue;
    }
    // 获取磁盘空间信息（这里只演示 C: 盘）
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    BOOL diskResult = GetDiskFreeSpaceEx(TEXT("C:\\"), &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes);

    // 获取网络收发速率
    double netRecvBytes = -1.0, netSendBytes = -1.0;
    status = PdhGetFormattedCounterValue(netRecvCounter, PDH_FMT_DOUBLE, nullptr, &counterVal);
    if (status == ERROR_SUCCESS) {
        netRecvBytes = counterVal.doubleValue;
    }
    status = PdhGetFormattedCounterValue(netSendCounter, PDH_FMT_DOUBLE, nullptr, &counterVal);
    if (status == ERROR_SUCCESS) {
        netSendBytes = counterVal.doubleValue;
    }

    // 整理 JSON 数据
    json["success"] = true;
    json["cpu"]["total"] = cpuTotal;
    json["cpu"]["perCore"] = cpuPerCore;

    json["memory"]["totalMB"] = totalMemoryMB;
    json["memory"]["usedMB"] = usedMemoryMB;
    json["memory"]["availableMB"] = memAvailableMB;

    if (diskResult) {
        json["disk"]["totalBytes"] = static_cast<double>(totalNumberOfBytes.QuadPart);
        json["disk"]["freeBytes"] = static_cast<double>(totalNumberOfFreeBytes.QuadPart);
    } else {
        json["disk"]["totalBytes"] = -1;
        json["disk"]["freeBytes"] = -1;
    }
    json["disk"]["readBytesPerSec"] = diskReadBytes;
    json["disk"]["writeBytesPerSec"] = diskWriteBytes;

    json["network"]["recvBytesPerSec"] = netRecvBytes;
    json["network"]["sendBytesPerSec"] = netSendBytes;

    // 关闭 PDH 查询
    PdhCloseQuery(query);

    res.set_content(json.dump(), "application/json");
}

auto APIController::get_all(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json;
    try {
        for (const auto& [fst, snd] : controllers) {
            json["data"][snd.group].push_back({
                {
                    "group",
                    snd.group
                },
                {
                    "name",
                    fst
                },
                {
                    "url",
                    snd.url_path
                },
                {
                    "note",
                    snd.note
                },
                {
                    "type",
                    snd.request
                }
            });
        }

        json["success"] = true;
        json["message"] = "获取接口数据成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("获取接口数据失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto APIController::set_api(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string name = json["name"];
        const httplib::HttpRequest type = json["type"];
        json.clear();

        save(type, name);

        json["success"] = true;
        json["message"] = "设置接口数据成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("设置接口数据失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto APIController::get_doc(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string name = json["name"];
        json.clear();
        if (apis.contains(name)) {
            json["data"] = apis[name];
        } else {
            throw std::runtime_error("接口没有文档!");
        }

        json["success"] = true;
        json["message"] = "获取接口数据成功!";
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("获取接口数据失败!") + exception.what();
    }
    res.set_content(json.dump(), "application/json");
}

auto APIController::command(const httplib::Request& req, httplib::Response& res) -> void {
    try {
        // 解析请求体中的 JSON 数据
        auto data = nlohmann::json::parse(req.body);
        const std::string command = data["command"];
        // 拼接调用 PowerShell 的完整命令
        const std::string fullCommand = "powershell -Command \"" + command + "\"";

        // 执行命令并获取输出管道
        FILE* pipe = _popen(fullCommand.c_str(), "r");
        if (!pipe) {
            throw std::runtime_error("Failed to run command");
        }

        // 设置响应头，指定流式传输内容类型（纯文本）
        res.set_header("Content-Type", "text/plain");

        // 使用 chunked_content_provider 以流式传输方式返回输出
        // 注意：这里使用 static 缓冲区在 lambda 内部进行数据读取
        res.set_chunked_content_provider("text/plain",
                                         [pipe](size_t offset, httplib::DataSink& sink) mutable -> bool {
                                             static char buffer[128]; // static 缓冲区
                                             // 尝试读取新的数据块
                                             if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                                                 // 写入到数据流中，实时传输给客户端
                                                 sink.write(buffer, std::strlen(buffer));
                                                 return true; // 还有更多数据待发送
                                             }
                                             // 读取完毕后关闭管道
                                             int retCode = _pclose(pipe);
                                             // 如有需要，可根据 retCode 进行额外处理（例如输出错误提示）
                                             sink.done(); // 通知数据流结束
                                             return false;
                                         });
    } catch (const std::exception& e) {
        // 如果发生异常，则返回错误信息（JSON 格式）
        nlohmann::json json;
        json["success"] = false;
        json["error"] = e.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto APIController::check(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json;
    const Service& service = Service::Instance();
    try {
        for (const auto& [fst, snd] : controllers) {
            if (controllers_default.contains(fst)) {
                const httplib::HttpRequest type = controllers_default[fst].request;
                if (type != snd.request && snd.request == httplib::ALL) {
                    json["data"].push_back({
                        {
                            "name",
                            snd.note
                        },
                        {
                            "type",
                            "API"
                        },
                        {
                            "note",
                            "权限异常"
                        },
                        {
                            "suggestion",
                            "建议调整成默认权限"
                        }
                    });
                }
            }
        }

        if (service.f_max_requests > 50 && service.f_window_time <= 1) {
            json["data"].push_back({
                {
                    "name",
                    "请求频率限制"
                },
                {
                    "type",
                    "Network"
                },
                {
                    "note",
                    "频率过高"
                },
                {
                    "suggestion",
                    "建议限制单个用户每秒不超过50次请求"
                }
            });
        }

        if (service.f_username.value().size() < 8) {
            json["data"].push_back({
                {
                    "name",
                    "管理员用户名"
                },
                {
                    "type",
                    "Administrator"
                },
                {
                    "note",
                    "用户名过短"
                },
                {
                    "suggestion",
                    "建议使用至少8位字符的用户名"
                }
            });
        }

        if (service.f_password.value().size() < 8) {
            json["data"].push_back({
                {
                    "name",
                    "管理员密码"
                },
                {
                    "type",
                    "Administrator"
                },
                {
                    "note",
                    "密码过短"
                },
                {
                    "suggestion",
                    "建议使用至少8位字符的密码"
                }
            });
        }

        if (service.f_password.value().size() < 8) {
            json["data"].push_back({
                {
                    "name",
                    "管理员密码"
                },
                {
                    "type",
                    "Administrator"
                },
                {
                    "note",
                    "密码过短"
                },
                {
                    "suggestion",
                    "建议使用至少8位字符的密码"
                }
            });
        }

        bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
        const std::string special_chars = "!@#$%^&*()_+-=[]{}|;:'\",.<>/?`~";

        for (const char c : service.f_password.value()) {
            if (isupper(c)) {
                has_upper = true;
            }
            if (islower(c)) {
                has_lower = true;
            }
            if (isdigit(c)) {
                has_digit = true;
            }
            if (special_chars.find(c) != std::string::npos) {
                has_special = true;
            }
        }

        if (!has_upper) {
            json["data"].push_back({
                {
                    "name",
                    "管理员密码"
                },
                {
                    "type",
                    "Administrator"
                },
                {
                    "note",
                    "缺少大写字母"
                },
                {
                    "suggestion",
                    "建议至少包含一个A-Z的字符"
                }
            });
        }

        if (!has_lower) {
            json["data"].push_back({
                {
                    "name",
                    "管理员密码"
                },
                {
                    "type",
                    "Administrator"
                },
                {
                    "note",
                    "缺少小写字母"
                },
                {
                    "suggestion",
                    "建议至少包含一个a-z的字符"
                }
            });
        }

        if (!has_digit) {
            json["data"].push_back({
                {
                    "name",
                    "管理员密码"
                },
                {
                    "type",
                    "Administrator"
                },
                {
                    "note",
                    "缺少数字"
                },
                {
                    "suggestion",
                    "建议至少包含一个0-9的数字"
                }
            });
        }

        if (!has_special) {
            json["data"].push_back({
                {
                    "name",
                    "管理员密码"
                },
                {
                    "type",
                    "Administrator"
                },
                {
                    "note",
                    "缺少特殊符号"
                },
                {
                    "suggestion",
                    "建议至少包含一个特殊字符（如!@#$%^&*_+-等）"
                }
            });
        }

        json["success"] = true;
        json["message"] = "获取数据成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("获取数据失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}
