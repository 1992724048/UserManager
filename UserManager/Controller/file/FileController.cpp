#include "FileController.h"

#include "chrono.h"

FileController::FileController() {
}

auto FileController::file_logic(const httplib::Request&& req, httplib::Response&& res, const bool user, const bool res_path) -> void {
    const Service& service = Service::Instance();
    const std::filesystem::path local_path = service.f_web_files / (res_path ? "res" : "pages") / (res_path ? "" : user ? "user" : "admin") / req.matches[1].data();

    std::error_code ec;
    std::filesystem::path resolved_local = canonical(local_path, ec);

    if (ec) {
        res.status = 404;
        return;
    }

    const auto base_path = canonical(service.f_web_files);
    if (!resolved_local.string().starts_with(base_path.string())) {
        res.status = 403;
        return;
    }

    if (is_directory(resolved_local)) {
        resolved_local /= "index.html";
        if (!exists(resolved_local)) {
            res.status = 404;
            return;
        }
    }

    if (!is_regular_file(resolved_local)) {
        res.status = 404;
        return;
    }

    std::string buffer;
    if (service.f_file_cache) {
        if (Service::file_cache.contains(resolved_local.string())) {
            auto& [data, read_time, size, revc_count] = Service::file_cache[resolved_local.string()];
            buffer = data;
            revc_count++;
            read_time = std::chrono::system_clock::now();
        } else if (service.file_total_size < service.f_file_cache_max_size) {
            buffer = util::ReadFile(resolved_local);
            auto& [data, read_time, size, revc_count] = Service::file_cache[resolved_local.string()];
            data = buffer;
            size = buffer.size();
            read_time = std::chrono::system_clock::now();
            revc_count = 1;
        }
    }

    if (buffer.empty()) {
        buffer = util::ReadFile(resolved_local);
    }

    const std::string ext = resolved_local.extension().string();
    const std::string mime = util::GetMIMEType(ext);

    res.set_header("Cache-Control", "public, max-age=31536000");

    if ((mime.contains("text") || mime.contains("application")) && buffer.contains("$cookie$")) {
        if (Service::CheckCookieValid(req)) {
            return res.set_content(util::replace_all(buffer, "$cookie$", ""), mime);
        }
        res.status = 401;
        return;
    }

    res.set_content(buffer, mime);
}

auto FileController::file(const httplib::Request& req, httplib::Response& res) -> void {
    return file_logic(std::move(req), std::move(res), false, false);
}

auto FileController::user_web(const httplib::Request& req, httplib::Response& res) -> void {
    visit.add(req.remote_addr);
    return file_logic(std::move(req), std::move(res), true, false);
}

auto FileController::res(const httplib::Request& req, httplib::Response& res) -> void {
    return file_logic(std::move(req), std::move(res), true, true);
}

auto FileController::logic_enum_path(const httplib::Request& req, httplib::Response& res, const bool web) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        std::string path = util::Encode::Utf8ToGbk(json["path"]);
        json.clear();

        if (!path.empty() && (path[0] == '\\' || path[0] == '/')) {
            path = path.substr(0, 1);
        }

        if (path.find("..") != std::string::npos) {
            throw std::runtime_error("非法路径访问");
        }

        const auto path_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / path;

        if (path_.lexically_relative(path_).string().find("..") != std::string::npos) {
            res.status = 403;
            throw std::runtime_error("非法路径访问");
        }

        if (path_.lexically_relative(path_).string().find("./") != std::string::npos) {
            res.status = 403;
            throw std::runtime_error("非法路径访问");
        }

        const auto base_path = canonical(path_.parent_path());
        if (!path_.string().starts_with(base_path.string())) {
            res.status = 403;
            throw std::runtime_error("非法路径访问");
        }

        json["data"] = nlohmann::json::array();
        for (const auto& [filename, size, type, is_directory, creation_time, access_time, modification_time] : util::File::list_directory(path_)) {
            json["data"].push_back({
                {
                    "filename",
                    filename
                },
                {
                    "size",
                    size
                },
                {
                    "type",
                    type
                },
                {
                    "is_directory",
                    is_directory
                },
                {
                    "creation_time",
                    creation_time
                },
                {
                    "access_time",
                    access_time
                },
                {
                    "modification_time",
                    modification_time
                }
            });
        }

        json["success"] = true;
        json["message"] = "获取文件成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json.clear();
        json["success"] = false;
        json["message"] = std::string("获取文件失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::logic_remove_file(const httplib::Request& req, httplib::Response& res, bool web) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string path = util::Encode::Utf8ToGbk(json["path"]);
        json.clear();

        const auto path_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / path;

        if (!std::filesystem::remove(path_)) {
            throw std::runtime_error("文件不存在或删除失败!");
        }

        json["success"] = true;
        json["message"] = "删除文件成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("删除文件失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::logic_remove_directory(const httplib::Request& req, httplib::Response& res, bool web) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string path = util::Encode::Utf8ToGbk(json["path"]);
        json.clear();

        const auto path_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / path;

        if (!remove_all(path_)) {
            throw std::runtime_error("目录不存在或删除失败!");
        }

        json["success"] = true;
        json["message"] = "删除目录成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("删除目录失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::logic_create_file(const httplib::Request& req, httplib::Response& res, bool web) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string path = util::Encode::Utf8ToGbk(json["path"]);
        json.clear();

        const auto path_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / path;

        std::ofstream file(path_);
        if (!file.is_open()) {
            throw std::runtime_error("文件已存在或创建失败!");
        }
        file.close();

        json["success"] = true;
        json["message"] = "创建文件成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("创建文件失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::logic_create_directory(const httplib::Request& req, httplib::Response& res, bool web) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string path = util::Encode::Utf8ToGbk(json["path"]);
        json.clear();

        const auto path_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / path;

        if (!create_directories(path_)) {
            throw std::runtime_error("目录已存在或创建失败!");
        }

        json["success"] = true;
        json["message"] = "创建目录成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("创建目录失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::logic_rename(const httplib::Request& req, httplib::Response& res, bool web) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string path = util::Encode::Utf8ToGbk(json["path"]);
        const std::string new_path = util::Encode::Utf8ToGbk(json["new_path"]);
        json.clear();

        const auto path_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / path;
        const auto path2_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / new_path;

        std::filesystem::rename(path_, path2_);

        json["success"] = true;
        json["message"] = "重命名成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("重命名失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::logic_copy(const httplib::Request& req, httplib::Response& res, bool web) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string path = util::Encode::Utf8ToGbk(json["path"]);
        const std::string new_path = util::Encode::Utf8ToGbk(json["new_path"]);
        json.clear();

        const auto path_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / path;
        const auto path2_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / new_path;

        std::filesystem::copy(path_, path2_);

        json["success"] = true;
        json["message"] = "重命名成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("重命名失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::logic_cut(const httplib::Request& req, httplib::Response& res, bool web) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string path = util::Encode::Utf8ToGbk(json["path"]);
        const std::string new_path = util::Encode::Utf8ToGbk(json["new_path"]);
        json.clear();

        const auto path_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / path;
        const auto path2_ = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / new_path;

        std::filesystem::rename(path_, path2_);

        json["success"] = true;
        json["message"] = "剪切成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("剪切失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::logic_upload(const httplib::Request& req, httplib::Response& res, bool web) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json;

    try {
        std::string current_path = req.get_param_value("path");
        current_path = util::Encode::Utf8ToGbk(current_path);

        auto target_dir = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / current_path;
        if (!exists(target_dir)) {
            throw std::runtime_error("目标目录不存在");
        }

        if (!req.has_file("file")) {
            throw std::runtime_error("未接收到文件");
        }

        const auto& file = req.get_file_value("file");
        std::string filename = util::Encode::Utf8ToGbk(file.filename);
        auto save_path = target_dir / filename;

        if (save_path.lexically_relative(service.f_files_path).string().find("..") != std::string::npos) {
            res.status = 403;
            throw std::runtime_error("非法路径访问");
        }

        if (save_path.lexically_relative(service.f_files_path).string().find("./") != std::string::npos) {
            res.status = 403;
            throw std::runtime_error("非法路径访问");
        }

        const auto base_path = canonical(service.f_files_path);
        if (!save_path.string().starts_with(base_path.string())) {
            res.status = 403;
            throw std::runtime_error("非法路径访问");
        }

        std::ofstream ofs(save_path, std::ios::binary);
        ofs.write(file.content.data(), file.content.size());
        ofs.close();

        json["success"] = true;
        json["message"] = "文件上传成功";
    } catch (const std::exception& e) {
        json["success"] = false;
        json["message"] = std::string("上传失败: ") + e.what();
    }

    res.set_content(json.dump(), "application/json");
}

auto FileController::logic_download(const httplib::Request& req, httplib::Response& res, bool web) -> void {
    const Service& service = Service::Instance();

    try {
        std::string path = util::Encode::Utf8ToGbk(req.get_param_value("path"));

        auto full_path = (web ? service.f_web_files / "pages" / "user" : service.f_files_path) / path;
        if (full_path.lexically_relative(service.f_files_path).string().find("..") != std::string::npos) {
            res.status = 403;
            throw std::runtime_error("非法路径访问");
        }

        if (full_path.lexically_relative(service.f_files_path).string().find("./") != std::string::npos) {
            res.status = 403;
            throw std::runtime_error("非法路径访问");
        }

        const auto base_path = canonical(service.f_files_path);
        if (!full_path.string().starts_with(base_path.string())) {
            res.status = 403;
            throw std::runtime_error("非法路径访问");
        }

        std::shared_ptr<std::ifstream> file = std::make_shared<std::ifstream>(full_path, std::ios::binary);
        res.set_header("Content-Disposition", "attachment; filename=\"" + util::Encode::GbkToUtf8(full_path.filename().string()) + "\"");

        LOG_TRACE << fmt::format("{} 正在被 {}:{} 地址下载", path, req.remote_addr, req.remote_port);

        res.set_content_provider(file_size(full_path),
                                 "application/octet-stream",
                                 [file, speed_limit = service.f_max_download_speed, start_time = std::chrono::steady_clock::now(), last_chunk_time =
                                     std::chrono::steady_clock::now(), chunk_size = 0](const size_t offset, const size_t length, const httplib::DataSink& sink) mutable {
                                     const size_t max_chunk = std::max<size_t>(speed_limit, 1024);
                                     const auto now = std::chrono::steady_clock::now();

                                     const double elapsed = std::chrono::duration<double>(now - last_chunk_time).count();
                                     const size_t allowed_bytes = static_cast<size_t>(speed_limit * elapsed);

                                     size_t bytes_to_send = std::max(max_chunk, allowed_bytes);
                                     if (bytes_to_send == 0) {
                                         bytes_to_send = 1;
                                     }

                                     std::vector<char> buffer(bytes_to_send);
                                     file->seekg(offset);
                                     file->read(buffer.data(), bytes_to_send);
                                     const std::streamsize bytes_read = file->gcount();

                                     if (bytes_read > 0) {
                                         sink.write(buffer.data(), bytes_read);
                                         const double expected_time = bytes_read / static_cast<double>(speed_limit);
                                         const double actual_time = std::chrono::duration<double>(std::chrono::steady_clock::now() - now).count();

                                         if (actual_time < expected_time) {
                                             std::this_thread::sleep_for(std::chrono::duration<double>(expected_time - actual_time));
                                         }
                                         last_chunk_time = std::chrono::steady_clock::now();
                                     }
                                     return true;
                                 });
    } catch (const std::exception& e) {
        nlohmann::json json;
        json["success"] = false;
        json["message"] = e.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::enum_path(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_enum_path(req, res, false);
}

auto FileController::remove_file(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_remove_file(req, res, false);
}

auto FileController::remove_directory(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_remove_directory(req, res, false);
}

auto FileController::create_file(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_create_file(req, res, false);
}

auto FileController::create_directory(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_create_directory(req, res, false);
}

auto FileController::rename(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_rename(req, res, false);
}

auto FileController::copy(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_copy(req, res, false);
}

auto FileController::cut(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_cut(req, res, false);
}

auto FileController::upload(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_upload(req, res, false);
}

auto FileController::download(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_download(req, res, false);
}

auto FileController::web_enum_path(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_enum_path(req, res, true);
}

auto FileController::web_remove_file(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_remove_file(req, res, true);
}

auto FileController::web_remove_directory(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_remove_directory(req, res, true);
}

auto FileController::web_create_file(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_create_file(req, res, true);
}

auto FileController::web_create_directory(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_create_directory(req, res, true);
}

auto FileController::web_rename(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_rename(req, res, true);
}

auto FileController::web_copy(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_copy(req, res, true);
}

auto FileController::web_cut(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_cut(req, res, true);
}

auto FileController::web_upload(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_upload(req, res, true);
}

auto FileController::web_download(const httplib::Request& req, httplib::Response& res) -> void {
    return logic_download(req, res, true);
}

auto FileController::web_user_view_count(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json;

    try {
        // 1. 获取请求参数
        int days = 30; // 默认查询30天
        if (req.has_param("days")) {
            days = std::stoi(req.get_param_value("days"));

            // 参数有效性校验
            if (days <= 0 || days > 30) {
                json["success"] = false;
                json["error"] = "Invalid days parameter (1-30 allowed)";
                res.status = 400; // Bad Request
                res.set_content(json.dump(), "application/json");
                return;
            }
        }

        // 2. 获取统计结果
        int count = visit.get(std::chrono::days(days));

        // 3. 构造响应
        json["success"] = true;
        json["data"] = {
            {
                "days",
                days
            },
            {
                "unique_visitors",
                count
            },
            {
                "period",
                "最近 " + std::to_string(days) + " 天"
            }
        };

        const auto stats = visit.get_daily_stats(std::chrono::days(days));
        nlohmann::json daily_data = nlohmann::json::array();

        for (const auto& [date, unique_visitors] : stats) {
            daily_data.push_back({
                {
                    "date",
                    std::chrono::system_clock::to_time_t(date)
                },
                {
                    "count",
                    unique_visitors
                }
            });
        }
        json["data"]["daily"] = daily_data;

        res.set_content(json.dump(4), "application/json"); // 美化格式
    } catch (const std::exception& e) {
        // 异常处理
        json["success"] = false;
        json["error"] = "服务器处理请求时发生错误";
        json["detail"] = e.what();
        res.status = 500;
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::log_enum_path(const httplib::Request& req, httplib::Response& res) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        std::string path = util::Encode::Utf8ToGbk(json["path"]);
        json.clear();

        if (!path.empty() && (path[0] == '\\' || path[0] == '/')) {
            path = path.substr(0, 1);
        }

        const auto path_ = util::AppPath() / "logs";

        json["data"] = nlohmann::json::array();
        for (const auto& [filename, size, type, is_directory, creation_time, access_time, modification_time] : util::File::list_directory(path_)) {
            json["data"].push_back({
                {
                    "filename",
                    filename
                },
                {
                    "size",
                    size
                },
                {
                    "type",
                    type
                },
                {
                    "is_directory",
                    is_directory
                },
                {
                    "creation_time",
                    creation_time
                },
                {
                    "access_time",
                    access_time
                },
                {
                    "modification_time",
                    modification_time
                }
            });
        }

        json["success"] = true;
        json["message"] = "获取文件成功!";
    } catch (const std::exception& exception) {
        json.clear();
        json["success"] = false;
        json["message"] = std::string("获取文件失败!") + exception.what();
    }
    res.set_content(json.dump(), "application/json");
}

auto FileController::log_remove_file(const httplib::Request& req, httplib::Response& res) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string path = util::Encode::Utf8ToGbk(json["path"]);
        json.clear();

        const auto path_ = util::AppPath() / "logs" / path;

        if (!std::filesystem::remove(path_)) {
            throw std::runtime_error("文件不存在或删除失败!");
        }

        json["success"] = true;
        json["message"] = "删除文件成功!";
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("删除文件失败!") + exception.what();
    }
    res.set_content(json.dump(), "application/json");
}

auto FileController::log_download(const httplib::Request& req, httplib::Response& res) -> void {
    const Service& service = Service::Instance();

    try {
        const std::string path = util::Encode::Utf8ToGbk(req.get_param_value("path"));

        auto full_path = util::AppPath() / "logs" / path;

        std::shared_ptr<std::ifstream> file = std::make_shared<std::ifstream>(full_path, std::ios::binary);
        res.set_header("Content-Disposition", "attachment; filename=\"" + util::Encode::GbkToUtf8(full_path.filename().string()) + "\"");

        res.set_content_provider(file_size(full_path),
                                 "application/octet-stream",
                                 [file, speed_limit = service.f_max_download_speed, start_time = std::chrono::steady_clock::now(), last_chunk_time =
                                     std::chrono::steady_clock::now(), chunk_size = 0](const size_t offset, const size_t length, const httplib::DataSink& sink) mutable {
                                     const size_t max_chunk = std::max<size_t>(speed_limit, 1024);
                                     const auto now = std::chrono::steady_clock::now();

                                     const double elapsed = std::chrono::duration<double>(now - last_chunk_time).count();
                                     const size_t allowed_bytes = static_cast<size_t>(speed_limit * elapsed);

                                     size_t bytes_to_send = std::max(max_chunk, allowed_bytes);
                                     if (bytes_to_send == 0) {
                                         bytes_to_send = 1;
                                     }

                                     std::vector<char> buffer(bytes_to_send);
                                     file->seekg(offset);
                                     file->read(buffer.data(), bytes_to_send);
                                     const std::streamsize bytes_read = file->gcount();

                                     if (bytes_read > 0) {
                                         sink.write(buffer.data(), bytes_read);
                                         const double expected_time = bytes_read / static_cast<double>(speed_limit);
                                         const double actual_time = std::chrono::duration<double>(std::chrono::steady_clock::now() - now).count();

                                         if (actual_time < expected_time) {
                                             std::this_thread::sleep_for(std::chrono::duration<double>(expected_time - actual_time));
                                         }
                                         last_chunk_time = std::chrono::steady_clock::now();
                                     }
                                     return true;
                                 });
    } catch (const std::exception& e) {
        nlohmann::json json;
        json["success"] = false;
        json["message"] = e.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::clear_memory_cache(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json;
    Service::file_cache.clear();
    json["success"] = true;
    res.set_content(json.dump(), "application/json");
}

auto FileController::get_cache_paths(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json;
    json["data"] = nlohmann::json::array();

    for (auto& [fst, snd] : Service::file_cache) {
        json["data"].push_back({
            {
                "file_size",
                snd.size
            },
            {
                "file_read_count",
                snd.revc_count
            },
            {
                "file_read_time",
                snd.read_time.time_since_epoch().count()
            },
            {
                "file_path",
                fst
            }
        });
    }

    json["success"] = true;
    res.set_content(json.dump(), "application/json");
}

auto FileController::sql_enum_path(const httplib::Request& req, httplib::Response& res) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        std::string path = util::Encode::Utf8ToGbk(json["path"]);
        json.clear();

        if (!path.empty() && (path[0] == '\\' || path[0] == '/')) {
            path = path.substr(0, 1);
        }

        const auto path_ = service.f_sql_path.value().parent_path() / "backup";

        json["data"] = nlohmann::json::array();
        for (const auto& [filename, size, type, is_directory, creation_time, access_time, modification_time] : util::File::list_directory(path_)) {
            json["data"].push_back({
                {
                    "filename",
                    filename
                },
                {
                    "size",
                    size
                },
                {
                    "type",
                    type
                },
                {
                    "is_directory",
                    is_directory
                },
                {
                    "creation_time",
                    creation_time
                },
                {
                    "access_time",
                    access_time
                },
                {
                    "modification_time",
                    modification_time
                }
            });
        }

        json["success"] = true;
        json["message"] = "获取文件成功!";
    } catch (const std::exception& exception) {
        json.clear();
        json["success"] = false;
        json["message"] = std::string("获取文件失败!") + exception.what();
    }
    res.set_content(json.dump(), "application/json");
}

auto FileController::sql_remove_file(const httplib::Request& req, httplib::Response& res) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string path = util::Encode::Utf8ToGbk(json["path"]);
        json.clear();

        const auto path_ = service.f_sql_path.value().parent_path() / "backup" / path;

        if (!std::filesystem::remove(path_)) {
            throw std::runtime_error("文件不存在或删除失败!");
        }

        json["success"] = true;
        json["message"] = "删除文件成功!";
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("删除文件失败!") + exception.what();
    }
    res.set_content(json.dump(), "application/json");
}

auto FileController::sql_download(const httplib::Request& req, httplib::Response& res) -> void {
    const Service& service = Service::Instance();

    try {
        const std::string path = util::Encode::Utf8ToGbk(req.get_param_value("path"));

        auto full_path = service.f_sql_path.value().parent_path() / "backup" / path;

        std::shared_ptr<std::ifstream> file = std::make_shared<std::ifstream>(full_path, std::ios::binary);
        res.set_header("Content-Disposition", "attachment; filename=\"" + util::Encode::GbkToUtf8(full_path.filename().string()) + "\"");

        res.set_content_provider(file_size(full_path),
                                 "application/octet-stream",
                                 [file, speed_limit = service.f_max_download_speed, start_time = std::chrono::steady_clock::now(), last_chunk_time =
                                     std::chrono::steady_clock::now(), chunk_size = 0](const size_t offset, const size_t length, const httplib::DataSink& sink) mutable {
                                     const size_t max_chunk = std::max<size_t>(speed_limit, 1024);
                                     const auto now = std::chrono::steady_clock::now();

                                     const double elapsed = std::chrono::duration<double>(now - last_chunk_time).count();
                                     const size_t allowed_bytes = static_cast<size_t>(speed_limit * elapsed);

                                     size_t bytes_to_send = std::max(max_chunk, allowed_bytes);
                                     if (bytes_to_send == 0) {
                                         bytes_to_send = 1;
                                     }

                                     std::vector<char> buffer(bytes_to_send);
                                     file->seekg(offset);
                                     file->read(buffer.data(), bytes_to_send);
                                     const std::streamsize bytes_read = file->gcount();

                                     if (bytes_read > 0) {
                                         sink.write(buffer.data(), bytes_read);
                                         const double expected_time = bytes_read / static_cast<double>(speed_limit);
                                         const double actual_time = std::chrono::duration<double>(std::chrono::steady_clock::now() - now).count();

                                         if (actual_time < expected_time) {
                                             std::this_thread::sleep_for(std::chrono::duration<double>(expected_time - actual_time));
                                         }
                                         last_chunk_time = std::chrono::steady_clock::now();
                                     }
                                     return true;
                                 });
    } catch (const std::exception& e) {
        nlohmann::json json;
        json["success"] = false;
        json["message"] = e.what();
        res.set_content(json.dump(), "application/json");
    }
}

auto FileController::sql_backup(const httplib::Request& req, httplib::Response& res) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    try {
        const std::string path = util::Encode::Utf8ToGbk(json["path"]);
        json.clear();

        const auto now = std::chrono::system_clock::now();
        const std::time_t tt = std::chrono::system_clock::to_time_t(now);
        std::tm tm = fmt::localtime(tt);

        const auto path_ = service.f_sql_path;
        const auto path2_ = service.f_sql_path.value().parent_path() / "backup" / fmt::format("sqlite_{:%Y-%m-%d %H_%M_%S}.db", tm);

        std::filesystem::copy(path_, path2_);

        json["success"] = true;
        json["message"] = "备份成功!";
        res.set_content(json.dump(), "application/json");
    } catch (const std::exception& exception) {
        json["success"] = false;
        json["message"] = std::string("备份失败!") + exception.what();
        res.set_content(json.dump(), "application/json");
    }
}
