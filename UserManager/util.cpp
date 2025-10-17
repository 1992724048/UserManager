#include "util.h"

#include "rand.h"

namespace util {
    auto app_path() -> std::filesystem::path {
        static std::filesystem::path app_path;
        if (app_path.empty()) {
            char path_out[MAX_PATH] = {};
            GetModuleFileNameA(GetModuleHandleA(nullptr), path_out, MAX_PATH);
            app_path = std::filesystem::path(path_out).parent_path();
        }
        return app_path;
    }

    auto read_file(const std::filesystem::path& _path) -> std::string {
        std::ifstream in(_path, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open file: " + _path.string());
        }

        in.seekg(0, std::ios::end);
        const size_t size = in.tellg();
        in.seekg(0, std::ios::beg);

        if (size == 0) {
            return {};
        }

        std::string buffer;
        buffer.resize(size);
        in.read(buffer.data(), size);

        if (!in) {
            throw std::runtime_error("Failed to read file: " + _path.string());
        }

        return buffer;
    }

    auto generate_session_token() -> std::string {
        constexpr int token_length = 32;
        unsigned char buffer[token_length];

        if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
            throw std::runtime_error("Failed to generate secure random bytes");
        }

        std::stringstream ss;
        for (const unsigned char i : buffer) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
        }
        return ss.str();
    }

    auto generate_timestamp_sha256() -> std::string {
        const auto now = std::chrono::system_clock::now();
        const auto duration = now.time_since_epoch();
        const uint64_t micros = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();

        unsigned char bytes[8];
        bytes[0] = static_cast<unsigned char>(micros >> 56);
        bytes[1] = static_cast<unsigned char>(micros >> 48);
        bytes[2] = static_cast<unsigned char>(micros >> 40);
        bytes[3] = static_cast<unsigned char>(micros >> 32);
        bytes[4] = static_cast<unsigned char>(micros >> 24);
        bytes[5] = static_cast<unsigned char>(micros >> 16);
        bytes[6] = static_cast<unsigned char>(micros >> 8);
        bytes[7] = static_cast<unsigned char>(micros);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(bytes, sizeof(bytes), hash);

        std::stringstream ss;
        for (const unsigned char i : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        }

        return ss.str();
    }

    auto get_mime_type(const std::string& _extension) -> std::string {
        static phmap::flat_hash_map<std::string, std::string> mime_types = {
            // 文本类
            {
                ".html",
                "text/html"
            },
            {
                ".htm",
                "text/html"
            },
            {
                ".css",
                "text/css"
            },
            {
                ".csv",
                "text/csv"
            },
            {
                ".txt",
                "text/plain"
            },
            {
                ".md",
                "text/markdown"
            },
            {
                ".xml",
                "application/xml"
            },
            {
                ".xsl",
                "application/xml"
            },

            // 脚本/代码
            {
                ".js",
                "application/javascript"
            },
            {
                ".mjs",
                "application/javascript"
            },
            {
                ".json",
                "application/json"
            },
            {
                ".jsonld",
                "application/ld+json"
            },
            {
                ".wasm",
                "application/wasm"
            },

            // 图片
            {
                ".png",
                "image/png"
            },
            {
                ".jpg",
                "image/jpeg"
            },
            {
                ".jpeg",
                "image/jpeg"
            },
            {
                ".gif",
                "image/gif"
            },
            {
                ".svg",
                "image/svg+xml"
            },
            {
                ".webp",
                "image/webp"
            },
            {
                ".ico",
                "image/x-icon"
            },
            {
                ".bmp",
                "image/bmp"
            },
            {
                ".tiff",
                "image/tiff"
            },
            {
                ".psd",
                "image/vnd.adobe.photoshop"
            },

            // 字体
            {
                ".ttf",
                "font/ttf"
            },
            {
                ".otf",
                "font/otf"
            },
            {
                ".woff",
                "font/woff"
            },
            {
                ".woff2",
                "font/woff2"
            },

            // 音视频
            {
                ".mp3",
                "audio/mpeg"
            },
            {
                ".wav",
                "audio/wav"
            },
            {
                ".ogg",
                "audio/ogg"
            },
            {
                ".flac",
                "audio/flac"
            },
            {
                ".aac",
                "audio/aac"
            },
            {
                ".mp4",
                "video/mp4"
            },
            {
                ".webm",
                "video/webm"
            },
            {
                ".ogv",
                "video/ogg"
            },
            {
                ".avi",
                "video/x-msvideo"
            },
            {
                ".mpeg",
                "video/mpeg"
            },
            {
                ".mov",
                "video/quicktime"
            },

            // 文档
            {
                ".pdf",
                "application/pdf"
            },
            {
                ".doc",
                "application/msword"
            },
            {
                ".docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            },
            {
                ".xls",
                "application/vnd.ms-excel"
            },
            {
                ".xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            },
            {
                ".ppt",
                "application/vnd.ms-powerpoint"
            },
            {
                ".pptx",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            },
            {
                ".odt",
                "application/vnd.oasis.opendocument.text"
            },
            {
                ".ods",
                "application/vnd.oasis.opendocument.spreadsheet"
            },

            // 压缩包
            {
                ".zip",
                "application/zip"
            },
            {
                ".rar",
                "application/vnd.rar"
            },
            {
                ".7z",
                "application/x-7z-compressed"
            },
            {
                ".tar",
                "application/x-tar"
            },
            {
                ".gz",
                "application/gzip"
            },
            {
                ".bz2",
                "application/x-bzip2"
            },

            // 编程相关
            {
                ".php",
                "application/x-httpd-php"
            },
            {
                ".sh",
                "application/x-sh"
            },
            {
                ".py",
                "text/x-python"
            },
            {
                ".java",
                "text/x-java-source"
            },
            {
                ".c",
                "text/x-c"
            },
            {
                ".cpp",
                "text/x-c++src"
            },
            {
                ".h",
                "text/x-c-header"
            },

            // 其他
            {
                ".exe",
                "application/x-msdownload"
            },
            {
                ".dll",
                "application/x-msdownload"
            },
            {
                ".swf",
                "application/x-shockwave-flash"
            },
            {
                ".apk",
                "application/vnd.android.package-archive"
            },
            {
                ".epub",
                "application/epub+zip"
            },
            {
                ".ics",
                "text/calendar"
            },
            {
                ".rtf",
                "application/rtf"
            },
            {
                ".yaml",
                "application/x-yaml"
            },
            {
                ".toml",
                "application/toml"
            }
        };
        const auto it = mime_types.find(_extension);
        return it != mime_types.end() ? it->second : "application/octet-stream";
    }
}
