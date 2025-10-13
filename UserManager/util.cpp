#include "util.h"

#include "rand.h"

namespace util {
    auto app_path() -> std::filesystem::path {
        static std::filesystem::path app_path;
        if (app_path.empty()) {
            char pathOut[MAX_PATH] = {};
            GetModuleFileNameA(GetModuleHandleA(nullptr), pathOut, MAX_PATH);
            app_path = std::filesystem::path(pathOut).parent_path();
        }
        return app_path;
    }

    auto read_file(const std::filesystem::path& path) -> std::string {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open file: " + path.string());
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
            throw std::runtime_error("Failed to read file: " + path.string());
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

    auto GetMIMEType(const std::string& extension) -> std::string {
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
        const auto it = mime_types.find(extension);
        return it != mime_types.end() ? it->second : "application/octet-stream";
    }

    // Boyer-Moore算法
    auto replace_all(std::string& str, const std::string& from, const std::string& to) -> std::string& {
        if (from.empty()) {
            return str;
        }

        const size_t from_len = from.length();
        const size_t to_len = to.length();

        std::vector bad_char(256, from_len);
        for (size_t i = 0; i < from_len - 1; ++i) {
            bad_char[static_cast<unsigned char>(from[i])] = from_len - i - 1;
        }

        size_t pos = 0;
        while (pos <= str.length() - from_len) {
            size_t j;
            for (j = from_len - 1; j > 0 && from[j] == str[pos + j]; --j) {
            }

            if (j == 0) {
                str.replace(pos, from_len, to);
                pos += to_len;
            } else {
                pos += bad_char[static_cast<unsigned char>(str[pos + from_len - 1])];
            }
        }

        return str;
    }
}
