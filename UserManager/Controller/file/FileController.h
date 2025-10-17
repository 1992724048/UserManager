#pragma once

#include "../HTTPController.h"

class FileController final : public httplib::HttpController<FileController>{
public:
    METHOD_LIST_BEGIN
		METHOD_ADD(FileController::file, "/root/(.*)", httplib::GET, httplib::ALL, "文件", "访问系统文件");
		METHOD_ADD(FileController::user_web, "/web/(.*)", httplib::GET, httplib::ALL, "文件", "访问用户网站");
		METHOD_ADD(FileController::res, "/res/(.*)", httplib::GET, httplib::ALL, "文件", "访问资源文件");
		METHOD_ADD(FileController::enum_path, "/file/enum_path", httplib::POST, httplib::ALL, "文件", "遍历目录文件");
		METHOD_ADD(FileController::remove_file, "/file/remove_file", httplib::POST, httplib::COOKIE, "文件", "删除文件");
		METHOD_ADD(FileController::remove_directory, "/file/remove_directory", httplib::POST, httplib::COOKIE, "文件", "删除目录");
		METHOD_ADD(FileController::create_file, "/file/create_file", httplib::POST, httplib::COOKIE, "文件", "创建文件");
		METHOD_ADD(FileController::create_directory, "/file/create_directory", httplib::POST, httplib::COOKIE, "文件", "创建目录");
		METHOD_ADD(FileController::rename, "/file/rename", httplib::POST, httplib::COOKIE, "文件", "重命名目录和文件");
		METHOD_ADD(FileController::copy, "/file/copy", httplib::POST, httplib::COOKIE, "文件", "拷贝目录和文件");
		METHOD_ADD(FileController::cut, "/file/cut", httplib::POST, httplib::COOKIE, "文件", "剪切目录和文件");
		METHOD_ADD(FileController::upload, "/file/upload", httplib::POST, httplib::COOKIE, "文件", "上传文件");
		METHOD_ADD(FileController::download, "/file/download", httplib::GET, httplib::ALL, "文件", "下载文件");
		METHOD_ADD(FileController::web_enum_path, "/web_file/enum_path", httplib::POST, httplib::COOKIE, "文件", "遍历用户网站目录文件");
		METHOD_ADD(FileController::web_remove_file, "/web_file/remove_file", httplib::POST, httplib::COOKIE, "文件", "删除用户网站文件");
		METHOD_ADD(FileController::web_remove_directory, "/web_file/remove_directory", httplib::POST, httplib::COOKIE, "文件", "删除用户网站目录");
		METHOD_ADD(FileController::web_create_file, "/web_file/create_file", httplib::POST, httplib::COOKIE, "文件", "创建用户网站文件");
		METHOD_ADD(FileController::web_create_directory, "/web_file/create_directory", httplib::POST, httplib::COOKIE, "文件", "创建用户网站目录");
		METHOD_ADD(FileController::web_rename, "/web_file/rename", httplib::POST, httplib::COOKIE, "文件", "重命名用户网站目录和文件");
		METHOD_ADD(FileController::web_copy, "/web_file/copy", httplib::POST, httplib::COOKIE, "文件", "拷贝用户网站目录和文件");
		METHOD_ADD(FileController::web_cut, "/web_file/cut", httplib::POST, httplib::COOKIE, "文件", "剪切用户网站目录和文件");
		METHOD_ADD(FileController::web_upload, "/web_file/upload", httplib::POST, httplib::COOKIE, "文件", "上传用户网站文件");
		METHOD_ADD(FileController::web_download, "/web_file/download", httplib::GET, httplib::COOKIE, "文件", "下载用户网站文件");
		METHOD_ADD(FileController::web_user_view_count, "/web_file/user_view_count", httplib::GET, httplib::COOKIE, "网站", "获取网站访问者数量");
		METHOD_ADD(FileController::clear_memory_cache, "/file/clear_memory_cache", httplib::GET, httplib::COOKIE, "文件", "清除文件缓存");
		METHOD_ADD(FileController::get_cache_paths, "/file/get_cache_paths", httplib::GET, httplib::COOKIE, "文件", "获取所有缓存文件");
		METHOD_ADD(FileController::log_enum_path, "/log_file/enum_path", httplib::POST, httplib::COOKIE, "文件", "遍历日志目录文件");
		METHOD_ADD(FileController::log_remove_file, "/log_file/remove_file", httplib::POST, httplib::COOKIE, "文件", "删除日志文件");
		METHOD_ADD(FileController::log_download, "/log_file/download", httplib::GET, httplib::COOKIE, "文件", "下载日志文件");
		METHOD_ADD(FileController::sql_enum_path, "/sql_file/enum_path", httplib::POST, httplib::COOKIE, "文件", "遍历日志目录文件");
		METHOD_ADD(FileController::sql_remove_file, "/sql_file/remove_file", httplib::POST, httplib::COOKIE, "文件", "删除日志文件");
		METHOD_ADD(FileController::sql_download, "/sql_file/download", httplib::GET, httplib::COOKIE, "文件", "下载日志文件");
		METHOD_ADD(FileController::sql_backup, "/sql_file/backup", httplib::POST, httplib::COOKIE, "文件", "拷贝用户网站目录和文件");
    METHOD_LIST_END

	inline static util::VisitCounter visit;

    FileController();
	static auto file_logic(const httplib::Request& req, httplib::Response& res, const bool user, const bool res_path) -> void;
	static auto file(const httplib::Request& req, httplib::Response& res) -> void;
	static auto user_web(const httplib::Request& req, httplib::Response& res) -> void;
	static auto res(const httplib::Request& req, httplib::Response& res) -> void;
	static auto logic_enum_path(const httplib::Request& req, httplib::Response& res, bool web) -> void;
	static auto logic_remove_file(const httplib::Request& req, httplib::Response& res, bool web) -> void;
	static auto logic_remove_directory(const httplib::Request& req, httplib::Response& res, bool web) -> void;
	static auto logic_create_file(const httplib::Request& req, httplib::Response& res, bool web) -> void;
	static auto logic_create_directory(const httplib::Request& req, httplib::Response& res, bool web) -> void;
	static auto logic_rename(const httplib::Request& req, httplib::Response& res, bool web) -> void;
	static auto logic_copy(const httplib::Request& req, httplib::Response& res, bool web) -> void;
	static auto logic_cut(const httplib::Request& req, httplib::Response& res, bool web) -> void;
	static auto logic_upload(const httplib::Request& req, httplib::Response& res, bool web) -> void;
	static auto logic_download(const httplib::Request& req, httplib::Response& res, bool web) -> void;
	static auto enum_path(const httplib::Request& req, httplib::Response& res) -> void;
	static auto remove_file(const httplib::Request& req, httplib::Response& res) -> void;
	static auto remove_directory(const httplib::Request& req, httplib::Response& res) -> void;
	static auto create_file(const httplib::Request& req, httplib::Response& res) -> void;
	static auto create_directory(const httplib::Request& req, httplib::Response& res) -> void;
	static auto rename(const httplib::Request& req, httplib::Response& res) -> void;
	static auto copy(const httplib::Request& req, httplib::Response& res) -> void;
	static auto cut(const httplib::Request& req, httplib::Response& res) -> void;
	static auto upload(const httplib::Request& req, httplib::Response& res) -> void;
	static auto download(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_enum_path(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_remove_file(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_remove_directory(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_create_file(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_create_directory(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_rename(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_copy(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_cut(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_upload(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_download(const httplib::Request& req, httplib::Response& res) -> void;
	static auto web_user_view_count(const httplib::Request& req, httplib::Response& res) -> void;
	static auto log_enum_path(const httplib::Request& req, httplib::Response& res) -> void;
	static auto log_remove_file(const httplib::Request& req, httplib::Response& res) -> void;
	static auto log_download(const httplib::Request& req, httplib::Response& res) -> void;
	static auto clear_memory_cache(const httplib::Request& req, httplib::Response& res) -> void;
	static auto get_cache_paths(const httplib::Request& req, httplib::Response& res) -> void;
	static auto sql_enum_path(const httplib::Request& req, httplib::Response& res) -> void;
	static auto sql_remove_file(const httplib::Request& req, httplib::Response& res) -> void;
	static auto sql_download(const httplib::Request& _req, httplib::Response& _res) -> void;
	static auto sql_backup(const httplib::Request& req, httplib::Response& res) -> void;
};
