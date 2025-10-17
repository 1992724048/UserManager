#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <boost/stacktrace/frame.hpp>
#include <boost/stacktrace/stacktrace.hpp>

#include "Service.h"
#include "crash_dump.h"

#include "opencv2/opencv.hpp"
#pragma comment(lib, "dbghelp.lib")


auto main() -> int {
    Crash::init();
    system("chcp 65001");

    setLogLevel(cv::utils::logging::LOG_LEVEL_SILENT);
    config::initialize(util::app_path() / "config.json");
    Logger::prepare_file_logging(util::app_path() / "logs");

    try {
        return Service::Instance().run();
    } catch (std::exception& exception) {
        LOG_ERROR << exception.what();
        std::this_thread::sleep_for(std::chrono::minutes(1));
        return -1;
    }
}
