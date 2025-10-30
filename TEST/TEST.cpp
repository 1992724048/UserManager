#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#include <iostream>
#include <Windows.h>
#include "../SDK/SDK.h"

using Start = void(*)();
int main() {
    start();

    bool need_exit = false;
    std::string str;
    while (!need_exit) {
        std::cout << "输入 q 退出程序\n";
        std::cin >> str;
        if (str == "q") {
            need_exit = true;
        }
    }
}