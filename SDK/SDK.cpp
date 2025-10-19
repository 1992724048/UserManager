// SDK.cpp : 定义 DLL 的导出函数。
//

#include "framework.h"
#include "SDK.h"


// 这是导出变量的一个示例
SDK_API int nSDK=0;

// 这是导出函数的一个示例。
SDK_API int fnSDK(void)
{
    return 0;
}

// 这是已导出类的构造函数。
CSDK::CSDK()
{
    return;
}
