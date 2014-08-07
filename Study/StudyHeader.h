
/************************************************************************/
/*   版权信息：macalyou
/*   项目名称：Study
/*	 文件名称：StudyHeader.h
/*	 用途    ：Study
/*   版本    ：1.0
/*	 作者    ：you
/*	 创建日期：2014.7.25
/************************************************************************/

#pragma once 
#pragma comment(lib,"Version.lib")

#include <windows.h>
#include <tchar.h>
#include <string>

#ifdef UNICODE
#define _tstring std::wstring
#else
#define _tstring std::string
#endif  //UNICODE

/************************************************************************/
/* 作用：将A字符集转化到宽字符集                                        */
/************************************************************************/
BOOL StringToWString(const std::string &str,std::wstring &wstr);

/************************************************************************/
/* 作用：将宽字符集转化到A字符集                                        */
/************************************************************************/
BOOL WStringToString(const std::wstring &wstr,std::string &str);

/************************************************************************/
/* 作用：获得一个GUID,以参数的形式返回                                  */
/************************************************************************/
int GetGuid(_tstring &sGuid);

/************************************************************************/
/* 作用：删除一个文件夹及下面的文件，
/* 第一个参数带“\\”，第二个参数设置为False
/* 返回值为0表示成功，不为0则是GetLastError()的值*/
/************************************************************************/
BOOL DeleteDirRecursion(LPCTSTR pSrcDir,BOOL bCheck);

/************************************************************************/
/* 作用：获得文件的版本号，一般右键可以看出来
/* 注意#pragma comment(lib,"Version.lib")
/************************************************************************/
int GetFileVersion(_tstring& sVersion, _tstring sNamePath);


