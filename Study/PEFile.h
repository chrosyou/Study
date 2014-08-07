
/************************************************************************/
/*   版权信息：macalyou
/*   项目名称：Study
/*	 文件名称：PEFile.h
/*	 用途    ：获得文件PE信息
/*   版本    ：1.0
/*	 作者    ：you
/*	 创建日期：2014.8.7
/************************************************************************/

#include "StudyHeader.h"
#include <assert.h>

#ifdef UNICODE
#define IsPEFile  IsPEFileW
#define IsDigiSig IsDigiSigW
#else
#define IsPEFile  IsPEFileA
#define IsDigiSig IsDigiSigA
#endif // !UNICODE

#define ERROR_PE_SUCCESS			0  //
#define ERROR_PE_FILEPATHNULL		2  //传入参数为NULL
#define ERROR_PE_CREATEFILE			3  //CreateFile函数失败
#define ERROR_PE_CREATEFILEMAPPING	4  //CreateFileMapping函数失败
#define ERROR_PE_MAPVIEWOFFILE		5  //MapViewOfFile函数失败
#define ERROR_PE_NOTDOSHEADER		6  //不是dos头
#define ERROR_PE_NOTNTHEADER		6  //不是NT头

//获得DOS头部
LPVOID GetDosHeader(LPVOID lpFile);

//获得NT头部
LPVOID GetNtHeader(LPVOID lpFile,BOOL& bX64);

//获得可选头部
LPVOID GetOptionHeader(LPVOID lpFile,BOOL& bX64);

BOOL IsDigiSigEX(HANDLE hFile);

//判断可选头安全字段是否有效
BOOL IsDigiSigW(LPCWSTR pPath);
BOOL IsDigiSigA(LPCSTR pPath);


//判断实际执行函数
BOOL IsPEFileEX(HANDLE hFile);

/************************************************************************/
/* 作用：判断一个文件是不是PE文件                                       */
/* 外部调用
/************************************************************************/
BOOL IsPEFileW(LPCWSTR pPath);
BOOL IsPEFileA(LPCSTR pPath);
