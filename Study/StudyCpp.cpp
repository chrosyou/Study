
/************************************************************************/
/*   版权信息：macalyou
/*   项目名称：Study
/*	 文件名称：StudyCpp.cpp
/*	 用途    ：Study
/*   版本    ：1.0
/*	 作者    ：you
/*	 创建日期：2014.7.25
/************************************************************************/

#include "StudyHeader.h"

#pragma comment(lib, "shlwapi.lib")

//将A字符集转化到宽字符集
BOOL StringToWString(const std::string &str, std::wstring &wstr)
{    
	int nLen = (int)str.length();    
	wstr.resize(nLen,L' ');
	int nResult = MultiByteToWideChar(CP_ACP,0,(LPCSTR)str.c_str(),nLen,(LPWSTR)wstr.c_str(),nLen);
	if (nResult == 0)
		return FALSE;
	return TRUE;
}

//将宽字符转化到A字符集
BOOL WStringToString(const std::wstring &wstr, std::string &str)
{    
	int nLen = (int)wstr.length();    
	str.resize(nLen,' ');
	int nResult = WideCharToMultiByte(CP_ACP,0,(LPCWSTR)wstr.c_str(),nLen,(LPSTR)str.c_str(),nLen,NULL,NULL);
	if (nResult == 0)
		return FALSE;
	return TRUE;
}

//获得GUID
int GetGuid(_tstring &sGuid)  
{
	GUID guid;
	CoCreateGuid(&guid);
	TCHAR buf[64] = {0};  
	_tprintf_s(buf,sizeof(buf),"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",  
		guid.Data1, guid.Data2, guid.Data3,  
		guid.Data4[0], guid.Data4[1],  
		guid.Data4[2], guid.Data4[3],  
		guid.Data4[4], guid.Data4[5],  
		guid.Data4[6], guid.Data4[7]);  
    sGuid = buf;
	return 0;
}

//删除文件夹
BOOL DeleteDirRecursion(LPCTSTR pSrcDir, BOOL bCheck)
{
	WIN32_FIND_DATA FileData; 
	HANDLE hSearch = NULL;
	TCHAR szFindString[MAX_PATH] = {0};
	TCHAR szNewSrcDir[MAX_PATH] = {0};
	BOOL fFinished = FALSE; 

	_tcscpy_s(szFindString,MAX_PATH,pSrcDir);
	_tcscat_s(szFindString,MAX_PATH,_T("*.*"));
	hSearch = FindFirstFile(szFindString, &FileData); 
	if (hSearch == INVALID_HANDLE_VALUE) 
	{ 
		return -1;
	} 

	LONG nRet = 0;
	while (!fFinished) 
	{ 
		if(_tcscmp(FileData.cFileName,_T("."))!=0 && _tcscmp(FileData.cFileName,_T(".."))!=0)
		{
			if( (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY )
			{
				_tcscpy_s(szNewSrcDir,MAX_PATH,pSrcDir);
				_tcscat_s(szNewSrcDir,MAX_PATH,FileData.cFileName);
				_tcscat_s(szNewSrcDir,MAX_PATH,_T("\\"));
				DeleteDirRecursion(szNewSrcDir,bCheck);
			}
			else
			{
				_tcscpy_s(szNewSrcDir,MAX_PATH,pSrcDir);
				_tcscat_s(szNewSrcDir,MAX_PATH,FileData.cFileName);
				SetFileAttributes(szNewSrcDir, 0);
				DeleteFile(szNewSrcDir);
			}
		}

		if (!FindNextFile(hSearch, &FileData)) 
		{
			if (GetLastError() == ERROR_NO_MORE_FILES) 
			{ 
				fFinished = TRUE; 
			} 
		}
	} 

	FindClose(hSearch); //**关闭句柄
	RemoveDirectory(pSrcDir);  //删除当前目录
	return TRUE;
}

//获得文件的版本号
int GetFileVersion(_tstring &sVersion, _tstring sNamePath)
{
	void *pData = NULL;
	UINT nItemLength;
	DWORD dwInfoSize, dwHandle;
	TCHAR tcVersion[MAX_PATH] = {0};
	dwInfoSize = GetFileVersionInfoSize(sNamePath.c_str(), &dwHandle);  //获得版本信息的大小

	if (dwInfoSize > 0)
	{
		VS_FIXEDFILEINFO *pFileInfo;
		pData = new TCHAR[dwInfoSize];
		ZeroMemory(pData, dwInfoSize * sizeof(TCHAR));
		if (GetFileVersionInfo(sNamePath.c_str(), dwHandle, dwInfoSize, pData))
		{
			if (VerQueryValue(pData, _T("\\"), (LPVOID*)&pFileInfo, &nItemLength))
			{
				wsprintf(tcVersion,_T("%d.%d.%d.%d"),
					pFileInfo->dwProductVersionMS >> 16, 
					pFileInfo->dwProductVersionMS & 0xFFFF, 
					pFileInfo->dwProductVersionLS >> 16,
					pFileInfo->dwProductVersionLS & 0xFFFF);
				sVersion = tcVersion ;
			}
		}
		delete[] pData;
	}
	else
	{
		sVersion = _T("1.0.0.-1");
	}
	return 0;
}

BOOL DoesFileOrDirExistW(LPCTSTR path)
{
	WIN32_FIND_DATA fd;
	HANDLE handle = NULL;
	handle = FindFirstFile(path,&fd);
	if (handle == INVALID_HANDLE_VALUE)
		return false;
	FindClose(handle);
	return true;
}

void ParseCmdLine(LPTSTR lpCmdLine)
{
	int num_args = 0;
	_TCHAR** args = CommandLineToArgvW(lpCmdLine, &num_args);

	_tstring sFilePath;
	for (int i = 0; i < num_args; i++)
	{
		sFilePath = args[i];
	}

	LocalFree( args );
}