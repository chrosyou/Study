
/************************************************************************/
/*   版权信息：macalyou
/*   项目名称：Study
/*	 文件名称：PEFile.cpp
/*	 用途    ：获得文件PE信息
/*   版本    ：1.0
/*	 作者    ：you
/*	 创建日期：2014.8.7
/************************************************************************/

#include "PEFile.h"
#include <iostream>

//获得DOS头
LPVOID GetDosHeader(LPVOID lpFile)
{
	assert(lpFile != NULL);
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (lpFile != NULL)
		pDosHeader = (PIMAGE_DOS_HEADER)lpFile;

	return (LPVOID)pDosHeader;
}

//获得NT头
LPVOID GetNtHeader(LPVOID lpFile,BOOL& bX64)
{
	assert(lpFile != NULL);
	bX64 = FALSE;
	PIMAGE_NT_HEADERS32 pNtHeader32 = NULL;
	PIMAGE_NT_HEADERS64 pHeaders64 = NULL;

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (lpFile != NULL)
		pDosHeader = (PIMAGE_DOS_HEADER)GetDosHeader(lpFile);
	//判断是否合法
    if (pDosHeader->e_magic !=IMAGE_DOS_SIGNATURE)
	    return NULL;

	pNtHeader32 = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//判断是不是正常的PE文件
	if (pNtHeader32->Signature != IMAGE_NT_SIGNATURE)
	    return NULL;

	if (pNtHeader32->FileHeader.Machine==IMAGE_FILE_MACHINE_AMD64) //64bit
	{
		bX64 = TRUE;
		pHeaders64 = (PIMAGE_NT_HEADERS64)((DWORD)pDosHeader + pDosHeader->e_lfanew);
		return pHeaders64;
	}

	return pNtHeader32;
}

//获得可选头
LPVOID GetOptionHeader(LPVOID lpFile,BOOL& bX64)
{
	assert(lpFile != NULL);
	bX64 = FALSE;
	LPVOID pOptionHeader = NULL;
	BOOL bX64Nt = FALSE;

	LPVOID pNtHeader = (LPVOID)GetNtHeader(lpFile,bX64Nt);
	if (pNtHeader == NULL)
	    return NULL;

	if (bX64Nt) //64bit
	{
		bX64 = TRUE;		
		pOptionHeader = (LPVOID) PIMAGE_OPTIONAL_HEADER64((DWORD)pNtHeader +sizeof( IMAGE_FILE_HEADER )+ sizeof(DWORD)) ;
	}else
	{
		pOptionHeader = (LPVOID) PIMAGE_OPTIONAL_HEADER32((DWORD)pNtHeader + sizeof( IMAGE_FILE_HEADER )+ sizeof(DWORD));
	}	
	return pOptionHeader;
}

/*
*  获取字段
*/
BOOL IsDigiSigEX(HANDLE hFile)
{
	if (hFile == INVALID_HANDLE_VALUE)  //文件对象
		return FALSE;
	HANDLE hFileMapping = CreateFileMapping(hFile,NULL,PAGE_READONLY,0, 0, NULL);
	if (hFileMapping == NULL)  
	{
		CloseHandle(hFile);
		return FALSE;
	}
	LPVOID lpFile = MapViewOfFile(hFileMapping,FILE_MAP_READ,0, 0, 0);
	if (lpFile==NULL)  //文件视图对象
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return FALSE;
	}

	IMAGE_DATA_DIRECTORY secData = { 0 };
	LPVOID pOptionHeader = NULL;
	BOOL bX64Opheader = FALSE;

	pOptionHeader     = (LPVOID)GetOptionHeader( lpFile,bX64Opheader );
	if(pOptionHeader != NULL && bX64Opheader)
	{
		secData = ((PIMAGE_OPTIONAL_HEADER64)pOptionHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	}
	else if(pOptionHeader != NULL)
	{
		secData = ((PIMAGE_OPTIONAL_HEADER32)pOptionHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	}

	UnmapViewOfFile(lpFile);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	if ( ( secData.VirtualAddress != 0 ) && ( secData.Size != 0 ) )
		return TRUE;
	return FALSE;
}
//A版函数
BOOL IsDigiSigA(LPCSTR pPath)
{
	HANDLE hFile = CreateFileA(pPath,GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);
    return IsDigiSigEX(hFile);
}
//W版函数
BOOL IsDigiSigW(LPCWSTR pPath)
{
	HANDLE hFile = CreateFileW(pPath,GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);
	return IsDigiSigEX(hFile);
}

//实际判断PE文件操作
BOOL IsPEFileEX(HANDLE hFile)
{
	if (hFile == INVALID_HANDLE_VALUE)  //文件对象
		return ERROR_PE_CREATEFILE;

	HANDLE hFileMapping = CreateFileMapping(hFile,NULL,PAGE_READONLY,0, 0, NULL);
	if (hFileMapping == NULL)  
	{
		return ERROR_PE_CREATEFILEMAPPING;
	}

	LPVOID lpFile = MapViewOfFile(hFileMapping,FILE_MAP_READ,0, 0, 0);
	if (lpFile == NULL)  //文件视图对象
	{
		CloseHandle(hFileMapping);
		return FALSE;
	}

	PIMAGE_DOS_HEADER pDosHeader=NULL;
	PIMAGE_NT_HEADERS32 pNtHeader32 = NULL;
	//取得Dos头部
	pDosHeader = (PIMAGE_DOS_HEADER)lpFile;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		UnmapViewOfFile(lpFile);
		CloseHandle(hFileMapping);
		return ERROR_PE_NOTDOSHEADER;
	}

	//获取NT头
	pNtHeader32 = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//判断是不是PE文件
	if (pNtHeader32->Signature != IMAGE_NT_SIGNATURE)
	{
		UnmapViewOfFile(lpFile);
		CloseHandle(hFileMapping);
		return ERROR_PE_NOTNTHEADER;
	}

	UnmapViewOfFile(lpFile);
	CloseHandle(hFileMapping);;

	return ERROR_PE_SUCCESS;
}

/*
*  返回值依照define定义
*/
BOOL IsPEFileA(LPCSTR pPath)
{
	if (pPath == NULL)
	{
		assert(0);
		return ERROR_PE_FILEPATHNULL;
	}

	HANDLE hFile = CreateFileA(pPath,GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);
	BOOL bReturn = IsPEFileEX(hFile);
	CloseHandle(hFile);
	return bReturn;
}

//W版
BOOL IsPEFileW(LPCWSTR pPath)
{
	if (pPath == NULL)
	{
		assert(0);
		return ERROR_PE_FILEPATHNULL;
	}	

	HANDLE hFile = NULL;
	hFile = CreateFileW(pPath,GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);	
	BOOL bReturn = IsPEFileEX(hFile);
	CloseHandle(hFile);
	return bReturn;
}
