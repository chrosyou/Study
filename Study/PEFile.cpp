
/************************************************************************/
/*   ��Ȩ��Ϣ��macalyou
/*   ��Ŀ���ƣ�Study
/*	 �ļ����ƣ�PEFile.cpp
/*	 ��;    ������ļ�PE��Ϣ
/*   �汾    ��1.0
/*	 ����    ��you
/*	 �������ڣ�2014.8.7
/************************************************************************/

#include "PEFile.h"
#include <iostream>

//���DOSͷ
LPVOID GetDosHeader(LPVOID lpFile)
{
	assert(lpFile != NULL);
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (lpFile != NULL)
		pDosHeader = (PIMAGE_DOS_HEADER)lpFile;

	return (LPVOID)pDosHeader;
}

//���NTͷ
LPVOID GetNtHeader(LPVOID lpFile,BOOL& bX64)
{
	assert(lpFile != NULL);
	bX64 = FALSE;
	PIMAGE_NT_HEADERS32 pNtHeader32 = NULL;
	PIMAGE_NT_HEADERS64 pHeaders64 = NULL;

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (lpFile != NULL)
		pDosHeader = (PIMAGE_DOS_HEADER)GetDosHeader(lpFile);
	//�ж��Ƿ�Ϸ�
    if (pDosHeader->e_magic !=IMAGE_DOS_SIGNATURE)
	    return NULL;

	pNtHeader32 = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//�ж��ǲ���������PE�ļ�
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

//��ÿ�ѡͷ
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
*  ��ȡ�ֶ�
*/
BOOL IsDigiSigEX(HANDLE hFile)
{
	if (hFile == INVALID_HANDLE_VALUE)  //�ļ�����
		return FALSE;
	HANDLE hFileMapping = CreateFileMapping(hFile,NULL,PAGE_READONLY,0, 0, NULL);
	if (hFileMapping == NULL)  
	{
		CloseHandle(hFile);
		return FALSE;
	}
	LPVOID lpFile = MapViewOfFile(hFileMapping,FILE_MAP_READ,0, 0, 0);
	if (lpFile==NULL)  //�ļ���ͼ����
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
//A�溯��
BOOL IsDigiSigA(LPCSTR pPath)
{
	HANDLE hFile = CreateFileA(pPath,GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);
    return IsDigiSigEX(hFile);
}
//W�溯��
BOOL IsDigiSigW(LPCWSTR pPath)
{
	HANDLE hFile = CreateFileW(pPath,GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL);
	return IsDigiSigEX(hFile);
}

//ʵ���ж�PE�ļ�����
BOOL IsPEFileEX(HANDLE hFile)
{
	if (hFile == INVALID_HANDLE_VALUE)  //�ļ�����
		return ERROR_PE_CREATEFILE;

	HANDLE hFileMapping = CreateFileMapping(hFile,NULL,PAGE_READONLY,0, 0, NULL);
	if (hFileMapping == NULL)  
	{
		return ERROR_PE_CREATEFILEMAPPING;
	}

	LPVOID lpFile = MapViewOfFile(hFileMapping,FILE_MAP_READ,0, 0, 0);
	if (lpFile == NULL)  //�ļ���ͼ����
	{
		CloseHandle(hFileMapping);
		return FALSE;
	}

	PIMAGE_DOS_HEADER pDosHeader=NULL;
	PIMAGE_NT_HEADERS32 pNtHeader32 = NULL;
	//ȡ��Dosͷ��
	pDosHeader = (PIMAGE_DOS_HEADER)lpFile;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		UnmapViewOfFile(lpFile);
		CloseHandle(hFileMapping);
		return ERROR_PE_NOTDOSHEADER;
	}

	//��ȡNTͷ
	pNtHeader32 = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//�ж��ǲ���PE�ļ�
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
*  ����ֵ����define����
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

//W��
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
