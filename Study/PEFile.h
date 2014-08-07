
/************************************************************************/
/*   ��Ȩ��Ϣ��macalyou
/*   ��Ŀ���ƣ�Study
/*	 �ļ����ƣ�PEFile.h
/*	 ��;    ������ļ�PE��Ϣ
/*   �汾    ��1.0
/*	 ����    ��you
/*	 �������ڣ�2014.8.7
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
#define ERROR_PE_FILEPATHNULL		2  //�������ΪNULL
#define ERROR_PE_CREATEFILE			3  //CreateFile����ʧ��
#define ERROR_PE_CREATEFILEMAPPING	4  //CreateFileMapping����ʧ��
#define ERROR_PE_MAPVIEWOFFILE		5  //MapViewOfFile����ʧ��
#define ERROR_PE_NOTDOSHEADER		6  //����dosͷ
#define ERROR_PE_NOTNTHEADER		6  //����NTͷ

//���DOSͷ��
LPVOID GetDosHeader(LPVOID lpFile);

//���NTͷ��
LPVOID GetNtHeader(LPVOID lpFile,BOOL& bX64);

//��ÿ�ѡͷ��
LPVOID GetOptionHeader(LPVOID lpFile,BOOL& bX64);

BOOL IsDigiSigEX(HANDLE hFile);

//�жϿ�ѡͷ��ȫ�ֶ��Ƿ���Ч
BOOL IsDigiSigW(LPCWSTR pPath);
BOOL IsDigiSigA(LPCSTR pPath);


//�ж�ʵ��ִ�к���
BOOL IsPEFileEX(HANDLE hFile);

/************************************************************************/
/* ���ã��ж�һ���ļ��ǲ���PE�ļ�                                       */
/* �ⲿ����
/************************************************************************/
BOOL IsPEFileW(LPCWSTR pPath);
BOOL IsPEFileA(LPCSTR pPath);
