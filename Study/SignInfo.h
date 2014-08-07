
/************************************************************************/
/*   ��Ȩ��Ϣ��macalyou
/*   ��Ŀ���ƣ�Study
/*	 �ļ����ƣ�SignInfo.h
/*	 ��;    ������ļ���ǩ����Ϣ
/*   �汾    ��1.0
/*	 ����    ��you
/*	 �������ڣ�2014.8.7
/************************************************************************/

#include <windows.h>
#include <tchar.h>
#include <string>
#include <assert.h>

#ifndef _tstring
#ifdef UNICODE
#define _tstring std::wstring
#else
#define _tstring std::string
#endif  //UNICODE
#endif

#define ERROR_SIGNINFO_SUCCESS					0   // 
#define ERROR_SIGNINFO_CRYPTQUERYOBJECT			1	//CryptQueryObject��������
#define ERROR_SIGNINFO_CRYPTMSGGETPARAM_SIZE	2	//CryptMsgGetParam�������signer size����
#define ERROR_SIGNINFO_LOCALALLOC				3   //LocalAlloc���������ڴ�ʧ��
#define ERROR_SIGNINFO_CRYPTMSGGETPARAM			4	//CryptMsgGetParam�������msg handle����
#define ERROR_SIGNINFO_CERTFIND					5	//CertFindCertificateInStore��������
#define ERROR_SIGNINFO_GETNAME_SIZE				6	//CertGetNameString������ȡ��С����

#define ERROR_SIGNINFO_FILEPATH					10  //�������ļ���������
#define ERROR_SIGNINFO_DECODEOBJECT_SIZE		11  //CryptDecodeObject��ô�Сʧ��
#define ERROR_SIGNINFO_DECODEOBJECT				12  //CryptDecodeObject�����Ϣʧ��

//���ڱ��洫�ص�ǩ����Ϣ
typedef struct _DIGITALINFO
{
	_tstring sProgramName;
	_tstring sPublishInfo;
	_tstring sMoreInfo;
	_tstring sIssureName;
	_tstring sSubjectName;
}DIGITALINFO,*PDIGITALINFO;

/************************************************************************/
/*  ���ã��ж�����ǩ������ȡ�����Ϣ 
/*  ������FileTrustCheck
/************************************************************************/
class SignInfo
{
public:
	SignInfo();
	~SignInfo();

	//�ж�����ǩ���Ƿ���Ч
	//��Ч�򷵻�0����Ч���ط�0,��ӦWinVarifyTrust�ķ���ֵ
	LONG VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);

	//�������ǩ������ϸ��Ϣ
	//����0��ʾ�ɹ�����Ӧ��Ϣ��info�
	//���ط�0��ʧ�ܣ�info��Ϣ������
	BOOL GetDigSign(LPCWSTR pwszSourceFile,DIGITALINFO &info);

private:
	_tstring sProgramName;
	_tstring sPublishInfo;
	_tstring sMoreInfo;
	_tstring sIssureName;
	_tstring sSubjectName;

	//��ù�˾�ͳ�����Ϣ
	BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo);
};