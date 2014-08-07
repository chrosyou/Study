
/************************************************************************/
/*   版权信息：macalyou
/*   项目名称：Study
/*	 文件名称：SignInfo.h
/*	 用途    ：获得文件的签名信息
/*   版本    ：1.0
/*	 作者    ：you
/*	 创建日期：2014.8.7
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
#define ERROR_SIGNINFO_CRYPTQUERYOBJECT			1	//CryptQueryObject函数出错
#define ERROR_SIGNINFO_CRYPTMSGGETPARAM_SIZE	2	//CryptMsgGetParam函数获得signer size出错
#define ERROR_SIGNINFO_LOCALALLOC				3   //LocalAlloc函数分配内存失败
#define ERROR_SIGNINFO_CRYPTMSGGETPARAM			4	//CryptMsgGetParam函数获得msg handle出错
#define ERROR_SIGNINFO_CERTFIND					5	//CertFindCertificateInStore函数出错
#define ERROR_SIGNINFO_GETNAME_SIZE				6	//CertGetNameString函数获取大小出错

#define ERROR_SIGNINFO_FILEPATH					10  //传进的文件参数出错
#define ERROR_SIGNINFO_DECODEOBJECT_SIZE		11  //CryptDecodeObject获得大小失败
#define ERROR_SIGNINFO_DECODEOBJECT				12  //CryptDecodeObject获得信息失败

//用于保存传回的签名信息
typedef struct _DIGITALINFO
{
	_tstring sProgramName;
	_tstring sPublishInfo;
	_tstring sMoreInfo;
	_tstring sIssureName;
	_tstring sSubjectName;
}DIGITALINFO,*PDIGITALINFO;

/************************************************************************/
/*  作用：判断数字签名，获取相关信息 
/*  类名：FileTrustCheck
/************************************************************************/
class SignInfo
{
public:
	SignInfo();
	~SignInfo();

	//判断数字签名是否有效
	//有效则返回0，无效返回非0,对应WinVarifyTrust的返回值
	LONG VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);

	//获得数字签名的详细信息
	//返回0表示成功，相应信息在info里，
	//返回非0，失败，info信息不可信
	BOOL GetDigSign(LPCWSTR pwszSourceFile,DIGITALINFO &info);

private:
	_tstring sProgramName;
	_tstring sPublishInfo;
	_tstring sMoreInfo;
	_tstring sIssureName;
	_tstring sSubjectName;

	//获得公司和出版信息
	BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo);
};