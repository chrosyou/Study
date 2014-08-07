
/************************************************************************/
/*   ��Ȩ��Ϣ��macalyou
/*   ��Ŀ���ƣ�Study
/*	 �ļ����ƣ�SignInfo.cpp
/*	 ��;    ������ļ�������ǩ��
/*   �汾    ��1.0
/*	 ����    ��you
/*	 �������ڣ�2014.8.7
/************************************************************************/

#include "SignInfo.h"
#include <wintrust.h>	//����ǩ�����
#include <Softpub.h>	//����ǩ�����
#include <wincrypt.h>

#pragma comment(lib, "wintrust")	//	WinVarifyTrust����ǩ��
#pragma comment(lib, "crypt32.lib")  //CryptQueryObject 

SignInfo::SignInfo()
{
	sProgramName.clear();
	sPublishInfo.clear();
	sMoreInfo.clear();
	sIssureName.clear();
	sSubjectName.clear();
}

SignInfo::~SignInfo(){}

LONG SignInfo::VerifyEmbeddedSignatureW(LPCWSTR pwszSourceFile)
{
	LONG lStatus;
	//DWORD dwLastError;

	// Initialize the WINTRUST_FILE_INFO structure.
	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;
	memset(&WinTrustData, 0, sizeof(WinTrustData));  //Ĭ�ϳ�ʼ��Ϊ0
	WinTrustData.cbStruct = sizeof(WinTrustData);	//��С
	WinTrustData.pPolicyCallbackData = NULL;	//һ��ΪNull
	WinTrustData.pSIPClientData = NULL;	//
	WinTrustData.dwUIChoice = WTD_UI_NONE; //��ʾ����
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WinTrustData.hWVTStateData = NULL;
	WinTrustData.pwszURLReference = NULL;
	WinTrustData.dwUIContext = 0;
	WinTrustData.pFile = &FileData;

	//����ֵ��֪����ǩ���Ƿ���Ч������Чԭ��
	lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	return lStatus;
}

LONG SignInfo::VerifyEmbeddedSignatureA(LPCSTR pszSourceFile)
{
	std::string s = pszSourceFile;
	std::wstring ws;
	StringToWString(s, ws);
	return VerifyEmbeddedSignatureW(ws.c_str());
}

BOOL SignInfo::GetDigSignW(LPCWSTR pwszSourceFile, DIGITALINFO &info)
{
	if (pwszSourceFile == NULL)
	{
		assert(0);
		return ERROR_SIGNINFO_FILEPATH;  //�ļ�·��Ϊ��
	}
	SignInfo();

	BOOL bResult = FALSE;
	BOOL bReturn = FALSE;
	DWORD dwEncoding, dwContentType, dwFormatType;
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	DWORD dwSignerInfo;
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	CERT_INFO CertInfo;
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD dwData; //���ǩ����Ϣ��С
	TCHAR tName[MAX_PATH];


	//����ļ���message handle��store handle
	//���ط�0�ɹ���0ʧ�ܣ�����GetLastError()
	bResult = CryptQueryObject(
		CERT_QUERY_OBJECT_FILE,	//�ļ�����
		pwszSourceFile, //�ļ���
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,	//����PKS7ǩ����Ϣ
		CERT_QUERY_FORMAT_FLAG_BINARY,					//��������Ϣ����
		0,				//�����ֶ�
		&dwEncoding,	//����ǩ���ı�������
		&dwContentType,//������ʵ�����ݸ�ʽ
		&dwFormatType,	//���ظ�ʽ����Ϣ
		&hStore,		//����һ���������������ǩ����Ϣ
		&hMsg,			//����һ���Ѵ���Ϣ�ľ��
		NULL);			//����Ķ�����Ϣ
	if (!bResult)
	{
		bResult =  ERROR_SIGNINFO_CRYPTQUERYOBJECT;	//CryptQueryObject��������
		goto FREEHANDLE;
	}


	// Get signer information size.
	bResult = CryptMsgGetParam(
		hMsg, 
		CMSG_SIGNER_INFO_PARAM, 
		0, 
		NULL, 
		&dwSignerInfo);
	if (!bResult)
	{
		bResult = ERROR_SIGNINFO_CRYPTMSGGETPARAM_SIZE; //CryptMsgGetParam��������
		goto FREEHANDLE;
	}

	// Allocate memory for signer information.
	pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
	if (pSignerInfo == NULL)
	{
		bResult =  ERROR_SIGNINFO_LOCALALLOC;  //MSG�����ڴ�ʧ��
		goto FREEHANDLE;
	}

	// Get Signer Information.
	bResult = CryptMsgGetParam(hMsg, 
		CMSG_SIGNER_INFO_PARAM, 
		0, 
		(PVOID)pSignerInfo, 
		&dwSignerInfo);
	if (!bResult)
	{
		bResult =  ERROR_SIGNINFO_CRYPTMSGGETPARAM;
		goto FREEHANDLE;
	}

	//��ù�˾��Ϣ
	GetProgAndPublisherInfo(pSignerInfo);

	// Search for the signer certificate in the temporary 
	// certificate store.
	CertInfo.Issuer = pSignerInfo->Issuer;
	CertInfo.SerialNumber = pSignerInfo->SerialNumber;

	pCertContext = CertFindCertificateInStore(hStore,
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		0,
		CERT_FIND_SUBJECT_CERT,
		(PVOID)&CertInfo,
		NULL);
	if (!pCertContext)
	{
		bResult = ERROR_SIGNINFO_CERTFIND;
		goto FREEHANDLE;
	}

	// Get Issuer name size.
	if (!(dwData = CertGetNameString(pCertContext, 
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		CERT_NAME_ISSUER_FLAG,
		NULL,
		NULL,
		0)))
	{
		bResult = ERROR_SIGNINFO_GETNAME_SIZE;
		goto FREEHANDLE;
	}
	if (!(CertGetNameString(pCertContext, 
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		CERT_NAME_ISSUER_FLAG,
		NULL,
		tName,
		dwData)))
	{
		bResult = ERROR_SIGNINFO_GETNAME_SIZE;
		goto FREEHANDLE;
	}
    sIssureName = tName;

	// Get Subject name size.
	if (!(dwData = CertGetNameString(pCertContext, 
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		NULL,
		NULL,
		0)))
	{
		bResult = ERROR_SIGNINFO_GETNAME_SIZE;
		goto FREEHANDLE;
	}
	// Get subject name.
	if (!(CertGetNameString(pCertContext, 
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		NULL,
		tName,
		dwData)))
	{
		bResult = ERROR_SIGNINFO_GETNAME_SIZE;
		goto FREEHANDLE;
	}
	sSubjectName = tName;
	bResult = ERROR_SIGNINFO_SUCCESS;


FREEHANDLE:
	if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
	if (pSignerInfo != NULL) LocalFree(pSignerInfo);
	if (hStore != NULL) CertCloseStore(hStore, 0);
	if (hMsg != NULL)   CryptMsgClose(hMsg);

#ifdef UNICODE
	info.sMoreInfo	 = sMoreInfo;
	info.sProgramName= sProgramName;
	info.sPublishInfo= sPublishInfo;
#else
	WStringToString(sMoreInfo, info.sMoreInfo);
	WStringToString(sProgramName, info.sProgramName);
	WStringToString(sPublishInfo, info.sPublishInfo);
#endif // UNICODE

	info.sIssureName = sIssureName;
	info.sSubjectName= sSubjectName;

	return bResult;
}

BOOL SignInfo::GetDigSignA(LPCSTR pszSourceFile, DIGITALINFO &info)
{
	std::string s = pszSourceFile;
	std::wstring ws;
	StringToWString(s, ws);
	return GetDigSignW(ws.c_str(), info );
}

BOOL SignInfo::GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo)
{
	BOOL fResult = FALSE;
	BOOL fReturn = FALSE;
	DWORD dwData = 0;
	PSPC_SP_OPUS_INFO OpusInfo = NULL;

	for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
	{           
		if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID, pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
		{
			// Get Size of SPC_SP_OPUS_INFO structure.
			fResult = CryptDecodeObject(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				SPC_SP_OPUS_INFO_OBJID,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				NULL,
				&dwData);
			if (!fResult)
			{
				fResult = ERROR_SIGNINFO_DECODEOBJECT_SIZE;
				goto FREELOCAL;
			}

			// Allocate memory for SPC_SP_OPUS_INFO structure.
			OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData);
			if (!OpusInfo)
			{
				fResult = ERROR_SIGNINFO_LOCALALLOC;
				goto FREELOCAL;
			}

			// Decode and get SPC_SP_OPUS_INFO structure.
			fResult = CryptDecodeObject(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				SPC_SP_OPUS_INFO_OBJID,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				OpusInfo,
				&dwData);
			if (!fResult)
			{
				fResult = ERROR_SIGNINFO_DECODEOBJECT_SIZE;
				goto FREELOCAL;
			}

			// Fill in Program Name if present.��Ŀ��
			sProgramName = OpusInfo->pwszProgramName;

			// Fill in Publisher Information if present.��ó�����
			if (OpusInfo->pPublisherInfo)
			{
				switch (OpusInfo->pPublisherInfo->dwLinkChoice)
				{
				case SPC_URL_LINK_CHOICE:
					sPublishInfo = OpusInfo->pPublisherInfo->pwszUrl;
					break;

				case SPC_FILE_LINK_CHOICE:
					sPublishInfo = OpusInfo->pPublisherInfo->pwszFile;
					break;

				default:
					break;
				}
			}

			// Fill in More Info if present. ������Ϣ
			if (OpusInfo->pMoreInfo)
			{
				switch (OpusInfo->pMoreInfo->dwLinkChoice)
				{
				case SPC_URL_LINK_CHOICE:
					sMoreInfo = OpusInfo->pMoreInfo->pwszUrl;
					break;

				case SPC_FILE_LINK_CHOICE:
					sMoreInfo = OpusInfo->pMoreInfo->pwszFile;
					break;

				default:
					break;
				}
			}
		}
	}
	fResult = ERROR_SIGNINFO_SUCCESS;

FREELOCAL:
	if (OpusInfo != NULL) LocalFree(OpusInfo); 
	return fResult;
}