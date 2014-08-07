
#include "StudyHeader.h"
#include "SignInfo.h"
#include "PEFile.h"
#include <iostream>
using namespace std;
int main()
{
	//123
	BOOL bResult = FALSE;
	cout<<IsPEFile(_T("Study.exe")); 

	return 0;
}