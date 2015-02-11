
#include "StudyHeader.h"
#include "SignInfo.h"
#include "PEFile.h"
#include <iostream>
using namespace std;
int main()
{
	//1234
	TCHAR test[10] = {0};
	DWORD d = 0xabcd;
	char b = '!';
	_stprintf_s(test, 10, _T("%X"), d);

	return 0;
}