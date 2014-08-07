
#include "StudyHeader.h"
#include "SignInfo.h"
#include <iostream>
using namespace std;
int main()
{
	DIGITALINFO info;
	SignInfo test;
	cout<<test.GetDigSign(_T("2.exe"), info);

	return 0;
}