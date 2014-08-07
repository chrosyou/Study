
#include "StudyHeader.h"
#include "SignInfo.h"
#include <iostream>
using namespace std;
int main()
{
	//123
	DIGITALINFO info;
	SignInfo test;
	cout<<test.GetDigSign(_T("1.exe"), info); 

	return 0;
}