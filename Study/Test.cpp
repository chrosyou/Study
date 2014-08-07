
#include "SignInfo.h"
#include "StudyHeader.h"
#include <iostream>
using namespace std;
int main()
{
	//123
	DIGITALINFO info;
	SignInfo test;
	cout<<test.GetDigSignW(_T("2.exe"), info); 

	return 0;
}