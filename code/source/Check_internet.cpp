#include "Check_internet.h"
#include <iostream>
#include <windows.h> 
#include <wininet.h>
#include <tchar.h>
#pragma comment(lib, "wininet.lib")



using namespace std;

Check_internet::Check_internet()
{
}


Check_internet::~Check_internet()
{
}

bool Check_internet::checkInternet()
{
	LPCTSTR s = _T("http://www.google.com"); 
	if (InternetCheckConnection(s, FLAG_ICC_FORCE_CONNECTION, 0) == true)
	{
		isInternet = true;
	}
	return isInternet;
}
