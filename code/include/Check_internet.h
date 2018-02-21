#pragma once
#include <iostream>
#include <windows.h> 
#include <wininet.h>
#include <tchar.h>

#pragma comment(lib, "wininet.lib")


class Check_internet
{
private:
	bool isInternet = false;
public:
	Check_internet();
	~Check_internet();
	bool checkInternet();
};

