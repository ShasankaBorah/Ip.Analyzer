#include "sizeCalculate.h"
#include <cstdint>
#include <string>
#include <iostream>

sizeCalculate::sizeCalculate()
{
}


sizeCalculate::~sizeCalculate()
{
}


std::string sizeCalculate::sizeCalculator(uint32_t size)
{

	float						result;
	float						tb = 1099511627776;
	float						gb = 1073741824;
	float						mb = 1048576;
	float						kb = 1024;

	if (size >= tb)
	{
		result = float(size) / tb;
		std::string re = std::to_string(result);
		re = re + "TB";
		return re;
	}
	else if (size >= gb && size < tb)
	{
		result = float(size) / gb;
		std::string re = std::to_string(result);
		re = re + "Gb";
		return re;
	}
	else if (size >= mb && size < gb)
	{
		result = float(size) / mb;
		std::string re = std::to_string(result);
		re = re + "MB";
		return re;
	}
	else if (size >= kb && size < mb)
	{
		result = float(size) / kb;
		std::string re = std::to_string(result);
		re = re + "KB";
		return re;
	}
	else
	{
		std::string re = std::to_string(size);
		re = re + "Bytes";
		return re;
	}
}