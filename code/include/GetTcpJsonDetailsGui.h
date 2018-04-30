#pragma once
#include "boost/filesystem.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <iostream>
#include <conio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <conio.h>
#include <map>
#include <set>
#include <Configuration.h>
#include <json.hpp>

using namespace std;
using namespace boost::filesystem;
//namespace pt = boost::posix_time;
//namespace ptree = boost::property_tree;
using jsonnlohmann = nlohmann::json;

class GetTcpJsonDetailsGui
{
public:
	GetTcpJsonDetailsGui();
	~GetTcpJsonDetailsGui();
	void getJsonData(std::string str);
	bool find_file(const path& dir_path, const path& file_name, path& path_found);
	void writePcapDataToJson(std::string file_name); //filename to search and write data to 
	std::string replaceString(std::string stringToReplace);
	std::string jsonToSendToGui();

private:
	jsonnlohmann j = jsonnlohmann::object();
};

