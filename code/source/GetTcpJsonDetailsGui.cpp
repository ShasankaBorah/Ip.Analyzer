#include "GetTcpJsonDetailsGui.h"
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
#include <sstream>



/******************************************************************************************************
 *This class is used to get the json from the individual pcap file that has been generated 
 *previously using the function writeToBin in th class Tcp_stream_writer.
 *
 *File name received fgrom the gui is first checked for the existence in the folder 
 *if the json is not found then tshark is used to read the respective pcap file and write the 
 *desired data in the json file
 ******************************************************************************************************/

using namespace std;
using					jsonnlohmann = nlohmann::json;
extern					std::string getJSON_string_from_jsonC(jsonnlohmann json);

GetTcpJsonDetailsGui::GetTcpJsonDetailsGui()
{
}


GetTcpJsonDetailsGui::~GetTcpJsonDetailsGui()
{
}

void GetTcpJsonDetailsGui::getJsonData(std::string str)
{
	jsonnlohmann jsonToSend;

	std::string replacedFileName = replaceString(str);
	
	std::string replacedFilenameJsonExtension = replacedFileName + ".json";
	
	std::string path_ = "tcpAnalysisData\\tcpJson\\";
	const path myPath = path_.c_str();
	//std::vector<std::string>::value_type fileName;
	
	path myFound;
	bool k = find_file(myPath, replacedFilenameJsonExtension, myFound);
	if(false == k) /*if the file is not foind in the directory*/
	{
		writePcapDataToJson(replacedFileName);
		
	}
	std::ifstream i(path_ + replacedFilenameJsonExtension);
	std::stringstream ss;

	if(i)
	{	
		ss << i.rdbuf();
		i.close();
		
	}

	j["tcp_pcaket_info"] = ss.str();
	
}

bool GetTcpJsonDetailsGui::find_file(const path& dir_path, const path& file_name, path& path_found)
{
	const recursive_directory_iterator end;
	const auto it = find_if(recursive_directory_iterator(dir_path), end,
		[&file_name](const directory_entry& e) {
		return e.path().filename() == file_name;
	});
	if (it == end) {
		return false;
	}
	else {
		path_found = it->path();
		return true;
	}
}


void GetTcpJsonDetailsGui::writePcapDataToJson(std::string file_name)
{
	
		std::string tsharkStartString = "\"C:\\Program Files\\Wireshark\\tshark.exe\" -r tcpAnalysisData\\tcpBin\\";
		std::string tsharkFilterString = ".pcap -t d -Tjson -e frame.time -e tcp.seq -e tcp.ack -e tcp.len -e tcp.srcport -e tcp.dstport -e tcp.flags > ";

		//std::size_t found = it->first.find_last_of("."); //separating src and dst port
		//std::string str = it->first.substr(0, found);
		std::string jsonFileName = "tcpAnalysisData\\tcpJson\\" + file_name + ".json";

		std::string tsharkCommandString = tsharkStartString + file_name +  tsharkFilterString + jsonFileName;

		system(tsharkCommandString.c_str());	
	
}

std::string GetTcpJsonDetailsGui::replaceString(std::string stringToReplace)
{
	size_t found1 = stringToReplace.find_first_of(":");
	stringToReplace.replace(found1, 1, "_");

	size_t found2 = stringToReplace.find_last_of(":");
	stringToReplace.replace(found2, 1, "_");

	return stringToReplace;
 }

std::string GetTcpJsonDetailsGui::jsonToSendToGui()
{
	j["type"] = "ipJsonResult";
	return getJSON_string_from_jsonC(j);
}
