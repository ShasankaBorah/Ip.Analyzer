#include "GetDnsJsonDetailsGui.h"
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

using namespace std;
using					jsonnlohmann = nlohmann::json;
extern					std::string getJSON_string_from_jsonC(jsonnlohmann json);




GetDnsJsonDetailsGui::GetDnsJsonDetailsGui()
{
}


GetDnsJsonDetailsGui::~GetDnsJsonDetailsGui()
{
}

void GetDnsJsonDetailsGui::getJsonData(std::string str)
{
	jsonnlohmann jsonToSend;

	std::string fileName = str;

	std::string filenameJsonExtension = fileName + ".json";

	std::string path_ = "dnsAnalysisData\\dnsJson\\";
	const path myPath = path_.c_str();

	path myFound;
	bool k = find_file(myPath, filenameJsonExtension, myFound);
	if (false == k) /*if the file is not foind in the directory*/
	{
		writePcapDataToJson(fileName);

	}
	std::ifstream i(path_ + filenameJsonExtension);
	std::stringstream ss;

	if (i)
	{
		ss << i.rdbuf();
		i.close();
	}

	j["dns_packet_info"] = ss.str();
}

bool GetDnsJsonDetailsGui::find_file(const path& dir_path, const path& file_name, path& path_found)
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


void GetDnsJsonDetailsGui::writePcapDataToJson(std::string file_name)
{
	std::string tsharkStartString = "\"C:\\Program Files\\Wireshark\\tshark.exe\" -r dnsAnalysisData\\dnsBin\\";
	std::string tsharkFilterString = ".pcap -Tjson -e dns.id -e dns.qry.name -e dns.resp.name > ";

	std::string jsonFileName = "dnsAnalysisData\\dnsJson\\" + file_name + ".json";

	std::string tsharkCommandString = tsharkStartString + file_name + tsharkFilterString + jsonFileName;

	system(tsharkCommandString.c_str());
}

std::string GetDnsJsonDetailsGui::jsonToSendToGui()
{
	j["type"] = "ipJsonResult";
	return getJSON_string_from_jsonC(j);
}
