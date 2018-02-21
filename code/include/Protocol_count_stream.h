#pragma once
#include "stdafx.h"
#include <iostream>
#include <conio.h>
#include <string.h>
#include <pcap.h>
#include <conio.h>
#include <map>
#include <vector>
#include <set>
#include <json.hpp>
#include "boost/filesystem.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace std;
using namespace boost::filesystem;
namespace pt = boost::posix_time;
using jsonnlohmann = nlohmann::json;

class Protocol_count_stream
{
private:
	std::map<std::string, int> protocol_count_map;
	std::set<boost::filesystem::path> fl_files_protocol_pair;
	std::set<boost::filesystem::path> rl_files_protocol_pair;
public:
	Protocol_count_stream();
	~Protocol_count_stream();

};