#pragma once
#include "Tcp_stream.h"
#include <string>
#include <iostream>
#include <map>
#include <vector>
#include <algorithm>
#include <fstream>
#include <set>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "boost/date_time/posix_time/posix_time.hpp"
#include "json.hpp"

using jsonnlohmann = nlohmann::json;

class Ip_stream
{
private:

	std::string srcIP;
	std::string dstIP;
	boost::filesystem::path fl_fileName;
	boost::filesystem::path rl_fileName;
	std::vector<std::string> fl_files;
	std::vector<std::string> rl_files;	
	std::map<std::string, Tcp_stream*> tcp_streams_map;
	uint64_t src_dst, dst_src;
	std::set<std::string> folders_FL;
	std::set<std::string> folders_RL;


public:
	Ip_stream();
	~Ip_stream();
	Ip_stream(std::string, std::string , std::string filename, bool is_fl); //overloaded contructor
	int ip_equals(const Ip_stream &that) const;
	std::string get_ip_srcIP();
	std::string get_ip_dstIP();
	std::string Ip_stream::get_fl_file();
	std::string Ip_stream::get_rl_file();
	boost::filesystem::path fl_files_return();
	boost::filesystem::path rl_files_return();
	std::pair<std::string , std::string> split_string(std::string str); // splits string and returns two values
	void is_fl_rl(std::string ip_src_dst, bool if_fl_rl, std::string file_name); // function to check if the file is fl or 
	jsonnlohmann get_statistics();
	void update(std::string port, uint64_t sequence, uint64_t acknowlegement);

	//void store_data();
	
};