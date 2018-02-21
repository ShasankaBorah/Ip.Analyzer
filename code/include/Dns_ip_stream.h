#pragma once
#include "stdafx.h"
#include "boost/filesystem.hpp"
#include <boost/property_tree/ptree.hpp>
#include <iostream>
#include <conio.h>
#include <string.h>
#include <pcap.h>
#include <conio.h>
#include <map>
#include <vector>
#include <set>
#include <json.hpp>

using jsonnlohmann = nlohmann::json;


class Dns_ip_stream
{
private:

	struct dns_pair
	{
		u_int16_t dns_id;
		bool request;
		bool reply;
	};

	std::string srcIP;
	std::string dstIP;
	
	uint64_t src_dst, dst_src;
	std::map<u_int16_t, dns_pair> dns_pair_map;

	std::set<std::string> folders_FL;
	std::set<std::string> folders_RL;

	std::set<boost::filesystem::path> pcap_files_FL; //set for Unique FL Files
	std::set<boost::filesystem::path> pcap_files_RL; //set for Unique RL Files



public:
	Dns_ip_stream();
	~Dns_ip_stream();
	Dns_ip_stream(std::string, std::string);
	int equals(const Dns_ip_stream &that) const;
	void increment_dns_src_dst();
	void increment_dns_dst_src();
	void update_info(u_int16_t id , u_int8_t qr);
	void add_folder_FL(std::string);
	void add_folder_RL(std::string);
	void add_pcap_file_FL(std::string);
	void add_pcap_file_RL(std::string);
	uint64_t get_count_src_dst();
	
	uint64_t get_count_dst_src();
	
	jsonnlohmann get_statistics();
};