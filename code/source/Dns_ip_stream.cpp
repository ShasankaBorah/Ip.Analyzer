

#include "Dns_ip_stream.h"
#include "stdafx.h"
#include "boost/filesystem.hpp"
#include <boost/property_tree/ptree.hpp>
#include <iostream>
#include <conio.h>
#include <string.h>
#include <pcap.h>
#include <conio.h>
#include <map>
#include <set>
#include <Configuration.h>
#include <json.hpp>


using namespace std;
using jsonnlohmann = nlohmann::json;



Dns_ip_stream::Dns_ip_stream()
{
	
}

Dns_ip_stream::~Dns_ip_stream()
{
	
}

void Dns_ip_stream::increment_dns_src_dst()
{
	src_dst++;
}
void Dns_ip_stream::increment_dns_dst_src()
{
	dst_src++;
}

Dns_ip_stream::Dns_ip_stream(std::string A , std::string B)
{
	srcIP = A;
	dstIP = B;
	src_dst = 0;
	dst_src = 0;
}

void Dns_ip_stream::add_folder_FL(string str) {
	folders_FL.insert(str);
}

void Dns_ip_stream::add_folder_RL(string str) {
	folders_RL.insert(str);
}

void Dns_ip_stream::add_pcap_file_FL(string str) {
	pcap_files_FL.insert(str);
}

void Dns_ip_stream::add_pcap_file_RL(string str) {
	pcap_files_RL.insert(str);
}

uint64_t Dns_ip_stream::get_count_src_dst()
{
	return src_dst;
}
uint64_t Dns_ip_stream::get_count_dst_src()
{
	return dst_src;
}

void Dns_ip_stream::update_info(u_int16_t id , u_int8_t qr)
{
	if(dns_pair_map.find(id) == dns_pair_map.end())/*if the id is not found*/
	{
		dns_pair new_dns_pair;
		new_dns_pair.dns_id = id;
		new_dns_pair.request = false;
		new_dns_pair.reply = false;
		dns_pair_map.insert(std::pair<u_int16_t, dns_pair>(id, new_dns_pair));		
	}

	switch (qr)
	{
	case 0:
		dns_pair_map[id].request = true;
		break;
	case 1:
		dns_pair_map[id].reply = true;
		break;
	}
	
}


int Dns_ip_stream::equals(const Dns_ip_stream &that)  const
{
	if ((strcmp(srcIP.c_str(), that.srcIP.c_str()) == 0) && (strcmp(dstIP.c_str(), that.dstIP.c_str()) == 0))/* A to B */
		return 0;
	if ((strcmp(srcIP.c_str(), that.dstIP.c_str()) == 0) && (strcmp(dstIP.c_str(), that.srcIP.c_str()) == 0))/*B to A*/
		return 1;
	else
		return 2;
}

jsonnlohmann Dns_ip_stream::get_statistics()
{
	std::string str;
	jsonnlohmann root;

	root["SrcIp"] = srcIP;
	root["DstIp"] = dstIP;
	root["src_dst"] = get_count_src_dst();
	root["dst_src"] = get_count_dst_src();

	for (auto it = dns_pair_map.begin(); it != dns_pair_map.end(); ++it)
	{
		jsonnlohmann j_seq;
		j_seq["id"] = it->second.dns_id;
		j_seq["request"] = it->second.request;
		j_seq["reply"] = it->second.reply;
		

		root["sequence_array"].push_back(j_seq);
		j_seq.clear();
	}

	for (auto it = folders_FL.begin(); it != folders_FL.end(); ++it)
	{
		root["folders_FL"].push_back(*it);
	}

	for (auto it = pcap_files_FL.begin(); it != pcap_files_FL.end(); ++it)
	{
		str = it->filename().string();
		root["files_FL"].push_back(str);
	}

	for (auto it = folders_RL.begin(); it != folders_RL.end(); ++it)
	{
		root["folders_RL"].push_back(*it);
	}

	for (auto it = pcap_files_RL.begin(); it != pcap_files_RL.end(); ++it)
	{
		str = it->filename().string();
		root["files_RL"].push_back(str);
	}

	return root;
}
