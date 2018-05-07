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
#include <pcap/pcap.h>

using jsonnlohmann = nlohmann::json;

Tcp_stream::Tcp_stream()
{
}


Tcp_stream::~Tcp_stream()
{
}

uint32_t Tcp_stream::get_src_port()
{
	return tcp_src_port;
}

uint32_t Tcp_stream::get_dst_port()
{
	return tcp_dst_port;
}

vector<uint64_t> Tcp_stream::get_seq_num()
{
	return tcp_seq_no_vec;
}

vector<uint64_t> Tcp_stream::get_ack_num()
{
		return tcp_ack_no_vec;
}

Tcp_stream::Tcp_stream(uint32_t s, uint32_t d, uint64_t se_n, uint64_t ack_n )
{
	tcp_src_port = s;
	tcp_dst_port = d;
	tcp_seq_no_vec.push_back(se_n);
	tcp_ack_no_vec.push_back(ack_n);
}

Tcp_stream::Tcp_stream(std::string srcIP, std::string dstIP)
{
	tcp_srcIP = srcIP;
	tcp_dstIP = dstIP;
	src_dst = dst_src = 0;
}

void Tcp_stream::increment_tcp_src_dst()
{
	src_dst++;
}

void Tcp_stream::increment_tcp_dst_src()
{
	dst_src++;
}

int Tcp_stream::getSrcDstCount()
{
	return src_dst;
}

int Tcp_stream::getDstSrcCount()
{
	return dst_src;
}


std::string Tcp_stream::getSrcIP()
{
	return tcp_srcIP;
}


std::string Tcp_stream::getDstIP()
{
	return tcp_dstIP;
}


void Tcp_stream::add_folder_FL(string str) {
	folders_FL.insert(str);
}

void Tcp_stream::add_folder_RL(string str) {
	folders_RL.insert(str);
}

void Tcp_stream::add_pcap_file_FL(string str) {
	pcap_files_FL.insert(str);
}

void Tcp_stream::add_pcap_file_RL(string str) {
	pcap_files_RL.insert(str);
}


void Tcp_stream::update_se_ack(uint64_t se , uint64_t ack)
{
	tcp_seq_no_vec.push_back(se);
	tcp_ack_no_vec.push_back(ack);
}

int Tcp_stream::tcp_equals(const Tcp_stream& that) const
{
	if ((strcmp(tcp_srcIP.c_str(), that.tcp_srcIP.c_str()) == 0) && (strcmp(tcp_dstIP.c_str(), that.tcp_dstIP.c_str()) == 0))/* A to B */
		return 0;
	if ((strcmp(tcp_srcIP.c_str(), that.tcp_dstIP.c_str()) == 0) && (strcmp(tcp_dstIP.c_str(), that.tcp_srcIP.c_str()) == 0))/*B to A*/
		return 1;
	else
		return 2;
}

std::pair<std::string, std::string> Tcp_stream::split_string(std::string str) //function to split string and return two values as pair
{
	std::size_t found = str.find_first_of(":");			//separating src and dst port
	std::string str1 = str.substr(0, found);			// converting src port from string to uint32_t
	std::string str2 = str.substr(found + 1);			// converting src port from string to uint32_t
	return std::make_pair(str1, str2);
}


void Tcp_stream::update(std::string port, uint64_t se, uint64_t ack)
{
	uint32_t src_port = stoi(split_string(port).first);
	uint32_t dst_port = stoi(split_string(port).second);
	Tcp_stream* tcp_stream;

	if (tcp_streams_map.find(port) == tcp_streams_map.end()) //if not found
	{
		tcp_stream = new Tcp_stream(src_port, dst_port, se, ack);
		tcp_streams_map.insert(std::pair<std::string, Tcp_stream*>(port, tcp_stream));
	}
	else
	{
		tcp_stream = tcp_streams_map.at(port);
		tcp_stream->update_se_ack(se, ack);
	}
}

jsonnlohmann Tcp_stream::get_statistics()
{
	jsonnlohmann root;

	root["srcIP"]				= getSrcIP();
	root["dstIP"]				= getDstIP();
	root["src_dst"]				= getSrcDstCount();
	root["dst_src"]				= getDstSrcCount();

	std::string str;

	//FL file iterator
	for (auto it = pcap_files_FL.begin(); it != pcap_files_FL.end(); ++it) 
	{
		str = it->filename().string();
		if (str.front() == '"') {
			str.erase(0, 1);  //algo to remove quote
			str.erase(str.size() - 1);
		}
		root["files_FL"].push_back(str);
		str.clear();
	}

	//RL file Iterator
	for (auto it = pcap_files_RL.begin(); it != pcap_files_RL.end(); ++it) 
	{
		str = it->filename().string();
		if (str.front() == '"') {
			str.erase(0, 1);  //algo to remove quote
			str.erase(str.size() - 1);
		}
		root["files_RL"].push_back(str);
		str.clear();
	}

	/*for(auto it = tcp_streams_map.begin() ; it!= tcp_streams_map.end() ; ++it)
	{
		jsonnlohmann j_inner_root;
		jsonnlohmann j_src_port;
		jsonnlohmann j_dst_port;

		root["src_port"].push_back(it->second->get_src_port());
		root["dst_port"].push_back(it->second->get_dst_port());

	
		jsonnlohmann sequence(it->second->get_seq_num());
		root["seq_num"] = sequence;

		jsonnlohmann acknowledgement(it->second->get_ack_num());
		root["ack_num"] = acknowledgement;

	}*/

	std::ofstream o("pretty.json");

	o << root;
	o.close();
	return root;
}





