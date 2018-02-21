#include "Ip_stream.h"
#include "json.hpp"
#include <cstddef>  
#include "iostream"
#include <string>

using namespace std;
using jsonnlohmann = nlohmann::json;


Ip_stream::Ip_stream() //default constructor	
{
	
}


Ip_stream::~Ip_stream() //default deconstructor
{
}

std::string Ip_stream::get_ip_srcIP() {
	return srcIP;
}

std::string Ip_stream::get_ip_dstIP() {
	return dstIP;
}


boost::filesystem::path Ip_stream::fl_files_return()
{
	return fl_fileName;
}

boost::filesystem::path Ip_stream::rl_files_return()
{
	return rl_fileName;
}



Ip_stream::Ip_stream(std::string src, std::string dst , std::string filename , bool is_fl) {//overloaded constrcutor
	srcIP = src;
	dstIP = dst;
	if(is_fl)
	{
		fl_fileName = filename;
	}
	else
	{
		rl_fileName = filename;
	}
	src_dst = dst_src = 0;
}


/*equal function*/
int Ip_stream::ip_equals(const Ip_stream &that)  const
{
	if ((strcmp(srcIP.c_str(), that.srcIP.c_str()) == 0) && (strcmp(dstIP.c_str(), that.dstIP.c_str()) == 0))/* A to B */
		return 0;
	if ((strcmp(srcIP.c_str(), that.dstIP.c_str()) == 0) && (strcmp(dstIP.c_str(), that.srcIP.c_str()) == 0))/*B to A*/
		return 1;
	else
		return 2;
}

std::pair<std::string , std::string> Ip_stream::split_string(std::string str) //function to split string and return two values as pair
{
	std::size_t found = str.find_first_of(":"); //separating src and dst port
    std::string str1 = str.substr(0, found); // converting src port from string to uint32_t
	std::string str2 = str.substr(found + 1); // converting src port from string to uint32_t
	return std::make_pair(str1,str2);
}


void Ip_stream::update(std::string port , uint64_t sequence , uint64_t acknowlegement)
{
	uint32_t src_port= stoi(split_string(port).first);
	uint32_t dst_port= stoi(split_string(port).second);
	Tcp_stream* tcp_stream;
	
	if (tcp_streams_map.find(port) == tcp_streams_map.end()) //if not found
	{
		tcp_stream = new Tcp_stream(src_port, dst_port, sequence, acknowlegement);
		tcp_streams_map.insert(std::pair<std::string, Tcp_stream*>(port, tcp_stream));	
	}
	else
	{
		tcp_stream = tcp_streams_map.at(port);	
		tcp_stream->update_se_ack(sequence, acknowlegement);
	}
}



jsonnlohmann Ip_stream::get_statistics()
{
	jsonnlohmann root;
	for (auto it = tcp_streams_map.begin(); it != tcp_streams_map.end(); ++it)
	{		
		root["srcPort"] = it->second->get_src_port();
		root["dstPort"] = it->second->get_dst_port();

		jsonnlohmann sequence(it->second->get_seq_num());
		root["seq_num"] = sequence;
		
		jsonnlohmann ack(it->second->get_ack_num());
		root["ack_num"] = ack;	
	}
	return root;
}




