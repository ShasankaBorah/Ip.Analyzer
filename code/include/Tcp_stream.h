#pragma once
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
#include <string>
#include <boost/asio/ip/impl/address.ipp>

using namespace std;
using jsonnlohmann = nlohmann::json;

class Tcp_stream
{
private:
	uint32_t									tcp_src_port;
	uint32_t									tcp_dst_port;
	std::vector<uint64_t>						tcp_seq_no_vec;
	std::vector<uint64_t>						tcp_ack_no_vec;
	std::string									tcp_srcIP, tcp_dstIP;
	uint64_t									src_dst, dst_src;
	std::set<std::string>						folders_FL;
	std::set<std::string>						folders_RL;
	std::set<boost::filesystem::path>			pcap_files_FL; //set for Unique FL Files
	std::set<boost::filesystem::path>			pcap_files_RL; //set for Unique RL Files
	std::map<std::string, Tcp_stream*>			tcp_streams_map;
	static const int							PCAP_FILE_HEADER_LENGTH = 24;
	std::map<std::string, std::ofstream*>		binMap;

	unsigned char								globalHeader[PCAP_FILE_HEADER_LENGTH] =
												{ 212, 195, 178, 161, // Magic number
													02, 00,    // Major version
													04, 00,    // Minor version
													0,0,0,0,0,0,0,0,  // Time zone, Timestamp accuracy
													0, 0, 4, 0,  // Shapshot length
													1,0,0,0                // Link layer type
												};


public:
	Tcp_stream();
	~Tcp_stream();
	Tcp_stream(std::string, std::string);
	Tcp_stream(uint32_t s, uint32_t d, uint64_t se_n, uint64_t ack_n);

	uint32_t									get_src_port();
	uint32_t									get_dst_port();
	vector<uint64_t>							get_seq_num();
	vector<uint64_t>							get_ack_num();
	std::string									getSrcIP();
	std::string									getDstIP();
	int											tcp_equals(const Tcp_stream &that) const;
	int											getSrcDstCount();
	int											getDstSrcCount();	
	void										update_se_ack(uint64_t se, uint64_t ack); //se = sequence number and ack = acknowledgement number
	void										increment_tcp_src_dst();
	void										increment_tcp_dst_src();
	void										add_folder_FL(std::string str);
	void										add_folder_RL(std::string str);
	void										add_pcap_file_FL(std::string str);
	void										add_pcap_file_RL(std::string str);
	void										update(std::string port , uint64_t se , uint64_t ack);	
	void										createOutDir(std::string srcIP, std::string dstIP, uint32_t srcPort, uint32_t dstPort, const u_char* data, struct pcap_pkthdr* head); /*creates outpiut directory and then calls writeToBin*/
	void										writeToBin(std::string srcIP, std::string dstIP, uint32_t srcPort, uint32_t dstPort, const u_char* data, struct pcap_pkthdr* header);
	void										closeBinMap();
	std::pair<std::string, std::string>			split_string(std::string str);
	jsonnlohmann								get_statistics();
};

