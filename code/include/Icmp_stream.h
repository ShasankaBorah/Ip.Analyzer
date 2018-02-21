#pragma once
#include <string>
#include <iostream>
#include <map>
#include <vector>
#include <algorithm>
#include <fstream>
#include <set>
#include <json.hpp>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "boost/date_time/posix_time/posix_time.hpp"

namespace ptree = boost::property_tree;
using jsonnlohmann = nlohmann::json;

class Icmp_stream
{

private:

	struct icmp_pair{
		uint64_t reqTimeStamp;
		uint64_t repTimeStamp;
		uint64_t unreachableTimeStamp;
		uint64_t ttlExcessTimeStamp;
		int sequence_number;
		bool unsupported_type;
		bool ttlExceeded;
		bool destUnreachable;
		bool request;
		bool reply;		
	}ic_pair; 

	std::string icmp_srcIP,icmp_dstIP;
	uint64_t src_dst, dst_src;
	
	std::map<int,icmp_pair> icmp_pair_map; //key =sequence 
	ptree::ptree pt_icmp;
	
    std::set<std::string> folders_FL;
    std::set<std::string> folders_RL;

    std::set<boost::filesystem::path> pcap_files_FL; //set for Unique FL Files
    std::set<boost::filesystem::path> pcap_files_RL; //set for Unique RL Files

public:
	Icmp_stream(void);
	~Icmp_stream(void);
	Icmp_stream(std::string,std::string);//overloaded constructor
	int icmp_equals(const Icmp_stream &that) const;
	void update_icmp_pair_info(/*bool*/ int, int , uint64_t);
	std::string get_icmp_srcIP();
	std::string get_icmp_dstIP();
	jsonnlohmann get_statistics();
	uint64_t get_count_src_dst();
	uint64_t get_count_dst_src();
	void increment_icmp_src_dst();
	void increment_icmp_dst_src();	
    void add_folder_FL(std::string str);
    void add_folder_RL(std::string str);
    void add_pcap_file_FL(std::string str);
    void add_pcap_file_RL(std::string str);

};

