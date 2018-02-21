#include "Icmp_stream.h"
#include "json.hpp"
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

namespace ptree = boost::property_tree;
using namespace std;

#include <json.hpp>
using jsonnlohmann = nlohmann::json;

Icmp_stream::Icmp_stream(void)
{
}


Icmp_stream::~Icmp_stream(void)
{
}

Icmp_stream::Icmp_stream(std::string srcIP,std::string dstIP){//overloaded constrcutor
	icmp_srcIP = srcIP;
	icmp_dstIP = dstIP;
	src_dst = dst_src = 0;
}

void Icmp_stream::increment_icmp_src_dst()
{
	src_dst++;
}
void Icmp_stream::increment_icmp_dst_src()
{
	dst_src++;
}

uint64_t Icmp_stream::get_count_src_dst()
{
	return src_dst;
}
uint64_t Icmp_stream::get_count_dst_src()
{
	return dst_src;
}

string Icmp_stream::get_icmp_srcIP(){
	return icmp_srcIP;
}

string Icmp_stream::get_icmp_dstIP(){
	return icmp_dstIP;
}

void Icmp_stream::add_folder_FL(string str) {
    folders_FL.insert(str);
}

void Icmp_stream::add_folder_RL(string str) {
    folders_RL.insert(str);
}

void Icmp_stream::add_pcap_file_FL(string str) {
    pcap_files_FL.insert(str);
}

void Icmp_stream::add_pcap_file_RL(string str) {
    pcap_files_RL.insert(str);
}


/*equal function*/
int Icmp_stream::icmp_equals(const Icmp_stream &that)  const
{
	if ((strcmp(icmp_srcIP.c_str(), that.icmp_srcIP.c_str()) == 0) && (strcmp(icmp_dstIP.c_str(),that.icmp_dstIP.c_str())==0))/* A to B */
		return 0;
	if((strcmp(icmp_srcIP.c_str(), that.icmp_dstIP.c_str())==0) && (strcmp(icmp_dstIP.c_str(),that.icmp_srcIP.c_str())==0))/*B to A*/
		return 1;
	else 
		return 2;
}

void Icmp_stream::update_icmp_pair_info( int sequence_received, int request_type_received , uint64_t ts)
{
	// check if seq no exists in the map
	// if exists then update the req/reply to true
	// if not then create a new icmp_pair and set its req/rep and add to the map
	// add one more var to icmp_pair for unsupported type and set if that value comes. normally it shoudln't

	if(icmp_pair_map.find(sequence_received) == icmp_pair_map.end())//if sequence number not found
	{
		icmp_pair new_pair;
		new_pair.sequence_number = sequence_received;
		new_pair.reqTimeStamp = 0;
		new_pair.repTimeStamp = 0;
		new_pair.unreachableTimeStamp = 0;
		new_pair.ttlExcessTimeStamp = 0;
		new_pair.request = false;
		new_pair.reply = false;
		new_pair.unsupported_type = false;
		new_pair.ttlExceeded = false;
		new_pair.destUnreachable = false;
		icmp_pair_map.insert(std::pair<int,icmp_pair>(sequence_received, new_pair));
	}

	switch(request_type_received){
	case 8:
		icmp_pair_map[sequence_received].request = true;
		icmp_pair_map[sequence_received].reqTimeStamp = ts;
		break;
	case 0:
		icmp_pair_map[sequence_received].reply = true;
		icmp_pair_map[sequence_received].repTimeStamp = ts;
		break;
	case 11:
		icmp_pair_map[sequence_received].ttlExceeded = true;
		icmp_pair_map[sequence_received].ttlExcessTimeStamp = ts;
		break;
	case 3:
		icmp_pair_map[sequence_received].destUnreachable = true;
		icmp_pair_map[sequence_received].unreachableTimeStamp = ts;
		break;
	default:
		icmp_pair_map[sequence_received].unsupported_type = true;
		break;
		
	}
}


jsonnlohmann Icmp_stream::get_statistics()
{
	std::string str;
	jsonnlohmann root;

	root["SrcIp"] = icmp_srcIP;
	root["DstIp"] = icmp_dstIP;
	root["src_dst"] = get_count_src_dst();
	root["dst_src"] = get_count_dst_src();
  
	for (auto it = icmp_pair_map.begin();it != icmp_pair_map.end(); ++it)
	{
		jsonnlohmann j_seq;
		j_seq["sequence_no"] = it->second.sequence_number;
		j_seq["reqts"] = it->second.reqTimeStamp;
		j_seq["repts"] = it->second.repTimeStamp;
		j_seq["ttlexcesstime"] = it->second.ttlExcessTimeStamp;
		j_seq["unreachabletime"] = it->second.unreachableTimeStamp;
		j_seq["ttlExceeded"] = it->second.ttlExceeded;
		j_seq["dstUnreachable"] = it->second.destUnreachable;
		j_seq["request"] = it->second.request;
		j_seq["reply"] = it->second.reply;
		j_seq["unsupported"] = it->second.unsupported_type;

		root["sequence_array"].push_back(j_seq);
		j_seq.clear();
	}

	for(auto it = folders_FL.begin(); it != folders_FL.end(); ++it)
	{
		root["folders_FL"].push_back(*it);
	}

    for (auto it = pcap_files_FL.begin(); it != pcap_files_FL.end(); ++it)
    {
		str = it->filename().string();
		root["files_FL"].push_back(str);
		str.clear();
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
