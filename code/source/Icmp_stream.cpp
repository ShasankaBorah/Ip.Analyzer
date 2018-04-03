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

#include <json.hpp>

namespace ptree = boost::property_tree;
using namespace std;


using jsonnlohmann = nlohmann::json;

Icmp_stream::Icmp_stream(void)
{
}


Icmp_stream::~Icmp_stream(void)
{
}

Icmp_stream::Icmp_stream(std::string srcIP, std::string dstIP) {//overloaded constrcutor
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

string Icmp_stream::get_icmp_srcIP() {
	return icmp_srcIP;
}

string Icmp_stream::get_icmp_dstIP() {
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
	if ((strcmp(icmp_srcIP.c_str(), that.icmp_srcIP.c_str()) == 0) && (strcmp(icmp_dstIP.c_str(), that.icmp_dstIP.c_str()) == 0))/* A to B */
		return 0;
	if ((strcmp(icmp_srcIP.c_str(), that.icmp_dstIP.c_str()) == 0) && (strcmp(icmp_dstIP.c_str(), that.icmp_srcIP.c_str()) == 0))/*B to A*/
		return 1;
	else
		return 2;
}

void Icmp_stream::update_icmp_pair_info(int sequence_received, int request_type_received, uint64_t ts)
{
	// check if seq no exists in the map
	// if exists then update the req/reply to true
	// if not then create a new icmp_pair and set its req/rep and add to the map
	// add one more var to icmp_pair for unsupported type and set if that value comes. normally it shoudln't
	/*icmp_pair newPair;*/

	if(sequence_received == 33608)
	{
		std::cout << "hello"<<std::endl;
	}
	icmp_pair item;
	item.sequence_number = sequence_received;
	item.reqTimeStamp = 0;							//request timestamp
	item.repTimeStamp = 0;							//reply timestamp
	item.unreachableTimeStamp = 0;					//unreachable timestamp
	item.ttlExcessTimeStamp = 0;					//ttlexcess timestamp
	item.request = false;							//request
	item.reply = false;								//reply
	item.unsupported_type = false;					//unsupported type
	item.ttlExceeded = false;						//ttlexceeded
	item.destUnreachable = false;					//dstUnreachable

	switch (request_type_received)
	{
	case 8: //request
		item.request = true;
		item.reqTimeStamp = ts;
		break;
	case 0:
		item.reply = true;
		item.repTimeStamp = ts;
		break;
	case 3: //dst unreachable
		item.destUnreachable = true;
		item.unreachableTimeStamp = ts;
		break;
	case 11: //ttl exceeded
		item.ttlExceeded = true;
		item.ttlExcessTimeStamp = ts;
		break;
	default:
		item.unsupported_type = true;
		break;
	}


	bool flag = false;

	if (item.destUnreachable == true || item.ttlExceeded == true || item.unsupported_type == true)
	{
		ttl_unreachable.push_back(item);
	}

	else
	{
		for (auto& it : icmp_pair_vector)
		{
			if (it.request == true && it.reply == true)//if the pointed values has both request and reply true then continue and add the item to the vector
			{
				continue;
			}
			else if (it.sequence_number == item.sequence_number) // if sequence number of item and it are same 
			{		
				if ((it.request == true && item.request == true)|| (it.reply == true && item.reply == true)) //if type is same
				{			
					continue;
				}
				else
				{
					if (it.request == true && item.reply == true) //check it type and item type 
					{
						int requestSec = ((it.reqTimeStamp + 500) / 1000);
						int replySec = ((item.repTimeStamp + 500) / 1000);
						int diff = replySec - requestSec;
						if (diff <= 60)
						{
							flag = true;
							it.reply = true;
							it.repTimeStamp = ts;
						}
						else
						{
							continue;
						}

					}
					else if (it.reply == true && item.request == true)
					{
						int requestSec = ((item.reqTimeStamp + 500) / 1000);
						int replySec = ((it.repTimeStamp + 500) / 1000);
						int diff = replySec - requestSec;
						if(diff <= 60)
						{
							flag = true;
							it.request = true;
							it.reqTimeStamp = ts;
						}
						else
						{
							continue;
						}
					}
				}
			}
		}

		if (!flag)
		{
			icmp_pair_vector.push_back(item);
		}
	}

}


//if(icmp_pair_map.find(sequence_received) == icmp_pair_map.end())//if sequence number not found
//{
//	icmp_pair new_pair;
//	new_pair.sequence_number = sequence_received;
//	new_pair.reqTimeStamp = 0;
//	new_pair.repTimeStamp = 0;
//	new_pair.unreachableTimeStamp = 0;
//	new_pair.ttlExcessTimeStamp = 0;
//	new_pair.request = false;
//	new_pair.reply = false;
//	new_pair.unsupported_type = false;
//	new_pair.ttlExceeded = false;
//	new_pair.destUnreachable = false;
//	icmp_pair_map.insert(std::pair<int,icmp_pair>(sequence_received, new_pair));
//}

//switch(request_type_received){
//case 8:
//	icmp_pair_map[sequence_received].request = true;
//	icmp_pair_map[sequence_received].reqTimeStamp = ts;
//	break;
//case 0:
//	icmp_pair_map[sequence_received].reply = true;
//	icmp_pair_map[sequence_received].repTimeStamp = ts;
//	break;
//case 11:
//	icmp_pair_map[sequence_received].ttlExceeded = true;
//	icmp_pair_map[sequence_received].ttlExcessTimeStamp = ts;
//	break;
//case 3:
//	icmp_pair_map[sequence_received].destUnreachable = true;
//	icmp_pair_map[sequence_received].unreachableTimeStamp = ts;
//	break;
//default:
//	icmp_pair_map[sequence_received].unsupported_type = true;
//	break;
//	
//}
//}


jsonnlohmann Icmp_stream::get_statistics()
{
	std::string str;
	jsonnlohmann root;

	root["SrcIp"] = icmp_srcIP;
	root["DstIp"] = icmp_dstIP;
	root["src_dst"] = get_count_src_dst();
	root["dst_src"] = get_count_dst_src();

	for (auto it = icmp_pair_vector.begin(); it != icmp_pair_vector.end(); ++it)
	{
		jsonnlohmann j_seq;
		
		j_seq["sequence_no"] = it->sequence_number;
		j_seq["reqts"] = it->reqTimeStamp;
		j_seq["repts"] = it->repTimeStamp;
		j_seq["ttlexcesstime"] = it->ttlExcessTimeStamp;
		j_seq["unreachabletime"] = it->unreachableTimeStamp;
		j_seq["ttlExceeded"] = it->ttlExceeded;
		j_seq["dstUnreachable"] = it->destUnreachable;
		j_seq["request"] = it->request;
		j_seq["reply"] = it->reply;
		j_seq["unsupported"] = it->unsupported_type;

		root["sequence_array"].push_back(j_seq);
		j_seq.clear();
	}

	for(auto itr = ttl_unreachable.begin() ; itr != ttl_unreachable.end() ; ++itr)
	{
		jsonnlohmann j_tll_unreach;
		j_tll_unreach["sequence_no"] = itr->sequence_number;
		j_tll_unreach["reqts"] = itr->reqTimeStamp;
		j_tll_unreach["repts"] = itr->repTimeStamp;
		j_tll_unreach["ttlexcesstime"] = itr->ttlExcessTimeStamp;
		j_tll_unreach["unreachabletime"] = itr->unreachableTimeStamp;
		j_tll_unreach["ttlExceeded"] = itr->ttlExceeded;
		j_tll_unreach["dstUnreachable"] = itr->destUnreachable;
		j_tll_unreach["request"] = itr->request;
		j_tll_unreach["reply"] = itr->reply;
		j_tll_unreach["unsupported"] = itr->unsupported_type;

		root["unsuported_or_default"].push_back(j_tll_unreach);
		j_tll_unreach.clear();
	}
	
	for (auto it = folders_FL.begin(); it != folders_FL.end(); ++it)
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
