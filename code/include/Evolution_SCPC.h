#pragma once
#include "Evolution_SCPC_stream.h"
#include "Protocol_count_stream.h"
#include "stdafx.h"
#include <iostream>
#include <conio.h>
#include <string.h>
#include <pcap.h>
#include <conio.h>
#include <map>
#include <vector>
#include <set>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using namespace std;

class Evolution_SCPC
{
private:
	struct ether_header {
		u_int8_t			 ether_Dest[6]; //Total 48 bits
		u_int8_t			 ether_Source[6]; //Total 48 bits
		u_int16_t			 type; //16 bits
	};

	/*ip header*/
	struct ip_header {
		unsigned char		ip_header_len : 4;  // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
		unsigned char		ip_version : 4;  // 4-bit IPv4 version
		unsigned char		ip_tos;           // IP type of service
		unsigned short	    ip_total_length;  // Total length
		unsigned short		ip_id;            // Unique identifier 
		unsigned char		ip_frag_offset : 5;        // Fragment offset field
		unsigned char		ip_more_fragment : 1;
		unsigned char		ip_dont_fragment : 1;
		unsigned char		ip_reserved_zero : 1;
		unsigned char		ip_frag_offset1;    //fragment offset
		unsigned char		ip_ttl;           // Time to live
		unsigned char		ip_protocol;      // Protocol(TCP,UDP etc)
		unsigned short		ip_checksum;      // IP checksum
		struct in_addr		ip_srcaddr;       // Source address
		struct in_addr		ip_destaddr;      // Source address
	};

	struct pcap_pkthdr*							header;
	const u_char*								data;
	struct in_addr								Saddr;
	struct in_addr								Daddr;
	vector<Evolution_SCPC_stream>				streams;
	int											protNum;      //protocol number of the packet
	std::map <int, int>							protocols;
	std::map<int, int>::iterator				it;  //iterator for the map
	float										totalSecondsElapsed = 0;
	std::map<std::string, std::string>		    sizePcapFiles; //to add the timestamp and size to each pcap file
	int											NumberOfFilesRead; //Total number of files read
	bool										isChecked;
	jsonnlohmann								j_root = jsonnlohmann::object();
	void										store_database();
	jsonnlohmann								j_protocol_root = jsonnlohmann::object();

	int											process(std::pair<std::string, std::string> item, bool is_fl); // main processing function


public:
	Evolution_SCPC();
	~Evolution_SCPC();
	void initialize(bool);
	int start_evolutionSCPC_analysis();
	void			printPairs(); // this funcktion is used to print the pairs obtained from the analysis into the json file
	std::string		printToJSON();

};

