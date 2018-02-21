#pragma once
#include "Tcp_stream.h"
#include "ip_stream.h"
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

using jsonnlohmann = nlohmann::json;

class Tcp_Analyzer
{
private:
	typedef struct ether_header {
		u_int8_t ether_Dest[6]; //Total 48 bits
		u_int8_t ether_Source[6]; //Total 48 bits
		u_int16_t type; //16 bits
	}ether_header;

	/*ip header*/
	typedef struct ip_header {
		unsigned char  ip_header_len : 4;  // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
		unsigned char  ip_version : 4;  // 4-bit IPv4 version
		unsigned char  ip_tos;           // IP type of service
		unsigned short ip_total_length;  // Total length
		unsigned short ip_id;            // Unique identifier 
		unsigned char  ip_frag_offset : 5;        // Fragment offset field
		unsigned char  ip_more_fragment : 1;
		unsigned char  ip_dont_fragment : 1;
		unsigned char  ip_reserved_zero : 1;
		unsigned char  ip_frag_offset1;    //fragment offset
		unsigned char  ip_ttl;           // Time to live
		unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
		unsigned short ip_checksum;      // IP checksum
		struct in_addr  ip_srcaddr;       // Source address
		struct in_addr  ip_destaddr;      // Source address
	}ip_header;


	/*TCP header*/
	typedef struct tcp_header {
		u_short th_sport;               /* source port */
		u_short th_dport;               /* destination port */
		u_int s_number;				//sequence number
		u_int ack_number;			//acknowledgement number
		u_short data_offset;		//data offset+reserved+ecn+controlbits
		u_short window;
		u_short checksum;
		u_short uPointer;
	}tcp_header;

	/*UDP Header*/
	typedef struct udp_header {
		u_short sport;          // Source port
		u_short dport;          // Destination port
		u_short len;            // Datagram length
		u_short crc;            // Checksum
	}udp_header;

	/*ICMP header*/
	typedef struct icmp_header
	{
		u_int8_t type;		/* message type */
		u_int8_t code;		/* type sub-code */
		u_int16_t checksum;
		union
		{
			struct
			{
				u_int16_t	id;
				u_int16_t	sequence;
			} echo;			/* echo datagram */
			u_int32_t	gateway;	/* gateway address */
			struct
			{
				u_int16_t	__unused;
				u_int16_t	mtu;
			} frag;			/* path mtu discovery */
		} un;
	};
	
	std::map<std::string, Ip_stream*> ip_streams_map;
	std::vector<boost::filesystem::path> fl_files_; /*fl files read*/
	std::vector<boost::filesystem::path> rl_files_;/*rl files read*/
	int num_files_read; /*total number of files read*/
	pcap_t* tcpDescriptor; //pcap descriptor
	char errbuff[PCAP_BUF_SIZE];
	float										totalSecondsElapsed = 0;
	struct pcap_pkthdr* header;
	const u_char* data;
	jsonnlohmann root = jsonnlohmann::object(); //to make root a json array
	int process(std::pair<std::string, std::string> item, bool is_fl); // main process function to process the files with each packet


public:
	Tcp_Analyzer();
	~Tcp_Analyzer();
	void initialize(); //initializing variables function
	int32_t start_analysis();
	void store_database();
	std::string printToJson();
};

