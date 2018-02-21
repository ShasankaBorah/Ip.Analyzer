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
#include <set>
#include "Icmp_stream.h"
#include "Dns_ip_stream.h"

using namespace std;
using jsonnlohmann = nlohmann::json;


class Icmp_Analyzer
{
private:
	typedef struct ether_header{
		u_int8_t ether_Dest[6]; //Total 48 bits
		u_int8_t ether_Source[6]; //Total 48 bits
		u_int16_t type; //16 bits
	}ether_header;

	/*ip header*/
	typedef struct ip_header{
		unsigned char  ip_header_len:4;  // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
		unsigned char  ip_version   :4;  // 4-bit IPv4 version
		unsigned char  ip_tos;           // IP type of service
		unsigned short ip_total_length;  // Total length
		unsigned short ip_id;            // Unique identifier 
		unsigned char  ip_frag_offset   :5;        // Fragment offset field
		unsigned char  ip_more_fragment :1;
		unsigned char  ip_dont_fragment :1;
		unsigned char  ip_reserved_zero :1;
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
	typedef struct udp_header{
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


	pcap_t*									icmpDescriptor; //pcap descriptor
	char									errbuff[PCAP_BUF_SIZE];
	struct pcap_pkthdr*						header;
	const u_char*							data;
	int										returnValue_for_icmp;
	float									totalSecondsElapsed = 0;
	int										NumberOfFilesRead; //Total number of files read
	std::map<std::string, std::string>		sizePcapFl; //to add the timestamp and size to each pcap file
	std::map<std::string, std::string>		sizePcapRl;
	std::set<int>							icmp_Sequence;
	std::vector<Icmp_stream>				icmp_streams_vector;
	std::ofstream*							to_icmp_json;
	vector<boost::filesystem::path>			fl_files_;
	vector<boost::filesystem::path>			rl_files_;
	jsonnlohmann j_icmp_streams = jsonnlohmann::object(); //json object
    void									store_database();
	int process(std::pair<std::string, std::string> item, bool is_fl);


public:
	Icmp_Analyzer();
	~Icmp_Analyzer();
	
	std::string			printToJSON();
	void				initialize();
	int					start_analysis();
};

