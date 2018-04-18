#pragma once
#include "stdafx.h"
#include "boost/filesystem.hpp"

#include <boost/date_time/posix_time/posix_time.hpp>
#include "boost/filesystem.hpp"
#include <boost/property_tree/ptree.hpp>
#include <iostream>
#include <conio.h>
#include <string.h>
#include <pcap.h>
#include <conio.h>
#include <time.h>
#include <map>
#include <set>
#include <Configuration.h>
#include <algorithm>
#include <fstream>	
#include <iosfwd>
#include <string>
#include <direct.h>

using namespace std;

class pair_info
{
public:
	std::string src_ip;
	uint32_t src_port;
	std::string dst_ip;
	uint32_t dst_port;
	bool direction;

	pair_info(std::string a, uint32_t b, std::string c, uint32_t d)
	{
		src_ip = a;
		src_port = b;
		dst_ip = c;
		dst_port = d;
	}

	bool operator == (const pair_info& x) const
	{
		if ((strcmp(this->src_ip.c_str(), x.src_ip.c_str()) != 0) || this->src_port != x.src_port || (strcmp(this->dst_ip.c_str(), x.dst_ip.c_str()) != 0) || this->dst_port != x.dst_port)
		{
			cout << "1 true";
			return true;
		}//means from A to B
		else if ((strcmp(this->src_ip.c_str(), x.dst_ip.c_str()) != 0) || this->src_port != x.dst_port || (strcmp(this->dst_ip.c_str(), x.src_ip.c_str()) != 0) || this->dst_port != x.src_port)
		{
			cout << "2 true";
			return true; //B to A
		}

		return false;
	}
};


class Tcp_Stream_Writer
{
public:
	Tcp_Stream_Writer();
	~Tcp_Stream_Writer();
	Tcp_Stream_Writer(std::string s_IP, std::string d_IP);
	void initialize();
	int process(std::pair<std::string, std::string> item, bool is_fl);
	int32_t start_write_analysis();
	void closeBinMap();
	int tcp_equals(const Tcp_Stream_Writer& that) const;
	void writeToBin(std::string srcIP, std::string dstIP, uint32_t srcPort, uint32_t dstPort, const u_char* data, struct pcap_pkthdr* header);
	void writePcapDataToJson();
	



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

	std::string									tcp_srcIP, tcp_dstIP;
	char										errbuff[PCAP_BUF_SIZE];
	static const int							PCAP_FILE_HEADER_LENGTH = 24;
	std::vector<Tcp_Stream_Writer>				tcp_streams_writer_vector;
	std::map<std::string, std::ofstream*>		binMap;

	unsigned char								globalHeader[PCAP_FILE_HEADER_LENGTH] =
	{ 212, 195, 178, 161, // Magic number
		02, 00,    // Major version
		04, 00,    // Minor version
		0,0,0,0,0,0,0,0,  // Time zone, Timestamp accuracy
		0, 0, 4, 0,  // Shapshot length
		1,0,0,0                // Link layer type
	};
};



