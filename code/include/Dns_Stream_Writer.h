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

class Dns_Stream_Writer
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

	typedef struct udp_header {
		u_short				sport;          // Source port
		u_short				dport;          // Destination port
		u_short				len;            // Datagram length
		u_short				crc;            // Checksum
	}udp_header;

	struct DNS_HEADER
	{
		unsigned short id; // identification number
		unsigned char rd : 1; // recursion desired
		unsigned char tc : 1; // truncated message
		unsigned char aa : 1; // authoritive answer
		unsigned char opcode : 4; // purpose of message
		unsigned char qr : 1; // query/response flag

		unsigned char rcode : 4; // response code
		unsigned char cd : 1; // checking disabled
		unsigned char ad : 1; // authenticated data
		unsigned char z : 1; // its z! reserved
		unsigned char ra : 1; // recursion available

		unsigned short q_count; // number of question entries
		unsigned short ans_count; // number of answer entries
		unsigned short auth_count; // number of authority entries
		unsigned short add_count; // number of resource entries
	}_dns_header;

	static const int							PCAP_FILE_HEADER_LENGTH = 24;
	char										errbuff[PCAP_BUF_SIZE];
	std::vector<Dns_Stream_Writer>				dns_streams_writer_vector;
	std::string									dns_srcIP, dns_dstIP;
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
	Dns_Stream_Writer();
	~Dns_Stream_Writer();
	Dns_Stream_Writer(std::string s_IP, std::string d_IP);
	void initialize();
	int start_write_analysis();
	int process(std::pair<std::string, std::string> item, bool is_fl);
	int dns_equals(const Dns_Stream_Writer& that) const;
	void writeToBin(std::string srcIP, std::string dstIP, const u_char* data, struct pcap_pkthdr* header);
	void closeBinMap();
};

