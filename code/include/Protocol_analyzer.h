#pragma once
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
#include <json.hpp>
#include "boost/filesystem.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace std;
using namespace boost::filesystem;
namespace pt = boost::posix_time;
using jsonnlohmann = nlohmann::json;

class Protocol_analyzer
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


	std::map<std::string, std::string>				sizePcapFl; //to add the timestamp and size to each pcap file
	std::map<std::string, std::string>				sizePcapRl;
	std::vector<boost::filesystem::path>		fl_files_;
	std::vector<boost::filesystem::path>		rl_files_;
	pcap_t*										Descriptor;
	char										errbuff[PCAP_BUF_SIZE];
	struct pcap_pkthdr*							header;
	const u_char*								data;
	float										totalSecondsElapsed = 0;
	jsonnlohmann								j_protocol_stream;
	int											num_files_read; /*total number of files read*/	
	jsonnlohmann								port_no_tcp = jsonnlohmann::object();
	jsonnlohmann								port_no_udp = jsonnlohmann::object();

public:
	Protocol_analyzer();
	~Protocol_analyzer();
	void initialize();
	int32_t start_analysis();
	jsonnlohmann process(/*std::string filename*/std::vector<std::string> pcaps, bool is_fl);
	void store_database(jsonnlohmann data);
	std::string printToJson();
	void update_port_info(uint16_t src_port , bool cp_dp); /*tcp or udp*/
	//void update_port_infos(std::string file_name);/*tc ud indicates tcp or udp*/
	void read_file_for_port(std::vector<std::string> files);/*read the file and the sends the port info to update port info for updation*/
	//void update_port_information(uint16_t src_port, bool cp_dp);
};