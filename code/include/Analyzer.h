#pragma once

#include "Streamer.h"
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

using jsonnlohmann = nlohmann::json;

using namespace std;

class pcapPackAnalyzer
{
private:
	struct ether_header{
		u_int8_t			 ether_Dest[6]; //Total 48 bits
		u_int8_t			 ether_Source[6]; //Total 48 bits
		u_int16_t			 type; //16 bits
	};

	/*ip header*/
	struct ip_header{
		unsigned char		ip_header_len:4;  // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
		unsigned char		ip_version   :4;  // 4-bit IPv4 version
		unsigned char		ip_tos;           // IP type of service
		unsigned short	    ip_total_length;  // Total length
		unsigned short		ip_id;            // Unique identifier 
		unsigned char		ip_frag_offset   :5;        // Fragment offset field
		unsigned char		ip_more_fragment :1;
		unsigned char		ip_dont_fragment :1;
		unsigned char		ip_reserved_zero :1;
		unsigned char		ip_frag_offset1;    //fragment offset
		unsigned char		ip_ttl;           // Time to live
		unsigned char		ip_protocol;      // Protocol(TCP,UDP etc)
		unsigned short		ip_checksum;      // IP checksum
		struct in_addr		ip_srcaddr;       // Source address
		struct in_addr		ip_destaddr;      // Source address
	};


	/*TCP header*/
	struct tcp_header {
		u_short				th_sport;               /* source port */
		u_short				th_dport;               /* destination port */
		u_int				s_number;				//sequence number
		u_int				ack_number;			//acknowledgement number
		u_short				data_offset;		//data offset+reserved+ecn+controlbits
		u_short				window;
		u_short				checksum;
		u_short				uPointer;
	};

	/*UDP Header*/
	typedef struct udp_header{
		u_short				sport;          // Source port
		u_short				dport;          // Destination port
		u_short				len;            // Datagram length
		u_short				crc;            // Checksum
	}udp_header;

	/*ICMP header*/
	struct icmp_header
	{
		u_int8_t			type;		/* message type */
		u_int8_t			code;		/* type sub-code */
		u_int16_t		    checksum;
		union
		{
			struct
			{
				u_int16_t	id;
				u_int16_t	sequence;
			} echo;			/* echo datagram */
			u_int32_t		gateway;	/* gateway address */
			struct
			{
				u_int16_t	__unused;
				u_int16_t	mtu;
			} frag;			/* path mtu discovery */
		} un;
	};


	/*struct str_cmp {
		bool operator() (const std::string& a, const std::string& b) const
		{
			return (a.compare(b) < 0);
		}
	};*/

	/*member variables*/
	
	/*vector<boost::filesystem::path>				fl_files_;
	vector<boost::filesystem::path>				rl_files_;*/
	std::map<std::string, std::string>				sizePcapFl; //to add the timestamp and size to each pcap file
	std::map<std::string, std::string>				sizePcapRl;
	//std::set<uint32_t>							pcapSize;
	jsonnlohmann								j_protocol_root = jsonnlohmann::object();
	int											protNum;      //protocol number of the packet
    std::map <int,int>							protocols;
	std::map<int,int>::iterator				    it;  //iterator for the map
	struct pcap_pkthdr*							header;
	const u_char*								data;
	struct in_addr								Saddr;
	struct in_addr								Daddr;
	int											returnValue;
	vector<stream>							    streams;
	int											NumberOfFilesRead; //Total number of files read
	jsonnlohmann								j_root = jsonnlohmann::object();  
    void										store_database();
	float										totalSecondsElapsed = 0;
	bool										isChecked;
	int process(std::pair<std::string, std::string> item, bool is_fl); // main processing function
	
public:	
	pcapPackAnalyzer(std::string);  //constructor
	pcapPackAnalyzer(); //deafut constructor
	~pcapPackAnalyzer();
	void			initialize(bool);//resets all the values
	int				start_analysis();
	void			setNumberOfFiles(int);
	std::string		printToJSON();	
	int				TotalFilesReadFn();
	void			sendTosetDecFn(bool);
	void			fillFLmap(boost::filesystem::path);
	void			add_fl_protocol_file(std::string);
	void			add_rl_protocol_file(std::string);
	//std::string		sizeCalculate(uint32_t size);
	void			printPairs();
};

