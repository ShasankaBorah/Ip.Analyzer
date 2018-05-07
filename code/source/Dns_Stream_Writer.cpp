#include "Dns_Stream_Writer.h"
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
#include "json.hpp"

using namespace std;
using namespace boost::filesystem;
namespace pt = boost::posix_time;
namespace ptree = boost::property_tree;
using jsonnlohmann = nlohmann::json;


extern Configuration config;

extern void send_analysis_message_GUI(std::string progress_msg);
extern void send_message_GUI(std::string msg);
extern std::string getJSON_string_from_jsonC(jsonnlohmann json);
extern std::string getJSONString(ptree::ptree pt);



Dns_Stream_Writer::Dns_Stream_Writer()
{
}


Dns_Stream_Writer::~Dns_Stream_Writer()
{
}

Dns_Stream_Writer::Dns_Stream_Writer(std::string s_IP, std::string d_IP)
{
	dns_srcIP = s_IP;
	dns_dstIP = d_IP;
}



void Dns_Stream_Writer::initialize()
{
	std::vector<std::string> directoryVec;

	directoryVec.push_back("dnsBin");
	directoryVec.push_back("dnsJson");

	for (auto itr = directoryVec.begin(); itr != directoryVec.end(); ++itr)
	{
		std::string path_ = "dnsAnalysisData\\" + *itr;
		const char* dir_path_ = path_.c_str();

		if (!boost::filesystem::is_directory(dir_path_))
		{
			boost::filesystem::path dir(dir_path_);
			boost::filesystem::create_directories(dir);

			if (is_directory(dir))
			{
				std::cout << "created:" << std::endl;

			}
			else
			{
				std::cout << "not created: " << std::endl;
			}
		}
	}
}

int Dns_Stream_Writer::dns_equals(const Dns_Stream_Writer& that) const
{
	if ((strcmp(dns_srcIP.c_str(), that.dns_srcIP.c_str()) == 0) && (strcmp(dns_dstIP.c_str(), that.dns_dstIP.c_str()) == 0))/* A to B */
		return 0;
	if ((strcmp(dns_srcIP.c_str(), that.dns_dstIP.c_str()) == 0) && (strcmp(dns_dstIP.c_str(), that.dns_srcIP.c_str()) == 0))/*B to A*/
		return 1;
	else
		return 2;
}


int Dns_Stream_Writer::start_write_analysis()
{
	std::vector<std::pair<string, string>> FilesVector;

	/* Analyse FL Path*/
	if (!config.get_fl_path().empty())
	{
		for (directory_iterator itr(config.get_fl_path()); itr != directory_iterator(); ++itr) /*top folder*/
		{
			if (boost::filesystem::is_directory(itr->path()))
			{
				if (std::find(config.fl_folders.begin(), config.fl_folders.end(), itr->path().filename().string()) != config.fl_folders.end())
				{
					for (directory_iterator itr2(itr->path()); itr2 != directory_iterator(); ++itr2) /*inner folder*/
					{
						if (itr2->path().filename().extension() == ".pcap")
						{
							FilesVector.push_back(std::make_pair(itr->path().filename().string(), itr2->path().string())); /*folder name and file name as argument*/
						}
					}
				}
			}
		}


		for (int i = 0; i < FilesVector.size(); ++i)
		{
			cout << "Reading File (" << i << "/" << FilesVector.size() << ") : " << FilesVector.at(i).second << std::endl;
			process(FilesVector.at(i), true);
		}
		FilesVector.clear();

	}


	/* Analyse RL Path*/
	if (!config.get_rl_path().empty())
	{
		for (directory_iterator itr(config.get_rl_path()); itr != directory_iterator(); ++itr) /* top folder*/
		{
			if (boost::filesystem::is_directory(itr->path()))
			{
				if (std::find(config.rl_folders.begin(), config.rl_folders.end(), itr->path().filename().string()) != config.rl_folders.end())
				{
					for (directory_iterator itr2(itr->path()); itr2 != directory_iterator(); ++itr2) /* inner folder*/
					{
						if (itr2->path().filename().extension() == ".pcap")
						{
							FilesVector.push_back(std::make_pair(itr->path().filename().string(), itr2->path().string()));
						}
					}
				}
			}
		}

		for (int i = 0; i < FilesVector.size(); ++i)
		{
			cout << "Reading File (" << i << "/" << FilesVector.size() << ") : " << FilesVector.at(i).second << std::endl;
			process(FilesVector.at(i), false);
		}

		FilesVector.clear();
	}

	return 0;
}

int Dns_Stream_Writer::process(std::pair<std::string, std::string> item, bool is_fl)
{
	pcap_t*							descriptor; //pcap descriptor
	float							seconds;
	clock_t							t1, t2;
	ether_header*					eth_hdr;
	ip_header*						ip_hdr;
	udp_header*						udp_hdr;
	DNS_HEADER*						dns_hdr;
	struct in_addr					udp_Saddr;
	struct in_addr					udp_Daddr;
	jsonnlohmann					j_json_progress;
	struct pcap_pkthdr*				header;
	const u_char*					data;
	double							bytesRead = 0;
	double							perc;/*shows the percentage*/
	int								next_perc = 0;
	double							remain;

	std::string						folder = item.first;
	std::string						filename = item.second;

	std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	int fileSize = in.tellg();
	in.close();

	descriptor = pcap_open_offline(filename.c_str(), errbuff);

	std::cout << std::endl;
	t1 = clock();

	while (true)
	{
		int returnValue = pcap_next_ex(descriptor, &header, &data);

		if (1 != returnValue)
		{
			break;
		}

		bytesRead += header->len;
		perc = (bytesRead / fileSize) * 100;

		if (perc > double(next_perc))
		{
			t2 = clock();
			float diff((float)t2 - (float)t1);
			seconds = diff / CLOCKS_PER_SEC;

			std::cout << (uint64_t)bytesRead << "/" << fileSize << " ( " << perc << " %) " << std::endl;
			j_json_progress["type"] = "progress";
			j_json_progress["filename"] = filename;
			j_json_progress["bytesRead"] = bytesRead;
			j_json_progress["fileSize"] = fileSize;
			j_json_progress["seconds"] = seconds;

			send_analysis_message_GUI(getJSON_string_from_jsonC(j_json_progress));
			j_json_progress.clear();

			next_perc += 5;
		}

		eth_hdr = (ether_header*)data;
		if (0x0008 == eth_hdr->type)
		{
			ip_hdr = (ip_header*)(data + 14);
			if (17 == ip_hdr->ip_protocol) /*if udp*/
			{
				udp_hdr = (udp_header*)(data + 14 + (ip_hdr->ip_header_len * 4));
				memcpy((u_char*)&udp_Saddr.s_addr, (u_char*)&ip_hdr->ip_srcaddr, 4);
				string src(inet_ntoa(udp_Saddr));

				memcpy((u_char*)&udp_Daddr.s_addr, (u_char*)&ip_hdr->ip_destaddr, 4);
				string dst(inet_ntoa(udp_Daddr));

				if ((53 == ntohs(udp_hdr->sport)) || (53 == ntohs(udp_hdr->dport)))
				{
					dns_hdr = (DNS_HEADER*)(data + 14 + (ip_hdr->ip_header_len * 4) + sizeof(udp_hdr));

					Dns_Stream_Writer new_dns_stream_writer(src, dst);

					int retVal = NULL;
					bool found = false;

					for (int i = 0; i < dns_streams_writer_vector.size(); i++)
					{
						retVal = dns_streams_writer_vector.at(i).dns_equals(new_dns_stream_writer);

						switch (retVal)
						{
						case 0:
							found = true;
							writeToBin(src, dst, data, header);
							break;
						case 1:
							found = true;
							writeToBin(dst, src, data, header);
							break;
						}//ssrich

						if (found)
						{
							break;
						}
					}//for loop
					if (!found)
					{
						dns_streams_writer_vector.push_back(new_dns_stream_writer);
						writeToBin(src, dst, data, header);

					}
				}
			}
		}
	}
	remain = fileSize - bytesRead;
	bytesRead += remain;
	perc = (bytesRead / fileSize) * 100;
	std::cout << (uint64_t)bytesRead << "/" << fileSize << " (" << perc << "%)" << std::endl;

	t2 = clock();

	float diff((float)t2 - (float)t1);

	seconds = diff / CLOCKS_PER_SEC;
	//totalSecondsElapsed = totalSecondsElapsed + seconds;

	j_json_progress["type"] = "progress";
	j_json_progress["filename"] = filename;
	j_json_progress["bytesRead"] = bytesRead;
	j_json_progress["fileSize"] = fileSize;
	j_json_progress["seconds"] = seconds;
	//j_json_progress["total_time"] = totalSecondsElapsed;

	send_analysis_message_GUI(getJSON_string_from_jsonC(j_json_progress));
	closeBinMap();
	return 0;



}


void Dns_Stream_Writer::writeToBin(std::string srcIP, std::string dstIP, const u_char* data, pcap_pkthdr* header)
{
	if(srcIP == "192.168.1.10" && dstIP == "192.168.1.1")
	{
		cout << "error" << std::endl;
	}
	std::string s_ip = srcIP;
	std::string d_ip = dstIP;
	std::string binfileName = s_ip + "_" + d_ip + ".pcap";
	const std::string pathfull = "dnsAnalysisData\\dnsBin\\" + binfileName;
	std::ofstream* outFile;

	if (binMap.find(binfileName) == binMap.end()) /*if the file name is not found in the map*/
	{

		outFile = new std::ofstream(pathfull, std::ios::binary);
		outFile->write((char*)globalHeader, sizeof(globalHeader));
		binMap[binfileName] = outFile;

	}
	else /*if found*/
	{
		outFile = binMap[binfileName];
	}

	outFile->write((char*)header, sizeof(*header));
	outFile->write((char*)data, header->len);

}

void Dns_Stream_Writer::closeBinMap()
{
	int k = binMap.size();

	for (auto it = binMap.begin(); it != binMap.end(); ++it)
	{
		/*if (it->first.compare("10.10.0.14_10.10.32.100_2000_15908.pcap") == 0)
		{
		cout << "stop" << std::endl;
		}*/
		it->second->close();
	}

}

