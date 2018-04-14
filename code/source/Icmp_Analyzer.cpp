#include "Icmp_Analyzer.h"
#include "Icmp_stream.h"
#include "Ip_Address_to_country_mapper.h"
#include "Streamer.h"
#include "stdafx.h"
#include "sizeCalculate.h"
#include "json.hpp"
#include "boost/filesystem.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include "boost/property_tree/ptree.hpp"
#include <iostream>
#include <conio.h>
#include <string.h>
#include <pcap.h>
#include <conio.h>
#include <map>
#include <time.h>
#include <set>
#include <Configuration.h>
#include <algorithm>
#include <fstream>
#include <iosfwd>


using namespace std;
using namespace boost::filesystem;
namespace pt = boost::posix_time;
namespace ptree = boost::property_tree;
using jsonnlohmann = nlohmann::json;

extern				Ip_Address_to_country_mapper ip_address_resolve;
extern void			send_analysis_message_GUI(std::string progress_msg);
extern void			send_message_GUI(std::string msg);
extern std::string	getJSONString(ptree::ptree pt);
extern std::string	getJSON_string_from_jsonC(jsonnlohmann json);
extern				Configuration config;


Icmp_Analyzer::Icmp_Analyzer()
{
}

Icmp_Analyzer::~Icmp_Analyzer()
{
}

void Icmp_Analyzer::initialize(bool isExPrivateChecked)
{
	isChecked = isExPrivateChecked; // is exclude private ip checked
	icmp_streams_vector.clear();
	NumberOfFilesRead = 0;
	sizePcapFl.clear();
	sizePcapRl.clear();
}

int32_t Icmp_Analyzer::start_analysis()
{
	vector<std::pair<string, string>> FilesVector;

	if (!config.get_fl_path().empty())
	{
		for (directory_iterator itr(config.get_fl_path()); itr != directory_iterator(); ++itr) // top folder
		{
			if (boost::filesystem::is_directory(itr->path()))
			{
				if (std::find(config.fl_folders.begin(), config.fl_folders.end(), itr->path().filename().string()) != config.fl_folders.end())
				{
					for (directory_iterator itr2(itr->path()); itr2 != directory_iterator(); ++itr2) // inner folder
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
			process(FilesVector.at(i), true);
		}
		FilesVector.clear();
	}
	// Analyse FL Path

	if (!config.get_rl_path().empty())
	{
		// Analyse RL Path
		for (directory_iterator itr(config.get_rl_path()); itr != directory_iterator(); ++itr) // top folder
		{
			if (boost::filesystem::is_directory(itr->path()))
			{
				if (std::find(config.rl_folders.begin(), config.rl_folders.end(), itr->path().filename().string()) != config.rl_folders.end())
				{
					for (directory_iterator itr2(itr->path()); itr2 != directory_iterator(); ++itr2) // inner folder
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


	store_database();

	return 0;
}

int Icmp_Analyzer::process(std::pair<std::string, std::string> item, bool is_fl)
{
	float seconds;
	clock_t				t1, t2;
	ether_header*		eth_hdr;
	ip_header*			ip_hdr;
	icmp_header*		icmp_hdr;
	struct in_addr		icmp_Saddr;
	struct in_addr		icmp_Daddr;
	jsonnlohmann		j_json;

	std::string folder = item.first;
	std::string filename = item.second;


	if (is_fl)
	{
		fl_files_.push_back(filename);
	}
	else {
		rl_files_.push_back(filename);
	}

	std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	int fileSize = in.tellg();
	in.close();

	icmpDescriptor = pcap_open_offline(filename.c_str(), errbuff); //handle to offline file
	double bytesRead = 0;

	double perc;//shows the percentage
	int next_perc = 0;
	double remain;

	std::cout << std::endl;
	t1 = clock();

	while (true)
	{
		returnValue_for_icmp = pcap_next_ex(icmpDescriptor, &header, &data);

		if (returnValue_for_icmp != 1)
			break;
		bytesRead += header->len;

		uint64_t ts = (static_cast<uint64_t>(header->ts.tv_sec) * 1000) + (header->ts.tv_usec / 1000); // millisecs

		perc = (bytesRead / fileSize) * 100;
		if (perc > (double)next_perc)
		{
			t2 = clock();
			float diff((float)t2 - (float)t1);
			seconds = diff / CLOCKS_PER_SEC;

			std::cout << (uint64_t)bytesRead << "/" << fileSize << " (" << perc << "%)" << std::endl;
			j_json["type"] = "progress";
			j_json["filename"] = filename;
			j_json["bytesRead"] = bytesRead;
			j_json["fileSize"] = fileSize;
			j_json["seconds"] = seconds;

			send_analysis_message_GUI(getJSON_string_from_jsonC(j_json));
			j_json.clear();
			next_perc += 5;
		}

		eth_hdr = (ether_header*)(data); //type casting data to header struct
		if (0x0008 == eth_hdr->type)
		{	 //check if its ipv4 packet or not in network address format
			ip_hdr = (ip_header*)(data + 14);
			if (1 == ip_hdr->ip_protocol) // only allow ICMP
			{
				icmp_hdr = (icmp_header*)(data + 14 + (ip_hdr->ip_header_len * 4));
				memcpy((u_char*)&icmp_Saddr.s_addr, (u_char*)&ip_hdr->ip_srcaddr, 4);
				string src(inet_ntoa(icmp_Saddr));

				memcpy((u_char*)&icmp_Daddr.s_addr, (u_char*)&ip_hdr->ip_destaddr, 4);
				string dst(inet_ntoa(icmp_Daddr));

				if (true == isChecked)
				{
					Ip_Address_to_country_mapper compareIp;

					bool srcPrivateIp = compareIp.stringComp(src);
					bool dstPrivateIp = compareIp.stringComp(dst);

					if (srcPrivateIp == false || dstPrivateIp == false)
					{
						continue;
					}
				}

				Icmp_stream new_icmp_streams(src, dst);

				int retVal = NULL;;

				bool found = false;
				for (int i = 0; i < icmp_streams_vector.size(); i++)
				{
					retVal = icmp_streams_vector.at(i).icmp_equals(new_icmp_streams);

					switch (retVal)
					{
					case 0:
						found = true;
						icmp_streams_vector.at(i).increment_icmp_src_dst();
						icmp_streams_vector.at(i).update_icmp_pair_info(icmp_hdr->un.echo.sequence, icmp_hdr->type , ts);
						if (is_fl)
						{
							icmp_streams_vector.at(i).add_folder_FL(folder);
							icmp_streams_vector.at(i).add_pcap_file_FL(filename);
						}
						else
						{
							icmp_streams_vector.at(i).add_folder_RL(folder);
							icmp_streams_vector.at(i).add_pcap_file_RL(filename);
						}
						break;
					case 1:
						found = true;
						icmp_streams_vector.at(i).increment_icmp_dst_src();
						icmp_streams_vector.at(i).update_icmp_pair_info(icmp_hdr->un.echo.sequence, icmp_hdr->type, ts);
						if (is_fl)
						{
							icmp_streams_vector.at(i).add_folder_FL(folder);
							icmp_streams_vector.at(i).add_pcap_file_FL(filename);
						}
						else
						{
							icmp_streams_vector.at(i).add_folder_RL(folder);
							icmp_streams_vector.at(i).add_pcap_file_RL(filename);
						}
						break;

					}
					if (found) break;
				}//for loop ending
				if (!found)
				{
					new_icmp_streams.increment_icmp_src_dst();
					new_icmp_streams.update_icmp_pair_info(icmp_hdr->un.echo.sequence, icmp_hdr->type , ts);
					if (is_fl)
					{
						new_icmp_streams.add_folder_FL(folder);
						new_icmp_streams.add_pcap_file_FL(filename);
					}
					else
					{
						new_icmp_streams.add_folder_RL(folder);
						new_icmp_streams.add_pcap_file_RL(filename);
					}
					icmp_streams_vector.push_back(new_icmp_streams);
				}

			}
		}
	}//while loop ending
	remain = fileSize - bytesRead;
	bytesRead += remain;
	perc = (bytesRead / fileSize) * 100;
	std::cout << (uint64_t)bytesRead << "/" << fileSize << " (" << perc << "%)" << std::endl;

	t2 = clock();
	float diff((float)t2 - (float)t1);

	seconds = diff / CLOCKS_PER_SEC;
	totalSecondsElapsed = totalSecondsElapsed + seconds;

	j_json["type"] = "progress";
	j_json["filename"] = filename;
	j_json["bytesRead"] = bytesRead;
	j_json["fileSize"] = fileSize;
	j_json["seconds"] = seconds;
	j_json["total_time"] = totalSecondsElapsed;

	send_analysis_message_GUI(getJSON_string_from_jsonC(j_json));

	/*****to store the name of the file and the size***/
	std::size_t found = filename.find_last_of("\\");
	std::string pcapFile = filename.substr(found + 1);
	if (pcapFile.front() == '"') {
		pcapFile.erase(0, 1);
		pcapFile.erase(pcapFile.size() - 1);
	}
	sizeCalculate size;
	if (is_fl)
	{
		std::string returnSizeFl = size.sizeCalculator(fileSize);
		sizePcapFl[pcapFile] = returnSizeFl;
	}
	else
	{
		std::string returnSizeRl = size.sizeCalculator(fileSize);
		sizePcapRl[pcapFile] = returnSizeRl;
	}

	/******************************************************/
	NumberOfFilesRead++;
	return 0;
}

void Icmp_Analyzer::store_database()
{
	time_t			rawtime;
	struct tm*		timeinfo;
	char			buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%Y-%m-%d-%I-%M-%S", timeinfo);
	std::string		str(buffer);

	str += "_icmp.json";

	std::ofstream ofs(str);
	std::ofstream dbofs("icmp_database.json", std::ios::app);

	j_icmp_streams.clear();

	if (ofs.is_open())
	{
		std::string				flFile, rlFile;
		std::string				sizeFL, sizeRL; /*size of the pcap file FL and RL*/
		jsonnlohmann			j_analysis_info;
		string					TotalFLFilesWQuotes, TotalRLFilesWQuotes; //string to store all FL or RL files read without quote

		pt::ptime current_date_microseconds = pt::microsec_clock::local_time();//to find the current time
		uint64_t milliseconds = current_date_microseconds.time_of_day().total_milliseconds();
		pt::time_duration current_time_milliseconds = pt::milliseconds(milliseconds);
		pt::ptime current_date_milliseconds(current_date_microseconds.date(), current_time_milliseconds);

		j_analysis_info["filePathFL"]					= config.get_fl_path();
		j_analysis_info["filePathRL"]					= config.get_rl_path();
		j_analysis_info["CreatedAt"]					= boost::posix_time::to_simple_string(current_date_milliseconds);
		j_analysis_info["Total_files_read"]				= NumberOfFilesRead;


		for (map<std::string, std::string>::iterator itrFL = sizePcapFl.begin(); itrFL != sizePcapFl.end(); ++itrFL)
		{
			jsonnlohmann pcap_info_fl = jsonnlohmann::object();
			flFile = itrFL->first;
			sizeFL = itrFL->second;
			pcap_info_fl["pcapFileFl"] = flFile;
			pcap_info_fl["size"] = sizeFL;
			j_analysis_info["FL_Files"].push_back(pcap_info_fl);
		}

		for (map<std::string, std::string>::iterator itrRL = sizePcapRl.begin(); itrRL != sizePcapRl.end(); ++itrRL)
		{
			jsonnlohmann pcap_info_rl = jsonnlohmann::object();
			rlFile = itrRL->first;
			sizeRL = itrRL->second;
			pcap_info_rl["pcapFileRl"] = rlFile;
			pcap_info_rl["size"] = sizeRL;
			j_analysis_info["RL_Files"].push_back(pcap_info_rl);
		}


		j_icmp_streams["analysis_info"].push_back(j_analysis_info);

		for (auto it = icmp_streams_vector.begin(); it != icmp_streams_vector.end(); ++it)
		{
			j_icmp_streams["streams"].push_back(it->get_statistics());
		}

		j_icmp_streams["streams"] = ip_address_resolve.analyze(j_icmp_streams);

		ofs << j_icmp_streams;
		ofs.close();
		dbofs << str << std::endl;
		dbofs.close();
	}
	else
	{
		std::cout << "the output file could not be opened." << std::endl;
	}
}

std::string Icmp_Analyzer::printToJSON()
{

	j_icmp_streams["type"] = "icmp_result";

	return getJSON_string_from_jsonC(j_icmp_streams);

}
