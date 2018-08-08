#include "Dns_Analyzer.h"
#include "Dns_ip_stream.h"
#include "sizeCalculate.h"
#include "stdafx.h"
#include "boost/filesystem.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <iostream>
#include <conio.h>
#include <string.h>
#include <pcap.h>
#include <conio.h>
#include <map>
#include <set>
#include <Configuration.h>
#include <json.hpp>	


using namespace std;
using namespace boost::filesystem;
namespace pt = boost::posix_time;
using jsonnlohmann = nlohmann::json;

extern Configuration config;
extern void send_analysis_message_GUI(std::string progress_msg);
extern std::string getJSON_string_from_jsonC(jsonnlohmann json);


Dns_Analyzer::Dns_Analyzer()
{
}


Dns_Analyzer::~Dns_Analyzer() //default deconstructor
{
}


void Dns_Analyzer::initialize()
{
	sizePcapFl.clear();
	sizePcapRl.clear();
	streams.clear();
	fl_files_.clear();
	rl_files_.clear();
	totalSecondsElapsed = 0;
}


int32_t Dns_Analyzer::start_analysis()
{
	std::vector<std::pair<string, string>> FilesVector;

	/* Analyse FL Path*/
	if(!config.get_fl_path().empty())
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
	
	if(!config.get_rl_path().empty())
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
	/* Analyse RL Path*/
	
	store_database();

	return 0;
}

int Dns_Analyzer::process(std::pair<std::string, std::string> item, bool is_fl)
{
	float				seconds;
	clock_t				t1, t2;
	ether_header*		eth_hdr;
	ip_header*			ip_hdr;
	udp_header*			udp_hdr;
	DNS_HEADER*			dns_hdr;
	struct in_addr		udp_Saddr;
	struct in_addr		udp_Daddr;
	jsonnlohmann		j_json_progress;
	std::string			folder = item.first;
	std::string			filename = item.second;


	if (is_fl)
	{
		fl_files_.push_back(filename);
	}
	else
	{
		rl_files_.push_back(filename);
	}

	std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	int fileSize = in.tellg();
	in.close();

	Descriptor = pcap_open_offline(filename.c_str(), errbuff); /*handle to offline file*/
	double bytesRead = 0;

	double perc;/*shows the percentage*/
	int next_perc = 0;
	double remain;

	std::cout << std::endl;
	t1 = clock();

	while (true) /*while loop*/
	{
		int returnValue = pcap_next_ex(Descriptor, &header, &data);

		if (1 != returnValue)
		{
			break;
		}

		bytesRead += header->len;
		perc = (bytesRead / fileSize) * 100;

		if (perc > double(next_perc))
		{
			t2		=	 clock();
			float		 diff((float)t2 - (float)t1);
			seconds =	 diff / CLOCKS_PER_SEC;
			std::cout << (uint64_t)bytesRead << "/" << fileSize << " ( " << perc << " %) " << std::endl;
			j_json_progress["type"]			=	"progress";
			j_json_progress["filename"]		=	filename;
			j_json_progress["bytesRead"]	=	bytesRead;
			j_json_progress["fileSize"]		=	fileSize;
			j_json_progress["seconds"]		=	seconds;

			send_analysis_message_GUI(getJSON_string_from_jsonC(j_json_progress));
			j_json_progress.clear();

			next_perc += 5;
		}

		eth_hdr = (ether_header*)(data);
		if (0x0008 == eth_hdr->type) /*if ip packet*/
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

					Dns_ip_stream new_dns_ip_stream(src, dst);

					int retVal;
					bool found = false;

					for (int i = 0; i < streams.size(); i++)
					{
						retVal = streams.at(i).equals(new_dns_ip_stream);

						switch (retVal)
						{
						case 0:
							{
								found = true;

								streams.at(i).increment_dns_src_dst();
								uint16_t k = ntohs(dns_hdr->id);
								uint8_t qr1 = ntohs(dns_hdr->qr);
								streams.at(i).update_info(dns_hdr->id, dns_hdr->qr);
								if (is_fl)
								{
									streams.at(i).add_folder_FL(folder);
									streams.at(i).add_pcap_file_FL(filename);
								}
								else
								{
									streams.at(i).add_folder_RL(folder);
									streams.at(i).add_pcap_file_RL(filename);
								}
								break;
							}


						case 1:
							{
								found = true;
								streams.at(i).increment_dns_dst_src();
								streams.at(i).update_info(dns_hdr->id, dns_hdr->qr);
								if (is_fl)
								{
									streams.at(i).add_folder_FL(folder);
									streams.at(i).add_pcap_file_FL(filename);
								}
								else
								{
									streams.at(i).add_folder_RL(folder);
									streams.at(i).add_pcap_file_RL(filename);
								}
								break;
							}
						}
						if (found) break;
					}/*for loop ending*/
					if (!found)
					{
						new_dns_ip_stream.increment_dns_src_dst();
						uint16_t b = ntohs(dns_hdr->id);
						uint8_t qr2 = ntohs(dns_hdr->qr);
						new_dns_ip_stream.update_info(dns_hdr->id, dns_hdr->qr);
						if (is_fl)
						{
							new_dns_ip_stream.add_folder_FL(folder);
							new_dns_ip_stream.add_pcap_file_FL(filename);
						}
						else
						{
							new_dns_ip_stream.add_folder_RL(folder);
							new_dns_ip_stream.add_pcap_file_RL(filename);
						}
						streams.push_back(new_dns_ip_stream);
					}/*if not found*/
				}/*if dns or not ending*/
			} /*if udp hdr ending*/
		} /*if ip packet ending*/
	} /*while loop ending*/
	remain = fileSize - bytesRead;
	bytesRead += remain;
	perc = (bytesRead / fileSize) * 100;
	std::cout << (uint64_t)bytesRead << "/" << fileSize << " (" << perc << "%)" << std::endl;

	t2		= clock();
	float	diff((float)t2 - (float)t1);

	seconds = diff / CLOCKS_PER_SEC;
	totalSecondsElapsed = totalSecondsElapsed + seconds;

	j_json_progress["type"]			= "progress";
	j_json_progress["filename"]		= filename;
	j_json_progress["bytesRead"]	= bytesRead;
	j_json_progress["fileSize"]		= fileSize;
	j_json_progress["seconds"]		= seconds;
	j_json_progress["total_time"]	= totalSecondsElapsed;

	send_analysis_message_GUI(getJSON_string_from_jsonC(j_json_progress));

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

	num_files_read++;
	return 0;
}

void Dns_Analyzer::store_database()
{
	time_t rawtime;
	struct tm* timeinfo;
	char buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%Y-%m-%d-%I-%M-%S", timeinfo);
	std::string str(buffer);

	str += "_dns.json";

	std::ofstream ofs(str);
	std::ofstream dbofs("dns_database.json", std::ios::app);

	j_dns_stream.clear();

	if (ofs.is_open())
	{
		std::string						flFile, rlFile;
		std::string						sizeFL, sizeRL; /*size of the pcap file FL and RL*/
		jsonnlohmann					j_analysis_info;
		string							TotalFLFilesWQuotes, TotalRLFilesWQuotes; //string to store all FL or RL files read without quote

		pt::ptime current_date_microseconds = pt::microsec_clock::local_time();//to find the current time
		uint64_t milliseconds = current_date_microseconds.time_of_day().total_milliseconds();
		pt::time_duration current_time_milliseconds = pt::milliseconds(milliseconds);
		pt::ptime current_date_milliseconds(current_date_microseconds.date(), current_time_milliseconds);

		j_analysis_info["filePathFL"] = config.get_fl_path();
		j_analysis_info["filePathRL"] = config.get_rl_path();
		j_analysis_info["CreatedAt"] = boost::posix_time::to_simple_string(current_date_milliseconds);
		j_analysis_info["number_of_files_read"] = num_files_read;

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

		//for (auto itrFL = fl_files_.begin(); itrFL != fl_files_.end(); itrFL++)
		//{ //displaying all the FL files read
		//	TotalFLFilesWQuotes = itrFL->filename().string();
		//	if (TotalFLFilesWQuotes.front() == '"')
		//	{
		//		TotalFLFilesWQuotes.erase(0, 1);
		//		TotalFLFilesWQuotes.erase(TotalFLFilesWQuotes.size() - 1);
		//	}
		//	j_analysis_info["fl_files"].push_back(TotalFLFilesWQuotes);
		//}

		//for (auto itrRL = rl_files_.begin(); itrRL != rl_files_.end(); itrRL++)
		//{ //Displaying all the RL FIles
		//	TotalRLFilesWQuotes = itrRL->filename().string();
		//	if (TotalRLFilesWQuotes.front() == '"')
		//	{
		//		TotalRLFilesWQuotes.erase(0, 1);
		//		TotalRLFilesWQuotes.erase(TotalRLFilesWQuotes.size() - 1);
		//	}
		//	j_analysis_info["rl_files"].push_back(TotalRLFilesWQuotes);
		//}

		j_dns_stream["analysis_info"].push_back(j_analysis_info);

		for (auto it = streams.begin(); it != streams.end(); ++it)
		{
			j_dns_stream["streams"].push_back(it->get_statistics());
		}
		ofs << j_dns_stream;
		ofs.close();
		dbofs << str << std::endl;
		dbofs.close();
	}
	else
	{
		std::cout << "the output file could not be opened." << std::endl;
	}
}

std::string Dns_Analyzer::printToJson()
{
	j_dns_stream["type"] = "dns_result";

	return getJSON_string_from_jsonC(j_dns_stream);
}
