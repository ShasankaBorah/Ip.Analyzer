#include "Tcp_Analyzer.h"

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
#include <boost/asio/write.hpp>



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
Tcp_stream tcp_stream;


/*****************************************************************************************
* 1.) Start analysis fills the file vector with FL and RL files that are being chosen    *
*	  by the user and then calls the process function which process the files.	         *
* 2.) Process is a native function of the class									         *
* 3.) Acknowledgement number contains the value of the next sequence number the sender   *
*	  of the segment is expecting to receive. once connection is setup it is always		 *
*	  sent																				 *
*
*
*
******************************************************************************************/

Tcp_Analyzer::Tcp_Analyzer()
{
}


Tcp_Analyzer::~Tcp_Analyzer()
{
}

void Tcp_Analyzer::initialize()
{
	/*tcp_streams_vector.clear();*/
	num_files_read = 0;
	fl_files_.clear();
	rl_files_.clear();
	ip_streams_map.clear();
	root.clear();
	totalSecondsElapsed = 0;
}

int32_t Tcp_Analyzer::start_analysis()
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


	store_database();

	return 0;
}


int Tcp_Analyzer::process(std::pair<std::string, std::string> item, bool is_fl)
{ /*function start*/
	float							seconds;
	clock_t							t1, t2;
	ether_header*					eth_hdr;
	ip_header*						ip_hdr;
	tcp_header*						tcp_hdr;
	struct in_addr					tcp_Saddr;
	struct in_addr					tcp_Daddr;
	jsonnlohmann					j_json_progress;
	struct pcap_pkthdr* header;

	const u_char* data;

	std::string						folder = item.first;
	std::string						filename = item.second;


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

	tcpDescriptor = pcap_open_offline(filename.c_str(), errbuff); /*handle to offline file*/
	double bytesRead = 0;

	double perc;/*shows the percentage*/
	int next_perc = 0;
	double remain;

	std::cout << std::endl;
	t1 = clock();

	while (true) /*while loop*/
	{
		int returnValue_for_tcp = pcap_next_ex(tcpDescriptor, &header, &data);

		if (1 != returnValue_for_tcp)
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

		eth_hdr = (ether_header*)(data);
		if (0x0008 == eth_hdr->type) /*if ip packet*/
		{
			ip_hdr = (ip_header*)(data + 14);
			if (6 == ip_hdr->ip_protocol) /*if tcp*/
			{
				

				tcp_hdr = (tcp_header*)(data + 14 + (ip_hdr->ip_header_len * 4));

				memcpy((u_char*)&tcp_Saddr.s_addr, (u_char*)&ip_hdr->ip_srcaddr, 4);
				string src(inet_ntoa(tcp_Saddr));

				memcpy((u_char*)&tcp_Daddr.s_addr, (u_char*)&ip_hdr->ip_destaddr, 4);
				string dst(inet_ntoa(tcp_Daddr));

				uint32_t s_port = ntohs(tcp_hdr->th_sport); /*source port number*/
				uint32_t d_port = ntohs(tcp_hdr->th_dport); /*destination port number*/

				uint64_t se_no = ntohl(tcp_hdr->s_number); /* sequence number of the packet*/
				uint64_t ack_no = ntohl(tcp_hdr->ack_number); /*acknowledgement number of the packet*/
				
				std::string src_port_str = std::to_string(s_port); /*converting source port and dst port to string to cancatenate*/
				std::string dst_port_str = std::to_string(d_port);

				/*	***************************************************************
				 *	search  for ip stream with src and dst ip
				 *	if not found add it to map
				 *	inside the ip stream find src dst port stream (tcp stream)
				 *	if not found add to tc stream map in the ip stream
				 *   update seq and ack no
				 ******************************************************************/


				std::string src_port_ip = src + ":" + src_port_str;
				std::string dst_port_ip = dst + ":" + dst_port_str;
				
				//std::string ip_str = src + ":" + dst; /* converting and cancatenating src ip and dst ip*/

				std::string src_dst_port_str = src_port_str + "_" + dst_port_str; /*cancatinating src and dst port*/

				Tcp_stream new_tcp_streams(src_port_ip , dst_port_ip); /*creating  a new tcp stream*/
				
				int retVal = NULL;;

				bool found = false;
				for(int i = 0 ; i < tcp_streams_vector.size() ; i++)
				{
					retVal = tcp_streams_vector.at(i).tcp_equals(new_tcp_streams);

					switch(retVal)
					{
					case 0: /*means src to destination*/
						found = true;
						tcp_streams_vector.at(i).increment_tcp_src_dst();
						//tcp_streams_vector.at(i).update(src_dst_port_str, se_no, ack_no);
						if (is_fl)
						{
							tcp_streams_vector.at(i).add_folder_FL(folder);
							tcp_streams_vector.at(i).add_pcap_file_FL(filename);
						}
						else
						{
							tcp_streams_vector.at(i).add_folder_RL(folder);
							tcp_streams_vector.at(i).add_pcap_file_RL(filename);
						}

						break;

					case 1: /*means destination to source*/
						found = true;
						tcp_streams_vector.at(i).increment_tcp_dst_src();
						//tcp_streams_vector.at(i).update(src_dst_port_str, se_no, ack_no);
						if (is_fl)
						{
							tcp_streams_vector.at(i).add_folder_FL(folder);
							tcp_streams_vector.at(i).add_pcap_file_FL(filename);
						}
						else
						{
							tcp_streams_vector.at(i).add_folder_RL(folder);
							tcp_streams_vector.at(i).add_pcap_file_RL(filename);
						}

						break;

					}	
					if(found)
					{
						break;
					}
				}//for loop ends
				if(!found)
				{
					new_tcp_streams.increment_tcp_src_dst();				
					//new_tcp_streams.update(src_dst_port_str, se_no, ack_no);
					
					if (is_fl)
					{
						new_tcp_streams.add_folder_FL(folder);
						new_tcp_streams.add_pcap_file_FL(filename);
					}
					else
					{
						new_tcp_streams.add_folder_RL(folder);
						new_tcp_streams.add_pcap_file_RL(filename);
					}
					tcp_streams_vector.push_back(new_tcp_streams);
				}

				//Ip_stream* ip_stream;
				//if (ip_streams_map.find(ip_str) == ip_streams_map.end()) //if not found
				//{
				//	ip_stream = new Ip_stream(src, dst, filename, is_fl);
				//	ip_streams_map.insert(std::pair<std::string, Ip_stream*>(ip_str, ip_stream));
				//	ip_stream->update(src_dst_port_str, se_no, ack_no);
				//}
				//else
				//{
				//	ip_stream = ip_streams_map.at(ip_str);
				//	ip_stream->update(src_dst_port_str, se_no, ack_no);
				//}


			} /*if tcp ending*/
		} /*if ip packet ending*/
	} /*while loop ending*/
	remain = fileSize - bytesRead;
	bytesRead += remain;
	perc = (bytesRead / fileSize) * 100;
	std::cout << (uint64_t)bytesRead << "/" << fileSize << " (" << perc << "%)" << std::endl;

	t2 = clock();

	float diff((float)t2 - (float)t1);

	seconds = diff / CLOCKS_PER_SEC;
	totalSecondsElapsed = totalSecondsElapsed + seconds;

	j_json_progress["type"] = "progress";
	j_json_progress["filename"] = filename;
	j_json_progress["bytesRead"] = bytesRead;
	j_json_progress["fileSize"] = fileSize;
	j_json_progress["seconds"] = seconds;
	j_json_progress["total_time"] = totalSecondsElapsed;

	send_analysis_message_GUI(getJSON_string_from_jsonC(j_json_progress));

	num_files_read++;
	
	//closeBinMap();
	return 0;
} /*function ending*/

void Tcp_Analyzer::store_database()
{
	//json j_analysis_info;
	time_t rawtime;
	struct tm* timeinfo;
	char buffer[80];
	string TotalFLFilesWQuotes, TotalRLFilesWQuotes; //string to store all FL or RL files read without quote

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%Y-%m-%d-%I-%M-%S", timeinfo);
	std::string str(buffer);

	str += "_TCP.json";

	std::ofstream ofs(str);
	std::ofstream dbofs("tcp_database.json", std::ios::app);

	root.clear();

	if (ofs.is_open())
	{
		pt::ptime current_date_microseconds = pt::microsec_clock::local_time();
		uint64_t milliseconds = current_date_microseconds.time_of_day().total_microseconds();
		pt::time_duration current_time_milliseconds = pt::milliseconds(milliseconds);
		pt::ptime current_date_milliseconds(current_date_microseconds.date(), current_time_milliseconds);
		jsonnlohmann j_files = jsonnlohmann::object(); /*json object to hold the file names that are read*/

		j_files["filePathFL"] = config.get_fl_path();
		j_files["filePathRL"] = config.get_rl_path();
		j_files["CreatedAt"] = boost::posix_time::to_simple_string(current_date_milliseconds);
		j_files["number_of_files_read"] = num_files_read;

		jsonnlohmann ip_stream;


		for (auto itrFL = fl_files_.begin(); itrFL != fl_files_.end(); itrFL++)
		{ //displaying all the FL files read
			TotalFLFilesWQuotes = itrFL->filename().string();
			if (TotalFLFilesWQuotes.front() == '"')
			{
				TotalFLFilesWQuotes.erase(0, 1);
				TotalFLFilesWQuotes.erase(TotalFLFilesWQuotes.size() - 1);
			}
			j_files["fl_files"].push_back(TotalFLFilesWQuotes);
		}

		for (auto itrRL = rl_files_.begin(); itrRL != rl_files_.end(); itrRL++)
		{ //Displaying all the RL FIles
			TotalRLFilesWQuotes = itrRL->filename().string();
			if (TotalRLFilesWQuotes.front() == '"')
			{
				TotalRLFilesWQuotes.erase(0, 1);
				TotalRLFilesWQuotes.erase(TotalRLFilesWQuotes.size() - 1);
			}
			j_files["rl_files"].push_back(TotalRLFilesWQuotes);
		}
		root["data_info"].push_back(j_files);
		j_files.clear();

		for (auto it = tcp_streams_vector.begin(); it != tcp_streams_vector.end(); ++it)
		{
			root["streams"].push_back(it->get_statistics());
		}

		/*for (auto it = tcp_streams_vector.begin(); it != tcp_streams_vector.end(); ++it)
		{
			
			ip_stream["srcIP"] = it->g
			ip_stream["dstIP"] = it->second->get_ip_dstIP();
			ip_stream["file_fl"] = it->second->fl_files_return().filename().string();
			ip_stream["file_rl"] = it->second->rl_files_return().filename().string();
			ip_stream["tcp_stream"] = it->second->get_statistics();
			root["ip_streams"].push_back(ip_stream);
		}*/


		/*for(auto it = tcp_streams_vector.begin() ; it != tcp_streams_vector.end() ; ++it)
		{
			ip_stream["srcIP"] = it->tcp_srcIP;
			ip_stream["dstIP"] = it->second->get_ip_dstIP();
			ip_stream["file_fl"] = it->second->fl_files_return().filename().string();
			ip_stream["file_rl"] = it->second->rl_files_return().filename().string();
			ip_stream["tcp_stream"] = it->second->get_statistics();
			root["ip_streams"].push_back(ip_stream);
			
		}*/

		ofs << root; //write the json to the output file
		ofs.close();
		dbofs << str << std::endl; //write the file name to the database file
		dbofs.close();
	}
	else
	{
		std::cout << "The output file could not be opened. " << std::endl;
	}
}

std::string Tcp_Analyzer::printToJson()
{
	root["type"] = "tcp_result";
	return getJSON_string_from_jsonC(root);
}



