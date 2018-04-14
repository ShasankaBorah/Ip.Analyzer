#include "Analyzer.h"
#include "Streamer.h"
#include "sizeCalculate.h"
#include "Protocol_count_stream.h"
#include "Ip_Address_to_country_mapper.h"
#include <string>
#include <iostream>
#include <map>
#include <time.h>
#include <ticktock.h>
#include <vector>
#include <algorithm>
#include <fstream>
#include <set>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "boost/date_time/posix_time/posix_time.hpp"
#include <Configuration.h>
#include "json.hpp"

using jsonnlohmann = nlohmann::json;
using namespace std;
namespace pt = boost::posix_time;
using namespace boost::filesystem;


/*eternal functions*/
extern					Ip_Address_to_country_mapper ip_address_resolve;
extern void				send_analysis_message_GUI(std::string progress_message);
extern void				send_message_GUI(std::string msg);
extern					std::string getJSON_string_from_jsonC(jsonnlohmann json);

extern					Configuration config;

pcapPackAnalyzer::pcapPackAnalyzer()
{
}

pcapPackAnalyzer::~pcapPackAnalyzer()
{
}

void pcapPackAnalyzer::initialize(bool isExPrivateChecked)
{
	isChecked = isExPrivateChecked;
	NumberOfFilesRead = 0;
	streams.clear();
	/*fl_files_.clear();
	rl_files_.clear();*/
	protocols.clear();
	j_root.clear();
	totalSecondsElapsed = 0;
	sizePcapFl.clear();
	sizePcapRl.clear();
}

int pcapPackAnalyzer::start_analysis()
{
	vector<std::pair<string, string>> FilesVector;

	// Analyse FL Path
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
			cout << "Reading File (" << (i + 1) << "/" << FilesVector.size() << ") : " << FilesVector.at(i).second << std::endl;
			process(FilesVector.at(i), true);
		}
		FilesVector.clear();
	}


	// Analyse RL Path
	if (!config.get_rl_path().empty())
	{
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
			cout << "Reading File (" << (i + 1) << "/" << FilesVector.size() << ") : " << FilesVector.at(i).second << std::endl;
			process(FilesVector.at(i), false);
		}

		FilesVector.clear();
	}

	store_database();

	return 0;
}

/*packet processing function */
int pcapPackAnalyzer::process(std::pair<std::string, std::string> item, bool is_fl)
{
	float						seconds;
	clock_t						t1, t2;
	uint64_t					frames = 0;
	uint64_t					nonIpPacket = 0;
	uint64_t					packetCount = 0;
	jsonnlohmann				j_json;
	std::string					folder = item.first;
	std::string					filename = item.second;
	


	j_json.clear();

	/*if (is_fl)
	{
		fl_files_.push_back(filename);
	}
	else {
		rl_files_.push_back(filename);
	}*/

	//Get file size
	std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	uint32_t fileSize = (uint32_t)in.tellg();
	in.close();

	pcap_t* descriptor;	//pcap_t* type handle
	char errbuff[PCAP_BUF_SIZE];
	ether_header* eth_hdr;
	ip_header* ip_hdr;

	descriptor = pcap_open_offline(filename.c_str(), errbuff); //handle to offline file
	double bytesRead = 0;

	double perc;//shows the percentage
	int next_perc = 0;
	double remain;

	std::cout << std::endl;
	t1 = clock();
	while (true)
	{
		returnValue = pcap_next_ex(descriptor, &header, &data);
		if (returnValue != 1)
			break;

		frames++;//total number of frames read from the files
		bytesRead += header->len;

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
			next_perc += 5;
		}

		eth_hdr = (ether_header*)(data); //type casting data to header struct
		if (eth_hdr->type == 0x0008)
		{
			ip_hdr = (ip_header*)(data + 14);

			memcpy((u_char*)&Saddr.s_addr, (u_char*)&ip_hdr->ip_srcaddr, 4);
			string src(inet_ntoa(Saddr));

			memcpy((u_char*)&Daddr.s_addr, (u_char*)&ip_hdr->ip_destaddr, 4);
			string dst(inet_ntoa(Daddr));


			if(true == isChecked)
			{
				Ip_Address_to_country_mapper compareIp;

				bool srcPrivateIp = compareIp.stringComp(src);
				bool dstPrivateIp = compareIp.stringComp(dst);

				if (srcPrivateIp == false || dstPrivateIp == false)
				{
					continue;
				}
			}
			

			stream newStream(src, dst);

			int retVal;

			bool found = false;
			for (int i = 0; i < streams.size(); i++)
			{

				retVal = streams.at(i).equals(newStream);

				if (retVal == 0 || retVal == 1)
				{
					found = true;
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
					if (retVal == 0)
					{
						streams.at(i).incrementAtoB();
						streams.at(i).protoCountAtoB(ip_hdr->ip_protocol);
					}
					else
					{
						streams.at(i).incrementBtoA();
						streams.at(i).protoCountBtoA(ip_hdr->ip_protocol);
					}
				}
				if (found) break;
			}

			if (!found)
			{
				newStream.incrementAtoB();
				newStream.protoCountAtoB(ip_hdr->ip_protocol);
				if (is_fl)
				{
					newStream.add_folder_FL(folder);
					newStream.add_pcap_file_FL(filename);
				}
				else
				{
					newStream.add_folder_RL(folder);
					newStream.add_pcap_file_RL(filename);
				}
				streams.push_back(newStream);
			}

			protNum = ip_hdr->ip_protocol;
			it = protocols.find(protNum);   //find the protocol number in the map , if found then increment value else create a new key value pair
			if (it != protocols.end())
			{
				it->second++;
			}
			else
			{
				protocols[protNum] = 1;
			}
			packetCount++; //packet count incremented
		}
		else
		{
			nonIpPacket++;   //non ip packet count incremented
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
	if(is_fl)
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

	std::cout << "\n Total number of frames read =>> " << frames << std::endl;//total number of packets read
	std::cout << "\n Total number of non IP Packets =>> " << nonIpPacket << std::endl;//total number of non ip packets read
	std::cout << "\n Total number of IP Packets =>> " << packetCount << std::endl;//total number pf ip packets read

	/*iterator to print the protocols and count of that protocol*/
	for (std::map<int, int>::iterator it = protocols.begin(); it != protocols.end(); it++)
	{
		std::cout << it->first << " => " << it->second << '\n';
	}

	NumberOfFilesRead++;
	std::cout << "\n\n";

	return 0;
}

void pcapPackAnalyzer::store_database()
{
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%Y-%m-%d-%I-%M-%S", timeinfo);
	std::string str(buffer);

	str += "_pcap.json";

	std::ofstream ofs(str);
	std::ofstream dbofs("pcap_database.json", std::ios::app);

	if (ofs.is_open())
	{
		jsonnlohmann j_analysis_info = jsonnlohmann::object();
		string TotalFLFilesWQuotes, TotalRLFilesWQuotes; //string to store all FL or RL files read without quote
		std::string flFile, rlFile;
		std::string sizeFL , sizeRL; /*size of the pcap file FL and RL*/

		pt::ptime current_date_microseconds = pt::microsec_clock::local_time();//to find the current time
		uint64_t milliseconds = current_date_microseconds.time_of_day().total_milliseconds();
		pt::time_duration current_time_milliseconds = pt::milliseconds(milliseconds);
		pt::ptime current_date_milliseconds(current_date_microseconds.date(), current_time_milliseconds);

		j_analysis_info["filePathFL"] = config.get_fl_path();
		j_analysis_info["filePathRL"] = config.get_rl_path();
		j_analysis_info["CreatedAt"] = boost::posix_time::to_simple_string(current_date_milliseconds);
		j_analysis_info["Total_Files_Read"] = NumberOfFilesRead;

		//for (vector<boost::filesystem::path>::iterator itrFL = fl_files_.begin(); itrFL != fl_files_.end(); itrFL++)
		//{ //displaying all the FL files read
		//	
		//	TotalFLFilesWQuotes = itrFL->filename().string();
		//	if (TotalFLFilesWQuotes.front() == '"') {
		//		TotalFLFilesWQuotes.erase(0, 1);
		//		TotalFLFilesWQuotes.erase(TotalFLFilesWQuotes.size() - 1);
		//	}
		//	j_analysis_info["FL_Files"].push_back(TotalFLFilesWQuotes);
		//}

		for(map<std::string, std::string>::iterator itrFL = sizePcapFl.begin(); itrFL != sizePcapFl.end(); ++itrFL)
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

		//for (vector<boost::filesystem::path>::iterator itrRL = rl_files_.begin(); itrRL != rl_files_.end(); itrRL++)
		//{ //Displaying all the RL FIles
		//	TotalRLFilesWQuotes = itrRL->filename().string();
		//	if (TotalRLFilesWQuotes.front() == '"') {
		//		TotalRLFilesWQuotes.erase(0, 1);
		//		TotalRLFilesWQuotes.erase(TotalRLFilesWQuotes.size() - 1);
		//	}
		//	j_analysis_info["RL_Files"].push_back(TotalRLFilesWQuotes);
		//}

		for (std::vector<stream>::iterator it = streams.begin(); it != streams.end(); ++it)
		{
			j_root["IPDetails"].push_back(it->getData());
		}
		j_root["IPDetails"] = ip_address_resolve.analyze(j_root);

		j_root["prot_details"] = j_protocol_root;
		j_root["status"] = "OK";
		j_root["data_info"] = j_analysis_info;
		j_analysis_info.clear();
		j_protocol_root.clear();

		ofs << j_root;
		ofs.close();

		dbofs << str << std::endl;
		dbofs.close();
	}
	else {
		std::cout << "the output file could not be opened." << std::endl;
	}
}

std::string pcapPackAnalyzer::printToJSON()
{
	j_root["type"] = "result";
	return getJSON_string_from_jsonC(j_root);
}


void pcapPackAnalyzer::printPairs()
{
	jsonnlohmann j_pairRoot;
	
	std::map<std::string, std::set<std::string>> fl_rl_pair_map;

	for (int i = 0; i < streams.size(); i++)
	{
		
		if(streams.at(i).getFolderFL().size() >= 1)
		{
			std::set<std::string> setFL = streams.at(i).getFolderFL();		
			for(auto it = setFL.begin() ; it != setFL.end() ; ++it)
			{
				std::set<std::string> rlFiles;
				//search for key if not found then add else check rl folder
				if(fl_rl_pair_map.find(*it) == fl_rl_pair_map.end() ) //not found
				{
					
					if (streams.at(i).getFolderRL().size() >= 1)
					{

						std::set<std::string> setRL = streams.at(i).getFolderRL();

						for (auto itr = setRL.begin(); itr != setRL.end(); ++itr)
						{
							rlFiles.insert(*itr);
						}
					}

					fl_rl_pair_map[*it] = rlFiles;				
				}	
				else//if key  found
				{
					if (streams.at(i).getFolderRL().size() >= 1)
					{
						std::set<std::string> newSet1 = streams.at(i).getFolderRL();
						for (auto itr = newSet1.begin(); itr != newSet1.end(); ++itr)
						{
							if(fl_rl_pair_map[*it].find(*itr) == fl_rl_pair_map[*it].end()) //if value not found in the set
							{
								fl_rl_pair_map[*it].insert(*itr);
							}
						}
					}						
				}
			}		
		}
		else
		{
			continue;
		}
	}


	for(auto mapItr = fl_rl_pair_map.begin() ; mapItr != fl_rl_pair_map.end() ; ++mapItr )
	{
		jsonnlohmann j_pairJson;
		j_pairJson["Fl_file"] = mapItr->first;
		if(mapItr->second.size() != 0)
		{
			jsonnlohmann j_rl_files;
			for(auto itrSet = mapItr->second.begin() ; itrSet != mapItr->second.end() ; ++itrSet)
			{
				
				j_pairJson["Rl_file"].push_back(*itrSet);
			}
			j_rl_files.clear();		
		}
		else
		{
			j_pairJson["Rl_file"] = "NO RL FILE";

		}
		j_pairRoot.push_back(j_pairJson);
		j_pairJson.clear();
		
	}

	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%Y-%m-%d-%I-%M-%S", timeinfo);
	std::string str(buffer);

	str += "_pair.json";

	std::ofstream ofs(str);
	ofs << j_pairRoot;
	ofs.close();
	j_pairRoot.clear();
	



}

