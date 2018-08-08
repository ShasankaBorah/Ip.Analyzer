#include "Evolution_SCPC.h"
#include "Evolution_SCPC_stream.h"
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



Evolution_SCPC::Evolution_SCPC()
{
}


Evolution_SCPC::~Evolution_SCPC()
{
}

void Evolution_SCPC::initialize(bool isExPrivateChecked)
{
	isChecked = isExPrivateChecked;
	NumberOfFilesRead = 0;
	streams.clear();
	/*fl_files_.clear();
	rl_files_.clear();*/
	protocols.clear();
	j_root.clear();
	totalSecondsElapsed = 0;
	sizePcapFiles.clear();

}

int Evolution_SCPC::start_evolutionSCPC_analysis()
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

	store_database();
	//printPairs();
	return 0;
}


int Evolution_SCPC::process(std::pair<std::string, std::string> item, bool is_fl)
{
	float						seconds;
	clock_t						t1, t2;
	jsonnlohmann				j_json;
	uint64_t					frames = 0;
	uint64_t					nonIpPacket = 0;
	uint64_t					packetCount = 0;
	std::string					folder = item.first;
	std::string					filename = item.second;
	int returnValue;

	j_json.clear();

	//Get file size
	std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	uint32_t fileSize = (uint32_t)in.tellg();
	in.close();

	pcap_t* descriptor;	//pcap_t* type handle
	char errbuff[PCAP_BUF_SIZE];
	ether_header* eth_hdr;
	ip_header* ip_hdr;

	descriptor = pcap_open_offline(filename.c_str(), errbuff);

	double remain;
	double perc;
	double bytesRead = 0;
	int next_perc = 0;

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

		eth_hdr = (ether_header*)(data);
		if (eth_hdr->type == 0x0008)
		{
			//bool isChecked = false;

			ip_hdr = (ip_header*)(data + 14);

			memcpy((u_char*)&Saddr.s_addr, (u_char*)&ip_hdr->ip_srcaddr, 4);
			string src(inet_ntoa(Saddr));

			memcpy((u_char*)&Daddr.s_addr, (u_char*)&ip_hdr->ip_destaddr, 4);
			string dst(inet_ntoa(Daddr));

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

			Evolution_SCPC_stream newStream(src, dst);
			int retVal;
			bool found = false;
			for (int i = 0; i < streams.size(); i++)
			{
				retVal = streams.at(i).equals(newStream);

				if (retVal == 0 || retVal == 1)
				{
					found = true;

					if (retVal == 0)
					{
						streams.at(i).addAtoBmap(folder);
						/*streams.at(i).incrementAtoB();
						streams.at(i).protoCountAtoB(ip_hdr->ip_protocol);*/

					}
					else
					{
						streams.at(i).addBtoAmap(folder);
					}

				}//if retval ends
				if (found) break;
			}//for loop ends
			if (!found)
			{
				/*newStream.incrementAtoB();
				newStream.protoCountAtoB(ip_hdr->ip_protocol);
				newStream.add_folder_FL(folder);
				newStream.add_pcap_file_FL(filename);*/
				newStream.addAtoBmap(folder);
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

		}//if ethernet packet ends
		else
		{
			nonIpPacket++;   //non ip packet count incremented
		}
	}//while loop ends
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
	std::string returnSizeFl = size.sizeCalculator(fileSize);
	sizePcapFiles[pcapFile] = returnSizeFl;

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
}//process ends


void Evolution_SCPC::store_database()
{
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%Y-%m-%d-%I-%M-%S", timeinfo);
	std::string str(buffer);

	str += "_evolution_scpc.json";

	std::ofstream ofs(str);
	std::ofstream dbofs("evolution_scpc_database.json", std::ios::app);

	if (ofs.is_open())
	{
		jsonnlohmann j_analysis_info = jsonnlohmann::object();
		string TotalFLFilesWQuotes, TotalRLFilesWQuotes; //string to store all FL or RL files read without quote
		std::string flFile, rlFile;
		std::string sizeFL, sizeRL; /*size of the pcap file FL and RL*/

		pt::ptime current_date_microseconds = pt::microsec_clock::local_time();//to find the current time
		uint64_t milliseconds = current_date_microseconds.time_of_day().total_milliseconds();
		pt::time_duration current_time_milliseconds = pt::milliseconds(milliseconds);
		pt::ptime current_date_milliseconds(current_date_microseconds.date(), current_time_milliseconds);

		j_analysis_info["filePathFL"] = config.get_fl_path();
		j_analysis_info["filePathRL"] = config.get_rl_path();
		j_analysis_info["CreatedAt"] = boost::posix_time::to_simple_string(current_date_milliseconds);
		j_analysis_info["Total_Files_Read"] = NumberOfFilesRead;


		for (map<std::string, std::string>::iterator itrFL = sizePcapFiles.begin(); itrFL != sizePcapFiles.end(); ++itrFL)
		{
			jsonnlohmann pcap_info_fl = jsonnlohmann::object();
			flFile = itrFL->first;
			sizeFL = itrFL->second;
			pcap_info_fl["pcapFile"] = flFile;
			pcap_info_fl["size"] = sizeFL;
			j_analysis_info["Freq_Files"].push_back(pcap_info_fl);
		}

		for (std::vector<Evolution_SCPC_stream>::iterator it = streams.begin(); it != streams.end(); ++it)
		{
			j_root["IPDetails"].push_back(it->getData());
		}
		//j_root["IPDetails"] = ip_address_resolve.analyze(j_root);

		//j_root["prot_details"] = j_protocol_root;
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

//void Evolution_SCPC::printPairs()
//{
//	jsonnlohmann j_pairRoot;
//	//std::set<std::vector<string>> pairs;
//	//std::set<std::string> freqFolders;
//	bool intersectExist = false;
//	bool difference = false;
//
//
//	std::set<std::string> newSet;
//
//
//	std::vector<std::set<std::string>> pairs;
//	std::vector<std::set<std::string>>::iterator itr;
//
//	//std::map<std::string, std::set<std::string>> fl_rl_pair_map;
//
//	for (int i = 0; i < streams.size(); i++)
//	{
//		std::set<std::string> freqFolders;
//		if (streams.at(i).getFolderFL().size() >= 1)
//		{
//			std::set<std::string> setDifference;
//			std::set<std::string> intersect;
//
//			if (i == 2179)
//			{
//				std::cout << "hello" << std::endl;
//			}
//			std::set<std::string> setFreqFolders = streams.at(i).getFolderFL();
//			for (auto it = setFreqFolders.begin(); it != setFreqFolders.end(); ++it)
//			{
//				freqFolders.insert(*it);
//			}
//			//freqFolders.clear();
//
//			if (pairs.size() > 0)
//			{
//				/*if (std::find(pairs.begin(), pairs.end(), freqFolders) == pairs.end())
//				{*/
//				for (itr = pairs.begin(); itr != pairs.end(); ++itr)
//				{
//
//					//first find if there is any intersection and then find the difference in the both sets ->vector set and setFreqFolders
//
//					//check if there are any common freq in the vector(set) of pairs 
//					//and the set of freq.
//					set_intersection(itr[0].begin(), itr[0].end(), freqFolders.begin(), freqFolders.end(),
//						std::inserter(intersect, intersect.begin()));
//
//					//to check if there is any common freq and 
//					if (intersect.size() > 0)
//					{
//						//set_difference inserts the uncommon freq from the first set in the result set
//						if (freqFolders.size() > itr[0].size())
//						{
//							std::set_difference(freqFolders.begin(), freqFolders.end(), itr[0].begin(), itr[0].end(),
//								std::inserter(setDifference, setDifference.begin()));
//							difference = true;
//						}
//						else if (freqFolders.size() < itr[0].size())
//						{
//							std::set_difference(itr[0].begin(), itr[0].end(), freqFolders.begin(), freqFolders.end(),
//								std::inserter(setDifference, setDifference.begin()));
//							difference = true;
//						}
//						else
//						{
//							continue;
//						}
//					}
//					else
//					{
//						pairs.push_back(freqFolders);
//					}
//
//
//					/*if(itr[0].find(freqFolders) != itr[0].end() )
//					{
//
//					}*/
//					/*if (std::find(itr[0].begin(), itr[0].end(), freqFolders) == itr[0].end())
//					{*/
//
//
//
//
//				}
//
//				if (difference == true)
//				{
//					//pairs.erase(itr);
//					intersect.insert(setDifference.begin(), setDifference.end());
//					pairs.push_back(intersect);
//					difference = false;
//				}
//
//			}
//			else
//			{
//				pairs.push_back(freqFolders);
//			}
//		}
//		else
//		{
//			continue;
//		}
//	}//for loop ends here
//}

std::string Evolution_SCPC::printToJSON()
{
	j_root["type"] = "evolution_result";
	return getJSON_string_from_jsonC(j_root);
}
