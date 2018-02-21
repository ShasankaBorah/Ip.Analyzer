#include "Protocol_analyzer.h"
#include "sizeCalculate.h"
#include "stdafx.h"
#include "boost/filesystem.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <iostream>
#include <conio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
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


Protocol_analyzer::Protocol_analyzer()
{
}


Protocol_analyzer::~Protocol_analyzer()
{
}

void Protocol_analyzer::initialize()
{
	num_files_read = 0;
	fl_files_.clear();
	rl_files_.clear();
	j_protocol_stream.clear();
	port_no_tcp.clear();
	port_no_tcp.clear();
	totalSecondsElapsed = 0;
}

int32_t Protocol_analyzer::start_analysis()
{
	std::vector<std::pair<string, string>> FilesVector;
	jsonnlohmann j_root = jsonnlohmann::object();
	j_root["fl_folder_name"] = config.get_fl_path();

	/* Analyse FL Path*/
	if (!config.get_fl_path().empty())
	{
		for (directory_iterator itr(config.get_fl_path()); itr != directory_iterator(); ++itr) /*top folder*/
		{
			if (boost::filesystem::is_directory(itr->path()))
			{
				if (std::find(config.fl_folders.begin(), config.fl_folders.end(), itr->path().filename().string()) != config.fl_folders.end())
				{
					jsonnlohmann file_info_fl = {};
					file_info_fl["freq_folder_name"] = itr->path().filename().string();/*new*/
					//std::string name = itr->path().filename().string();
					std::vector<std::string> pcapFiles;
					for (directory_iterator itr2(itr->path()); itr2 != directory_iterator(); ++itr2) /*inner folder*/
					{
						if (itr2->path().filename().extension() == ".pcap")
						{


							pcapFiles.push_back(itr2->path().string());
							/************************for individual pcap file*********************************************************/
							//
							//cout << "Reading File : " << itr2->path().filename().string() << std::endl;
							//
							//jsonnlohmann files = {};					
							//
							//files["file_name"] = itr2->path().filename().string();/*new*/
							//////file_info["file_name"] = itr2->path().filename().string();
							////
							//update_port_infos(itr2->path().string());
							//////file_info["proto_info"] = process(itr2->path().string(), true);
							//
							//files["proto_info"] = process(itr2->path().string(), true);/*new*/
							//
							//file_info_fl["analyzed_files"].push_back(files);/*new*/	
							/*********************************************************************************************************/
						}
					}
					//jsonnlohmann files = {};
					read_file_for_port(pcapFiles);

					file_info_fl["proto_info"] = process(pcapFiles, true);
					pcapFiles.clear();

					j_root["fl_info"].push_back(file_info_fl);
				}
			}
		}
		FilesVector.clear();
	}


	/* Analyse RL Path*/
	j_root["rl_folder_name"] = config.get_rl_path();
	if (!config.get_rl_path().empty())
	{
		for (directory_iterator itr(config.get_rl_path()); itr != directory_iterator(); ++itr) /* top folder*/
		{
			if (boost::filesystem::is_directory(itr->path()))
			{
				if (std::find(config.rl_folders.begin(), config.rl_folders.end(), itr->path().filename().string()) != config.rl_folders.end())
				{
					jsonnlohmann file_info_rl = {};
					file_info_rl["freq_folder_name"] = itr->path().filename().string();/*new*/
					std::vector<std::string> pcapFiles;
					//std::string name = itr->path().filename().string();
					for (directory_iterator itr2(itr->path()); itr2 != directory_iterator(); ++itr2) /* inner folder*/
					{
						if (itr2->path().filename().extension() == ".pcap")
						{
							pcapFiles.push_back(itr2->path().string());

							/*****************************************************************************/

							//cout << "Reading File : " << itr2->path().filename().string() << std::endl;
							//jsonnlohmann files = {};
							//files["file_name"] = itr2->path().filename().string();/*new*/
							//update_port_infos(itr2->path().string());
							////files["proto_info"] = process(itr2->path().string(), false);/*new*/

							//file_info_rl["analyzed_files"].push_back(files);/*new*
							/*file_info["file_name"] = itr2->path().filename().string();
							file_info["proto_info"] = process(itr2->path().string(), false);*/
							/*****************************************************************************/

						}
					}
					read_file_for_port(pcapFiles);

					file_info_rl["proto_info"] = process(pcapFiles, false);
					pcapFiles.clear();
					j_root["rl_info"].push_back(file_info_rl);
				}
			}
		}
		FilesVector.clear();
	}
	/*std::ofstream ofs("test.json");
	ofs << j_root;*/
	store_database(j_root);

	return 0;
}

jsonnlohmann Protocol_analyzer::process(/*std::string filename*/std::vector<std::string> pcaps, bool is_fl)
{
	float									seconds;
	clock_t									t1, t2;
	ip_header*								ip_hdr;
	ether_header*							eth_hdr;
	tcp_header*								tcp_hdr;

	jsonnlohmann							j_json_progress;
	jsonnlohmann							prot_port_info = jsonnlohmann::object();
	jsonnlohmann							protocols = jsonnlohmann::object();


	for (int i = 0; i < pcaps.size(); i++)
	{
		if (is_fl)
		{
			fl_files_.push_back(pcaps[i]);
		}
		else
		{
			rl_files_.push_back(pcaps[i]);
		}
		std::ifstream in(pcaps[i], std::ifstream::ate | std::ifstream::binary);
		int fileSize = in.tellg();
		in.close();

		Descriptor = pcap_open_offline(pcaps[i].c_str(), errbuff); /*handle to offline file*/
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

			if (perc > double(next_perc))/*percentage if starts*/
			{
				t2 = clock();
				float diff((float)t2 - (float)t1);
				seconds = diff / CLOCKS_PER_SEC;

				std::cout << (uint64_t)bytesRead << "/" << fileSize << " ( " << perc << " %) " << std::endl;
				j_json_progress["type"] = "progress";
				j_json_progress["filename"] = pcaps[i];
				j_json_progress["bytesRead"] = bytesRead;
				j_json_progress["fileSize"] = fileSize;
				j_json_progress["seconds"] = seconds;

				send_analysis_message_GUI(getJSON_string_from_jsonC(j_json_progress));
				j_json_progress.clear();

				next_perc += 5;
			}/*percentage if ends*/

			eth_hdr = (ether_header*)(data);
			if (0x0008 == eth_hdr->type)/*if ip packet*/
			{
				ip_hdr = (ip_header*)(data + 14);
				string prot_no = std::to_string(ip_hdr->ip_protocol); /*protocol number*/

				if (protocols.find(prot_no) == protocols.end())/*if not found*/
				{
					protocols[prot_no]["count"] = 1;
					switch (ip_hdr->ip_protocol)
					{
					case 1:
						protocols[prot_no]["name"] = "ICMP";
						break;
					case 2:
						protocols[prot_no]["name"] = "IGMP";
						break;
					case 3:
						protocols[prot_no]["name"] = "GGP";
						break;
					case 4:
						protocols[prot_no]["name"] = "IP-in-IP";
						break;
					case 6:
						protocols[prot_no]["name"] = "TCP";
						protocols[prot_no]["protocols"].push_back(port_no_tcp);
						port_no_tcp.clear();
						break;
					case 8:
						protocols[prot_no]["name"] = "EGP";
						break;
					case 12:
						protocols[prot_no]["name"] = "PUP";
						break;
					case 17:
						protocols[prot_no]["name"] = "UDP";
						protocols[prot_no]["protocols"].push_back(port_no_udp);
						port_no_udp.clear();
						break;
					case 18:
						protocols[prot_no]["name"] = "MUX";
						break;
					case 28:
						protocols[prot_no]["name"] = "IRTP";
						break;
					case 30:
						protocols[prot_no]["name"] = "NETBLT";
						break;
					case 41:
						protocols[prot_no]["name"] = "IPv6";
						break;
					case 42:
						protocols[prot_no]["name"] = "SDRP";
						break;
					case 50:
						protocols[prot_no]["name"] = "ESP";
						break;
					case 56:
						protocols[prot_no]["name"] = "TLSP";
						break;
					case 64:
						protocols[prot_no]["name"] = "SAT-EXPAK";
						break;
					case 69:
						protocols[prot_no]["name"] = "SAT-MON";
						break;
					case 75:
						protocols[prot_no]["name"] = "PVP";
						break;
					case 80:
						protocols[prot_no]["name"] = "ISO-IP";
						break;
					case 86:
						protocols[prot_no]["name"] = "DGP";
						break;
					case 89:
						protocols[prot_no]["name"] = "OSPF";
						break;
					case 96:
						protocols[prot_no]["name"] = "SSC-SP";
						break;
					case 97:
						protocols[prot_no]["name"] = "ETHERIP";
						break;
					case 98:
						protocols[prot_no]["name"] = "ENCAP";
						break;
					case 100:
						protocols[prot_no]["name"] = "GMTP";
						break;
					case 109:
						protocols[prot_no]["name"] = "SNP";
						break;
					case 115:
						protocols[prot_no]["name"] = "L2TP";
						break;
					case 117:
						protocols[prot_no]["name"] = "IATP";
						break;
					case 118:
						protocols[prot_no]["name"] = "STP";
						break;
					case 131:
						protocols[prot_no]["name"] = "PIPE";
						break;
					case 132:
						protocols[prot_no]["name"] = "SCTP";
						break;

					default: /*add other protocols as needed*/
						break;
					}
				}
				else
				{
					protocols[prot_no]["count"] = protocols[prot_no]["count"].get<uint64_t>() + 1;
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
		totalSecondsElapsed = totalSecondsElapsed + seconds;

		j_json_progress["type"] = "progress";
		//j_json_progress["filename"] = filename;
		j_json_progress["bytesRead"] = bytesRead;
		j_json_progress["fileSize"] = fileSize;
		j_json_progress["seconds"] = seconds;
		j_json_progress["total_time"] = totalSecondsElapsed;

		send_analysis_message_GUI(getJSON_string_from_jsonC(j_json_progress));
		num_files_read++;

		/*****to store the name of the file and the size***/
		std::size_t found = pcaps[i].find_last_of("\\");
		std::string pcapFile = pcaps[i].substr(found + 1);
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
	}

	//std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	//int fileSize = in.tellg();
	//in.close();

	//Descriptor = pcap_open_offline(filename.c_str(), errbuff); /*handle to offline file*/
	//double bytesRead = 0;

	//double perc;/*shows the percentage*/
	//int next_perc = 0;
	//double remain;
	//std::cout << std::endl;
	//t1 = clock();
	//while (true) /*while loop*/
	//{
	//	int returnValue = pcap_next_ex(Descriptor, &header, &data);

	//	if (1 != returnValue)
	//	{
	//		break;
	//	}

	//	bytesRead += header->len;
	//	perc = (bytesRead / fileSize) * 100;

	//	if (perc > double(next_perc))/*percentage if starts*/
	//	{
	//		t2 = clock();
	//		float diff((float)t2 - (float)t1);
	//		seconds = diff / CLOCKS_PER_SEC;

	//		std::cout << (uint64_t)bytesRead << "/" << fileSize << " ( " << perc << " %) " << std::endl;
	//		j_json_progress["type"] = "progress";
	//		j_json_progress["filename"] = filename;
	//		j_json_progress["bytesRead"] = bytesRead;
	//		j_json_progress["fileSize"] = fileSize;
	//		j_json_progress["seconds"] = seconds;

	//		send_analysis_message_GUI(getJSON_string_from_jsonC(j_json_progress));
	//		j_json_progress.clear();

	//		next_perc += 5;
	//	}/*percentage if ends*/

	//	eth_hdr = (ether_header*)(data);
	//	if (0x0008 == eth_hdr->type)/*if ip packet*/
	//	{
	//		ip_hdr = (ip_header*)(data + 14);
	//		string prot_no = std::to_string(ip_hdr->ip_protocol); /*protocol number*/

	//		if (protocols.find(prot_no) == protocols.end())/*if not found*/
	//		{
	//			protocols[prot_no]["count"] = 1;
	//			switch (ip_hdr->ip_protocol)
	//			{
	//			case 1:
	//				protocols[prot_no]["name"] = "ICMP";
	//				break;
	//			case 2:
	//				protocols[prot_no]["name"] = "IGMP";
	//				break;
	//			case 3:
	//				protocols[prot_no]["name"] = "GGP";
	//				break;
	//			case 4:
	//				protocols[prot_no]["name"] = "IP-in-IP";
	//				break;
	//			case 6:
	//				protocols[prot_no]["name"] = "TCP";
	//				protocols[prot_no]["protocols"].push_back(port_no_tcp);
	//				port_no_tcp.clear();
	//				break;
	//			case 8:
	//				protocols[prot_no]["name"] = "EGP";
	//				break;
	//			case 12:
	//				protocols[prot_no]["name"] = "PUP";
	//				break;
	//			case 17:
	//				protocols[prot_no]["name"] = "UDP";
	//				protocols[prot_no]["protocols"].push_back(port_no_udp);
	//				port_no_udp.clear();
	//				break;
	//			case 18:
	//				protocols[prot_no]["name"] = "MUX";
	//				break;
	//			case 28:
	//				protocols[prot_no]["name"] = "IRTP";
	//				break;
	//			case 30:
	//				protocols[prot_no]["name"] = "NETBLT";
	//				break;
	//			case 41:
	//				protocols[prot_no]["name"] = "IPv6";
	//				break;
	//			case 42:
	//				protocols[prot_no]["name"] = "SDRP";
	//				break;
	//			case 50:
	//				protocols[prot_no]["name"] = "ESP";
	//				break;
	//			case 56:
	//				protocols[prot_no]["name"] = "TLSP";
	//				break;
	//			case 64:
	//				protocols[prot_no]["name"] = "SAT-EXPAK";
	//				break;
	//			case 69:
	//				protocols[prot_no]["name"] = "SAT-MON";
	//				break;
	//			case 75:
	//				protocols[prot_no]["name"] = "PVP";
	//				break;
	//			case 80:
	//				protocols[prot_no]["name"] = "ISO-IP";
	//				break;
	//			case 86:
	//				protocols[prot_no]["name"] = "DGP";
	//				break;
	//			case 89:
	//				protocols[prot_no]["name"] = "OSPF";
	//				break;
	//			case 96:
	//				protocols[prot_no]["name"] = "SSC-SP";
	//				break;
	//			case 97:
	//				protocols[prot_no]["name"] = "ETHERIP";
	//				break;
	//			case 98:
	//				protocols[prot_no]["name"] = "ENCAP";
	//				break;
	//			case 100:
	//				protocols[prot_no]["name"] = "GMTP";
	//				break;
	//			case 109:
	//				protocols[prot_no]["name"] = "SNP";
	//				break;
	//			case 115:
	//				protocols[prot_no]["name"] = "L2TP";
	//				break;
	//			case 117:
	//				protocols[prot_no]["name"] = "IATP";
	//				break;
	//			case 118:
	//				protocols[prot_no]["name"] = "STP";
	//				break;
	//			case 131:
	//				protocols[prot_no]["name"] = "PIPE";
	//				break;
	//			case 132:
	//				protocols[prot_no]["name"] = "SCTP";
	//				break;

	//			default: /*add other protocols as needed*/
	//				break;
	//			}
	//		}
	//		else
	//		{
	//			protocols[prot_no]["count"] = protocols[prot_no]["count"].get<uint64_t>() + 1;
	//		}
	//	}
	//}/*while loop ends*/
	/*remain = fileSize - bytesRead;
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
	num_files_read++;*/

	return protocols;
}

void Protocol_analyzer::store_database(jsonnlohmann data)
{
	time_t rawtime;
	struct tm* timeinfo;
	char buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%Y-%m-%d-%I-%M-%S", timeinfo);
	std::string str(buffer);

	str += "_protocol.json";

	std::ofstream ofs(str);
	std::ofstream dbofs("protocol_database.json", std::ios::app);

	j_protocol_stream.clear();

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

		j_protocol_stream["analysis_info"].push_back(j_analysis_info);
		j_protocol_stream["protocol_info"] = data;
		ofs << j_protocol_stream;
		ofs.close();
		dbofs << str << std::endl;
		dbofs.close();
	}
	else
	{
		std::cout << "the output file could not be opened." << std::endl;
	}
}

std::string Protocol_analyzer::printToJson()
{
	j_protocol_stream["type"] = "protocol_result";

	return getJSON_string_from_jsonC(j_protocol_stream);
}

void Protocol_analyzer::update_port_info(uint16_t src_port, bool cp_dp)
{
	jsonnlohmann port_no = jsonnlohmann::object();
	if (cp_dp)
	{
		port_no = port_no_tcp;
	}
	else
	{
		port_no = port_no_udp;
	}

	string s_port = std::to_string(src_port);

	if (src_port >= 1 && src_port <= 1023)
	{
		if (port_no.find(s_port) == port_no.end())/*if not found*/
		{
			port_no[s_port]["count"] = 1;

			switch (src_port)
			{
			case 1:
				port_no[s_port]["name"] = "TCPMUX";
				break;
			case 5:
				port_no[s_port]["name"] = "RJE";
				break;
			case 7:
				port_no[s_port]["name"] = "ECHO";
				break;
			case 11:
				port_no[s_port]["name"] = "Active users";
				break;
			case 13:
				port_no[s_port]["name"] = "Daytime Protocol";
				break;
			case 15:
				port_no[s_port]["name"] = "Previously netstat service";
				break;
			case 17:
				port_no[s_port]["name"] = "Quote of the Day";
				break;
			case 18:
				port_no[s_port]["name"] = "MSP";
				break;
			case 19:
				port_no[s_port]["name"] = "Character Generator Protocol";
				break;
			case 20:
				port_no[s_port]["name"] = "FTP-DATA";/*only tcp*/
				break;
			case 21:
				port_no[s_port]["name"] = "FTP-CONTROL";/*only tcp*/
				break;
			case 22:
				port_no[s_port]["name"] = "SSH Remote Login Protocol";
				break;
			case 23:
				port_no[s_port]["name"] = "Telnet";
				break;
			case 25:
				port_no[s_port]["name"] = "SMTP";
				break;
			case 29:
				port_no[s_port]["name"] = "MSG ICP";
				break;
			case 37:
				port_no[s_port]["name"] = "Time";
				break;
			case 38:
				port_no[s_port]["name"] = "Route Access Protocol";
				break;
			case 39:
				port_no[s_port]["name"] = "Resource Location Protocol";
				break;
			case 42:
				port_no[s_port]["name"] = "Host Name Server (Nameserv)";
				break;
			case 43:
				port_no[s_port]["name"] = "WhoIs";
				break;
			case 49:
				port_no[s_port]["name"] = "Login Host Protocol";
				break;
			case 50:
				port_no[s_port]["name"] = "Remote Mail Checking Protocol";
				break;
			case 52:
				port_no[s_port]["name"] = "XNS Time Protocol";
				break;
			case 53:
				port_no[s_port]["name"] = "DNS";
				break;
			case 67:
				port_no[s_port]["name"] = "Bootstrap Protocol (BOOTP) server";/*only udp*/
				break;
			case 68:
				port_no[s_port]["name"] = "Bootstrap Protocol (BOOTP) client";/*only udp*/
				break;
			case 69:
				port_no[s_port]["name"] = "TFTP";/*only udp tcp assigned*/
				break;
			case 70:
				port_no[s_port]["name"] = "Gopher Services";
				break;
			case 79:
				port_no[s_port]["name"] = "	Finger";
				break;
			case 80:
				port_no[s_port]["name"] = "HTTP";
				break;
			case 82:
				port_no[s_port]["name"] = "TorPark Control";
				break;
			case 88:
				port_no[s_port]["name"] = "Kerberos authentication system";
				break;
			case 90:
				port_no[s_port]["name"] = "PointCast";
				break;
			case 101:
				port_no[s_port]["name"] = "NIC Host Name";
				break;
			case 102:
				port_no[s_port]["name"] = " (TSAP) Class 0 protocol;";
				break;
			case 103:
				port_no[s_port]["name"] = "	X.400 Standard";
				break;
			case 105:
				port_no[s_port]["name"] = "CCSO Nameserver";
				break;
			case 107:
				port_no[s_port]["name"] = "RTelnet";
				break;
			case 108:
				port_no[s_port]["name"] = "SNA Gateway Access Server";
				break;
			case 109:
				port_no[s_port]["name"] = "POP2";
				break;
			case 110:
				port_no[s_port]["name"] = "POP3";
				break;
			case 115:
				port_no[s_port]["name"] = "SFTP";
				break;
			case 118:
				port_no[s_port]["name"] = "SQL Services";
				break;
			case 119:
				port_no[s_port]["name"] = "NNTP";/*tcp only*/
				break;
			case 135:
				port_no[s_port]["name"] = "DCE endpoint resolution or Microsoft EPMAP ";
				break;
			case 139:
				port_no[s_port]["name"] = "NetBIOS Datagram Service";
				break;
			case 143:
				port_no[s_port]["name"] = "IMAP";
				break;
			case 150:
				port_no[s_port]["name"] = "NetBIOS Session Service";
				break;
			case 156:
				port_no[s_port]["name"] = "SQL Server";
				break;
			case 161:
				port_no[s_port]["name"] = "SNMP";
				break;
			case 179:
				port_no[s_port]["name"] = "BGP";
				break;
			case 190:
				port_no[s_port]["name"] = "GACP";
				break;
			case 194:
				port_no[s_port]["name"] = "IRC";
				break;
			case 197:
				port_no[s_port]["name"] = "DLS";
				break;
			case 319:
				port_no[s_port]["name"] = "Precision Time Protocol (PTP) event messages";
				break;
			case 320:
				port_no[s_port]["name"] = "Precision Time Protocol (PTP) general messages";
				break;
			case 389:
				port_no[s_port]["name"] = "LDAP";
				break;
			case 396:
				port_no[s_port]["name"] = "Novell Netware over IP";
				break;
			case 443:
				port_no[s_port]["name"] = "HTTPS";
				break;
			case 444:
				port_no[s_port]["name"] = "SNPP";
				break;
			case 445:
				port_no[s_port]["name"] = "Microsoft-DS";
				break;
			case 458:
				port_no[s_port]["name"] = "Apple QuickTime";
				break;
			case 464:
				port_no[s_port]["name"] = "Kerberos Change/Set password";
				break;
			case 517:
				port_no[s_port]["name"] = "Talk";
				break;
			case 518:
				port_no[s_port]["name"] = "NTalk";
				break;
			case 521:
				port_no[s_port]["name"] = "Routing Information Protocol Next Generation (RIPng)";
				break;
			case 546:
				port_no[s_port]["name"] = "DHCP Client";
				break;
			case 547:
				port_no[s_port]["name"] = "DHCP Server";
				break;
			case 563:
				port_no[s_port]["name"] = "SNEWS";
				break;
			case 569:
				port_no[s_port]["name"] = "MSN";
				break;
			case 698:
				port_no[s_port]["name"] = "Optimized Link State Routing (OLSR)";
				break;
			case 1080:
				port_no[s_port]["name"] = "Socks";
				break;
			default:
				break;
			}/*switch ends*/
		}/*if not found ends here*/
		else
		{
			port_no[s_port]["count"] = port_no[s_port]["count"].get<uint64_t>() + 1;
		}
	}
	else
	{
		port_no["more_than_1023"]["count"] = port_no["more_than_1023"]["count"].get<uint64_t>() + 1;
	}

	if (cp_dp)
	{
		port_no_tcp = port_no;
	}
	else
	{
		port_no_udp = port_no;
	}
	port_no.clear();
}


//void Protocol_analyzer::update_port_infos(std::string file_name)
//{
//	ether_header* th_hdr;
//	tcp_header* cp_hdr;
//	udp_header* dp_hdr;
//	ip_header* p_hdr;
//	struct pcap_pkthdr* eader;	/*packet header*/
//	const u_char* ata;			/*packet data*/
//	pcap_t* escriptor;
//
//	escriptor = pcap_open_offline(file_name.c_str(), errbuff);/*descriptor*/
//	port_no_tcp["more_than_1023"]["count"] = 0;
//	port_no_udp["more_than_1023"]["count"] = 0;
//
//	while (true) /*while loop*/
//	{
//		int returValue = pcap_next_ex(escriptor, &eader, &ata);
//
//		if (1 != returValue)
//		{
//			break;
//		}
//
//		th_hdr = (ether_header*)(ata);
//		if (0x0008 == th_hdr->type)/*if ip packet*/
//		{
//			p_hdr = (ip_header*)(ata + 14);
//			if (6 == p_hdr->ip_protocol)
//			{
//				cp_hdr = (tcp_header*)(ata + 14 + (p_hdr->ip_header_len * 4));/*tcp header*/
//				update_port_info(ntohs(cp_hdr->th_sport), true);
//			}
//			else if (17 == p_hdr->ip_protocol)
//			{
//				dp_hdr = (udp_header*)(ata + 14 + (p_hdr->ip_header_len * 4));/*udp header*/
//				update_port_info(ntohs(dp_hdr->sport), false);
//			}
//		}
//	}
//}

void Protocol_analyzer::read_file_for_port(std::vector<std::string> files)
{
	ether_header*							th_hdr;
	tcp_header*								cp_hdr;
	udp_header*								dp_hdr;
	ip_header*								p_hdr;
	struct pcap_pkthdr*						eader;	/*packet header*/
	const u_char*							ata;			/*packet data*/
	pcap_t*									escriptor;
	jsonnlohmann							j_read_port_progress;

	port_no_tcp["more_than_1023"]["count"] = 0;
	port_no_udp["more_than_1023"]["count"] = 0;

	for (int i = 0; i < files.size(); i++)
	{
		j_read_port_progress["type"]				= "read_port_progress";
		j_read_port_progress["filename"]			= files[i];
		j_read_port_progress["wait"]				= "Please Wait";
		send_analysis_message_GUI(getJSON_string_from_jsonC(j_read_port_progress));

		escriptor = pcap_open_offline(files[i].c_str(), errbuff);

		while (true) /*while loop*/
		{
			int returValue = pcap_next_ex(escriptor, &eader, &ata);

			if (1 != returValue)
			{
				break;
			}

			th_hdr = (ether_header*)(ata);
			if (0x0008 == th_hdr->type)/*if ip packet*/
			{
				p_hdr = (ip_header*)(ata + 14);
				if (6 == p_hdr->ip_protocol)
				{
					cp_hdr = (tcp_header*)(ata + 14 + (p_hdr->ip_header_len * 4));/*tcp header*/
					update_port_info(ntohs(cp_hdr->th_sport), true);
				}
				else if (17 == p_hdr->ip_protocol)
				{
					dp_hdr = (udp_header*)(ata + 14 + (p_hdr->ip_header_len * 4));/*udp header*/
					update_port_info(ntohs(dp_hdr->sport), false);
				}
			}
		}

	}

}

