#include "Evolution_SCPC_stream.h"
#include <utility>
#include <functional>
#include <iostream>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <string>
#include <pcap.h>
#include <vector>
#include <fstream>
#include <set>
#include "json.hpp"

using json = nlohmann::json;
using namespace std;

namespace ptree = boost::property_tree;



Evolution_SCPC_stream::Evolution_SCPC_stream()
{
}


Evolution_SCPC_stream::~Evolution_SCPC_stream()
{
}

Evolution_SCPC_stream::Evolution_SCPC_stream(std::string A, std::string B)
{
	srcIP = A;
	dstIP = B;
	/*cntAtoB = 0;
	cntBtoA = 0;*/
}

//void Evolution_SCPC_stream::incrementAtoB()
//{
//	cntAtoB++;
//}

//void Evolution_SCPC_stream::incrementBtoA()
//{
//	cntBtoA++;
//}

string Evolution_SCPC_stream::getsrcIP() {
	return srcIP;
}

string Evolution_SCPC_stream::getdstIP() {
	return dstIP;
}

//int Evolution_SCPC_stream::getCountAtoB() {
//	return cntAtoB;
//}
//
//int Evolution_SCPC_stream::getCountBtoA() {
//	return cntBtoA;
//}
//
//void Evolution_SCPC_stream::add_folder_FL(string str) {
//	folders_FL.insert(str);
//}
//
//void Evolution_SCPC_stream::add_folder_RL(string str) {
//	folders_RL.insert(str);
//}

//void Evolution_SCPC_stream::add_pcap_file_FL(string str) {
//	pcap_files_FL.insert(str);
//}
//
//void Evolution_SCPC_stream::add_pcap_file_RL(string str) {
//	pcap_files_RL.insert(str);
//}

int Evolution_SCPC_stream::equals(const Evolution_SCPC_stream &that)  const
{
	if ((strcmp(srcIP.c_str(), that.srcIP.c_str()) == 0) && (strcmp(dstIP.c_str(), that.dstIP.c_str()) == 0))/* A to B */
		return 0;
	if ((strcmp(srcIP.c_str(), that.dstIP.c_str()) == 0) && (strcmp(dstIP.c_str(), that.srcIP.c_str()) == 0))/*B to A*/
		return 1;
	else
		return 2;
}

/*to count number of packets from A to B*/
//void Evolution_SCPC_stream::protoCountAtoB(int AtoBProt) {
//	std::map<int, int>::iterator itAtoB = AtoBprotocol.find(AtoBProt);
//	if (itAtoB != AtoBprotocol.end()) {		//checking protocol
//		itAtoB->second++;
//	}
//	else
//		AtoBprotocol[AtoBProt] = 1;
//}
//
//void Evolution_SCPC_stream::protoCountBtoA(int BtoAProt) {
//	std::map<int, int>::iterator itBtoA = BtoAprotocol.find(BtoAProt);
//	if (itBtoA != BtoAprotocol.end())		 //checking protocol
//		itBtoA->second++;
//	else
//		BtoAprotocol[BtoAProt] = 1;
//}


json Evolution_SCPC_stream::getData()
{
	json root = json::object();
	json j_json;

	root["SrcIp"] = getsrcIP();
	root["DstIp"] = getdstIP();
	/*root["PacketCount_AB"] = getCountAtoB();
	root["PacketCount_BA"] = getCountBtoA();*/

	for (auto itAB = AtoBmap.begin(); itAB != AtoBmap.end(); ++itAB)
	{
		std::string freqFolder = itAB->first;
		//int protNumAB = itAB->first;
		//j_json["protocolType"] = protocolAnalysis(protNumAB);
		j_json["Freq_Folder"] = freqFolder;
		j_json["Count"] = itAB->second;
		root["AtoB"].push_back(j_json);
		j_json.clear();
	}

	for (auto itBA = BtoAmap.begin(); itBA != BtoAmap.end(); ++itBA)
	{
		std::string freqFolder = itBA->first;
		/*int protNumBA = itBA->first;
		j_json["protocolType"] = protocolAnalysis(protNumBA);*/
		j_json["Freq_Folder"] = freqFolder;
		j_json["Count"] = itBA->second;
		root["BtoA"].push_back(j_json);
		j_json.clear();
	}


	//string str; // files without quote 

	//			//FL folders
	//for (auto it = folders_FL.begin(); it != folders_FL.end(); ++it) {
	//	str = *it;
	//	if (str.front() == '"') {
	//		str.erase(0, 1);  //algo to remove quote
	//		str.erase(str.size() - 1);
	//	}
	//	root["folders_AB"].push_back(str);
	//	str.clear();
	//}

	//for (auto it = pcap_files_FL.begin(); it != pcap_files_FL.end(); ++it) {
	//	str = it->filename().string();
	//	if (str.front() == '"') {
	//		str.erase(0, 1);  //algo to remove quote
	//		str.erase(str.size() - 1);
	//	}
	//	root["files_AB"].push_back(str);
	//	str.clear();
	//}

	return root;

}

//std::string Evolution_SCPC_stream::protocolAnalysis(int protocolNumber) {
//	//int ProtocolNumber;
//	std::string protocolName;
//	switch (protocolNumber) {
//	case 1:
//		protocolName = "ICMP";
//		break;
//	case 2:
//		protocolName = "IGMP";
//		break;
//	case 6:
//		protocolName = "TCP";
//		break;
//	case 17:
//		protocolName = "UDP";
//		break;
//	case 41:
//		protocolName = "IPv6";
//		break;
//	case 50:
//		protocolName = "ESP";
//		break;
//	case 97:
//		protocolName = "ETHERIP";
//		break;
//	default:
//		break;
//	}
//	return protocolName;
//
//}

//std::set<std::string> Evolution_SCPC_stream::getFolderFL()
//{
//	return folders_FL;
//}

void Evolution_SCPC_stream::addAtoBmap(std::string folderName)
{
	if(AtoBmap.find(folderName) != AtoBmap.end())
	{
		AtoBmap[folderName]++;
	}
	else
	{
		AtoBmap[folderName] = count;
	}
	
}


void Evolution_SCPC_stream::addBtoAmap(std::string folderName)
{
	if(BtoAmap.find(folderName) != BtoAmap.end())
	{
		BtoAmap[folderName] = count++;
	}
	else
	{
		BtoAmap[folderName] = count;
	}
}

