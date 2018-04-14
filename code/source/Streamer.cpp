#include "Streamer.h"
#include "Analyzer.h"
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

//default constructor
stream::stream(){}

//default destructor
stream::~stream(void)
{
}

//overloaded constructor
stream::stream(string A,string B)
{
	srcIP = A;
	dstIP = B;
	cntAtoB =0;
	cntBtoA = 0;
}

void stream::incrementAtoB(){ //increament packet count A to B
	cntAtoB++;
}

void stream::incrementBtoA(){ //increment packet count B to A
	cntBtoA++;
}

string stream::getsrcIP(){
	return srcIP;
}

string stream::getdstIP(){
	return dstIP;
}

int stream::getCountAtoB(){ 
	return cntAtoB;
}

int stream::getCountBtoA(){
	return cntBtoA;
}

void stream::add_folder_FL(string str){
	folders_FL.insert(str);
}

void stream::add_folder_RL(string str){
    folders_RL.insert(str);
}

void stream::add_pcap_file_FL(string str) {
    pcap_files_FL.insert(str);
}

void stream::add_pcap_file_RL(string str) {
    pcap_files_RL.insert(str);
}

/*to count number of packets from A to B*/
void stream::protoCountAtoB(int AtoBProt){
	std::map<int,int>::iterator itAtoB = AtoBprotocol.find(AtoBProt);
	if(itAtoB != AtoBprotocol.end()){		//checking protocol
		itAtoB->second++;
	}
	else
		AtoBprotocol[AtoBProt] = 1;   
}


/*to count number of packets from B to A*/
void stream::protoCountBtoA(int BtoAProt){
	std::map<int,int>::iterator itBtoA= BtoAprotocol.find(BtoAProt);
	if(itBtoA != BtoAprotocol.end())		 //checking protocol
		itBtoA->second++;
	else
		BtoAprotocol[BtoAProt] = 1;
}


std::string stream::protocolAnalysis(int protocolNumber){
	//int ProtocolNumber;
	std::string protocolName;
	switch(protocolNumber){
	case 1:
		protocolName = "ICMP";
		break;
	case 2:
		protocolName = "IGMP";
		break;
	case 6:
		protocolName = "TCP";
		break;
	case 17:
		protocolName = "UDP";
		break;
	case 41:
		protocolName = "IPv6";
		break;
	case 50:
		protocolName = "ESP";
		break;
	case 97:
		protocolName = "ETHERIP";
		break;
	default:
		break;
	}
	return protocolName;

}

json stream::getData()
{
	json root = json::object();
	json j_json;

	root["SrcIp"] = getsrcIP();
	root["DstIp"] = getdstIP();
	root["PacketCount_AB"] = getCountAtoB();
	root["PacketCount_BA"] = getCountBtoA();
	
    for (map<int,int>::iterator itAB = AtoBprotocol.begin();itAB != AtoBprotocol.end();++itAB)
	{	
		int protNumAB = itAB->first;
		j_json["protocolType"] = protocolAnalysis(protNumAB);
		j_json["protocolCount"] = itAB->second;
		root["protocols_AB"].push_back(j_json);
		j_json.clear();
	}
 
	for(map<int,int>::iterator itBA = BtoAprotocol.begin(); itBA != BtoAprotocol.end();++itBA)
	{
		int protNumBA = itBA->first;
		j_json["protocolType"] = protocolAnalysis(protNumBA);
		j_json["protocolCount"] = itBA->second;
		root["protocols_BA"].push_back(j_json);
		j_json.clear();
	}
	
	string str; // files without quote 

	//FL folders
	for(auto it = folders_FL.begin(); it != folders_FL.end(); ++it){
        str = *it;
		if(str.front() == '"'){
            str.erase(0,1);  //algo to remove quote
            str.erase(str.size()-1);
		}
		root["folders_AB"].push_back(str);
		str.clear();
	}
	//RL folders
    for (auto it = folders_RL.begin(); it != folders_RL.end(); ++it) {
        str = *it;
        if (str.front() == '"') {
            str.erase(0, 1);  //algo to remove quote
            str.erase(str.size() - 1);
        }
		root["folders_BA"].push_back(str);
		str.clear();
    }

    for (auto it = pcap_files_FL.begin(); it != pcap_files_FL.end(); ++it) {
        str = it->filename().string();
        if (str.front() == '"') {
            str.erase(0, 1);  //algo to remove quote
            str.erase(str.size() - 1);
        }
		root["files_AB"].push_back(str);
		str.clear();
    }

    //RL file Iterator
	for (auto it = pcap_files_RL.begin(); it != pcap_files_RL.end(); ++it) {
		str = it->filename().string();
		if (str.front() == '"') {
			str.erase(0, 1);  //algo to remove quote
			str.erase(str.size() - 1);
		}
		root["files_BA"].push_back(str);
		str.clear();
    }
	return root;
}


/*equal function*/
int stream::equals(const stream &that)  const
{
	if ((strcmp(srcIP.c_str(), that.srcIP.c_str()) == 0) && (strcmp(dstIP.c_str(),that.dstIP.c_str())==0))/* A to B */
		return 0;
	if((strcmp(srcIP.c_str(), that.dstIP.c_str())==0) && (strcmp(dstIP.c_str(),that.srcIP.c_str())==0))/*B to A*/
		return 1;
	else 
		return 2;
}

std::set<std::string> stream::getFolderFL()
{
	return folders_FL;
}

std::set<std::string> stream::getFolderRL()
{
	return folders_RL;
}

