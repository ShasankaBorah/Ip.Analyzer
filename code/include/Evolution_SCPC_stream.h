#pragma once
#include "stdafx.h"
#include "boost/filesystem.hpp"
#include <boost/property_tree/ptree.hpp>
#include <iostream>
#include <conio.h>
#include <string.h>
#include <pcap.h>
#include <conio.h>
#include <map>
#include <set>
#include "json.hpp"

using jsonnlohmann = nlohmann::json;
using namespace std;
namespace ptree = boost::property_tree;

class Evolution_SCPC_stream
{
private:
private:
	std::string								srcIP, dstIP;
	map<std::string, uint64_t>				AtoBmap;
	map<std::string, uint64_t>				BtoAmap;
	uint64_t								count = 1;



public:
	Evolution_SCPC_stream();
	Evolution_SCPC_stream(std::string, std::string);
	~Evolution_SCPC_stream();
	void								incrementAtoB();
	void								incrementBtoA();
	string								getsrcIP();
	string								getdstIP();
	int									getCountAtoB();
	int									getCountBtoA();
	void								protoCountAtoB(int);
	void								protoCountBtoA(int);
	jsonnlohmann						getData(); /*this function creates json object and returns the object containing the detials of each packet stream*/
	std::string							protocolAnalysis(int); //protocol number to name function
	void								add_folder_FL(string str);
	void								add_folder_RL(string str);
	void								add_pcap_file_FL(string str);
	void								add_pcap_file_RL(string str);
	int									equals(const Evolution_SCPC_stream &that) const;
	std::set<std::string>				getFolderFL();

	void								addAtoBmap(std::string folderName);
	void								addBtoAmap(std::string folderName);
};

