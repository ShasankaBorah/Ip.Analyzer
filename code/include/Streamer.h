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

class stream
{
private:
	std::string srcIP,dstIP;
	int cntAtoB,cntBtoA;		    //count of A(source) to B(destination) and B(source) to A(destination) 		
	int protocolNumAtoB;
	int protocolNumBtoA;
	string fileName;
	std::map<int,int> AtoBprotocol;
	std::map<int,int> BtoAprotocol;
	std::set<std::string> folders_FL;
	std::set<std::string> folders_RL;
	std::set<boost::filesystem::path> pcap_files_FL; //set for Unique FL Files
	std::set<boost::filesystem::path> pcap_files_RL; //set for Unique RL Files
	std::set<string>::iterator itSet;
	//std::map<int, int> protocol_map;

public:
	//default constructor
	stream();
	//overloaded constructor
	stream(std::string, std::string);
	~stream(void);
	void incrementAtoB();
	void incrementBtoA();
	string getsrcIP();
	string getdstIP();
	int getCountAtoB();
	int getCountBtoA();
	void protoCountAtoB(int);
	void protoCountBtoA(int);
	jsonnlohmann getData();
	std::string protocolAnalysis(int); //protocol number to name function
    void add_folder_FL(string str);
	void add_folder_RL(string str);
    void add_pcap_file_FL(string str);
    void add_pcap_file_RL(string str);
	int equals(const stream &that) const;
};

