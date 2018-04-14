#include "Streamer.h"
#include "Analyzer.h"
#include "Tcp_Analyzer.h"
#include "Icmp_Analyzer.h"
#include "Dns_Analyzer.h"
#include "Protocol_analyzer.h"
#include "Ip_Address_to_country_mapper.h"
#include "Tcp_Stream_Writer.h"
#include <iostream>
#include <conio.h>
#include <string>
#include <time.h>
#include <fstream>
#include <pcap.h>
#include <boost/filesystem.hpp>
#include "WebServer.h"
#include <boost/algorithm/string.hpp>
#include <conio.h>
#include <stdio.h>
#include "boost/date_time/posix_time/posix_time.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <Configuration.h>
#include "json.hpp"

using namespace std;
using namespace boost::filesystem;
namespace pt = boost::posix_time;
namespace ptree = boost::property_tree;
using jsonnlohmann = nlohmann::json;

WebServer server_instance;
Configuration config;
pcapPackAnalyzer filesToAnalyze;
Icmp_Analyzer icmp_analyze;
Tcp_Analyzer tcp_analyze;
Tcp_Stream_Writer tcp_stream_writer;
Dns_Analyzer dns_analyze;
Protocol_analyzer protocol_analyze;
Ip_Address_to_country_mapper ip_address_resolve;

//ip_addr.get_country(ip);

std::string selected_database;
std::string get_database_data_all(std::string );/*function to load all database files in each analysis section*/
std::string get_database_data_config(); /*to get database in the configuration nav bar*/
std::string load_database_data(std::string selected_database_file);/*function to load selected individual database*/
std::ofstream* pcap_to_json;
std::string load_pcap_folder_list(std::string fl_path, std::string rl_path);
std::string getJSON_string_from_jsonC(jsonnlohmann json);
jsonnlohmann read_database_file(std::string read_file , std::string type); /*to read the dataabse file containing list of individual database*/

ptree::ptree getPtree(std::string str)
{
	std::stringstream ss(str);
	boost::property_tree::ptree pt;
	boost::property_tree::json_parser::read_json(ss, pt);
	return pt;
}

void callback(const std::string& uri, const std::string& str)
{	
	std::cout << uri << ":" << str << std::endl;
	vector<std::string> tokens;
	boost::split(tokens, str, boost::is_any_of("&"));

	if(2 == tokens.size())
	{
		/*start normal pcap analysis*/


		if (tokens.at(0).compare("get_configuration") == 0)
		{
			// send the config
			// get jsonnlohmann format of the config and send it
			server_instance.send_data("/ws/command", config.getJSON());
		}
		else if(tokens.at(0).compare("start_analysis") == 0)
		{
			bool check = false;
			if(tokens.at(1).compare("true") == 0)
			{
				check = true;
			}
			
			filesToAnalyze.initialize(check);
			filesToAnalyze.start_analysis();
			std::string result = filesToAnalyze.printToJSON();
			server_instance.send_data("/ws/command", result);
		}
		else if(tokens.at(0).compare("start_icmp_analysis") == 0)
		{
			bool check = false;
			if (tokens.at(1).compare("true") == 0)
			{
				check = true;
			}
			icmp_analyze.initialize(check);
			icmp_analyze.start_analysis();

			std::string result = icmp_analyze.printToJSON();
			server_instance.send_data("/ws/command", result);
		}
		else if (tokens.at(0).compare("set_configuration") == 0)
		{
			ptree::ptree pt = getPtree(tokens.at(1));
			config.set_fl_path(pt.get<std::string>("fl_path"));
			config.set_rl_path(pt.get<std::string>("rl_path"));

			config.fl_folders.clear();
			BOOST_FOREACH(boost::property_tree::ptree::value_type &v, pt.get_child("fl_folders"))
			{
				config.fl_folders.push_back(v.second.get<std::string>(""));
			}

			config.rl_folders.clear();
			BOOST_FOREACH(boost::property_tree::ptree::value_type &v, pt.get_child("rl_folders"))
			{
				config.rl_folders.push_back(v.second.get<std::string>(""));
			}

			config.write();
			server_instance.send_data("/ws/message", "Configuration Saved.");
		} 

		/**********************************************************************
		 *selecting individual database 
		 **********************************************************************/
		else if(tokens.at(0).compare("load_selected_icmp_db") == 0)/*select individual icmp database*/
		{
			selected_database.clear();
			selected_database.assign(tokens.at(1));
			std::cout << selected_database << " selected to load." << std::endl;
			server_instance.send_data("/ws/message", "Icmp database selected.");
			std::cout << "loading selected icmp database " + selected_database + "...";
			std::string icmp_json_data = load_database_data(selected_database);
			server_instance.send_data("/ws/command", icmp_json_data);
		}
		else if(tokens.at(0).compare("load_selected_pcap_db") == 0)/*select individual pcap database*/
		{
			selected_database.clear();
			selected_database.assign(tokens.at(1));
			std::cout << selected_database<<" selected to load. " << std::endl;
			std::cout << "loading pcap database." << std::endl;
			std::string pcap_json_data = load_database_data(selected_database);
			std::cout << "done." << std::endl;
			server_instance.send_data("/ws/command", pcap_json_data);
			//server_instance.send_data("/ws/message", "PCAP database selected.");
		}
		else if(tokens.at(0).compare("load_selected_tcp_db") == 0)/*select individual tcp database*/
		{
			selected_database.clear();
			selected_database.assign(tokens.at(1));
			std::cout << selected_database << "selected to load." << std::endl;
			server_instance.send_data("/ws/message" , "TCP database selected");
			std::cout << "loading selected tcp database " + selected_database + "...";
			std::string tcp_json_data = load_database_data(selected_database);
			server_instance.send_data("/ws/command", tcp_json_data);
		}
		else if (tokens.at(0).compare("load_selected_dns_db") == 0)/*select individual tcp database*/
		{
			selected_database.clear();
			selected_database.assign(tokens.at(1));
			std::cout << selected_database << "selected to load." << std::endl;
			server_instance.send_data("/ws/message", "DNS database selected");
			std::cout << "loading selected dns database " + selected_database + "...";
			std::string protocol_json_data = load_database_data(selected_database);
			server_instance.send_data("/ws/command", protocol_json_data);
		}	
		else if (tokens.at(0).compare("load_selected_protocol_db") == 0)/*select individual tcp database*/
		{
			selected_database.clear();
			selected_database.assign(tokens.at(1));
			std::cout << selected_database << "selected to load." << std::endl;
			server_instance.send_data("/ws/message", "PROTOCOL database selected");
			std::cout << "loading selected dns database " + selected_database + "...";
			std::string protocol_json_data = load_database_data(selected_database);
			server_instance.send_data("/ws/command", protocol_json_data);
		}
		/**************************************************************************
		 *selecting individual database ends here
		 ***************************************************************************/
	}

	if (tokens.size() == 3)
	{
		if(tokens.at(0).compare("load_pcap_folders") == 0)
		{
			std::string folders = load_pcap_folder_list(tokens.at(1),tokens.at(2));			
			server_instance.send_data("/ws/command", folders);
		}
	}

	/*********************************************
	 *if token is 1 starts here
	 *********************************************/

	if(tokens.size() == 1)
	{		
		if(tokens.at(0).compare("save_pairs_") == 0)
		{
			filesToAnalyze.printPairs();
		}
		/********************************************
		 *to load full database in each analysis nav
		 *********************************************/
		else if(tokens.at(0).compare("get_icmp_database_all") == 0)
		{
			std::cout << "Getting icmp database..." << std::endl;
			std::string load_icmp_database_all_json = get_database_data_all("icmp");
			cout << "Done." << std::endl;
			server_instance.send_data("/ws/command", load_icmp_database_all_json);
		}
		else if(tokens.at(0).compare("get_pcap_database_all")==0)
		{
			std::cout << "Getting pcap database..." << std::endl;
			std::string load_pcap_database_all_json = get_database_data_all("pcap");
			cout << "Done." << std::endl;
			server_instance.send_data("/ws/command" , load_pcap_database_all_json);
		}
		else if (tokens.at(0).compare("get_tcp_database_all") == 0)
		{
			std::cout << "Getting TCP Database..." << std::endl;
			std::string load_tcp_database_list = get_database_data_all("tcp");
			cout << "Done." << std::endl;
			server_instance.send_data("/ws/command", load_tcp_database_list);
		}
		else if(tokens.at(0).compare("get_dns_database_all") == 0)
		{
			std::cout << "Getting dns database...";
			std::string load_dns_database_list = get_database_data_all("dns");
			cout << "Done." << std::endl;
			server_instance.send_data("/ws/command", load_dns_database_list);
		}
		else if (tokens.at(0).compare("get_protocol_database_all") == 0)
		{
			std::cout << "Getting protocol database...";
			std::string load_protocol_database_list = get_database_data_all("protocol");
			cout << "Done." << std::endl;
			server_instance.send_data("/ws/command", load_protocol_database_list);
		}
		/****************************************
		 *to load full database in each analysis
		 * nav ends here
		 ****************************************/

		else if (tokens.at(0).compare("get_database") == 0)
		{
			std::cout << "Getting database...";
			string load_json_data = get_database_data_config();
			std::cout << "done.";
			server_instance.send_data("/ws/command", load_json_data);			
		}

		/*******************************************
		*loading individual selected dataabase file 
		* ends here
		********************************************/
		else if(tokens.at(0).compare("start_tcp_analysis") == 0) /*for tcp analysis*/
		{
			tcp_analyze.initialize();
			tcp_analyze.start_analysis();

			tcp_stream_writer.initialize();
			tcp_stream_writer.start_write_analysis();

			std::string result = tcp_analyze.printToJson();
			server_instance.send_data("/ws/command", result);		
		}
		else if(tokens.at(0).compare("start_dns_analysis") == 0) /*for dns analysis*/
		{
			dns_analyze.initialize();
			dns_analyze.start_analysis();
			std::string result = dns_analyze.printToJson();
			server_instance.send_data("/ws/command", result);		
		}
		else if (tokens.at(0).compare("start_protocol_analysis") == 0) /*for dns analysis*/
		{
			protocol_analyze.initialize();
			protocol_analyze.start_analysis();
			std::string result =protocol_analyze.printToJson();
			server_instance.send_data("/ws/command", result);
		}
	}
	/*********************************************
	*if token is 1 ends here
	*********************************************/
}


void send_analysis_message_GUI(std::string progress_msg)
{
	server_instance.send_data("/ws/progress_message", progress_msg);
}


void send_message_GUI(std::string msg)
{
	server_instance.send_data("/ws/message", msg);
}


std::string getJSON_string_from_jsonC(jsonnlohmann json)
{
	std::string ss;
	ss = json.dump();
	return ss;
}


std::string load_pcap_folder_list(std::string fl_path, std::string rl_path) 
{
	pcap_to_json				= new std::ofstream("pcap_folder_list.txt"); 

	jsonnlohmann j_root					= jsonnlohmann::object();
	vector<boost::filesystem::path> fl_folder_vector;
	vector<boost::filesystem::path> rl_folder_vector;

	if(pcap_to_json->is_open())
	{
		j_root["type"] = "pcap_folders";

		if(!config.get_fl_path().empty())
		{
			for (directory_iterator itr(config.get_fl_path()); itr != directory_iterator(); ++itr) // top folder
			{
				if (boost::filesystem::is_directory(itr->path()))
				{
					fl_folder_vector.push_back(itr->path());
				}
			}

			for (auto fl_path_iterator = fl_folder_vector.begin(); fl_path_iterator != fl_folder_vector.end(); ++fl_path_iterator)
			{
				std::string FLFolders_WQoute = fl_path_iterator->filename().string();
				if (FLFolders_WQoute.front() == '"') {
					FLFolders_WQoute.erase(0, 1);  //algo to remove quote
					FLFolders_WQoute.erase(FLFolders_WQoute.size() - 1);
				}
				j_root["fl_folders"].push_back(FLFolders_WQoute);
			}
		}
		
		if (!config.get_rl_path().empty())
		{
			for (directory_iterator itr(config.get_rl_path()); itr != directory_iterator(); ++itr) // top folder
			{
				if (boost::filesystem::is_directory(itr->path()))
				{
					rl_folder_vector.push_back(itr->path());
				}
			}

			for (auto rl_path_iterator = rl_folder_vector.begin(); rl_path_iterator != rl_folder_vector.end(); ++rl_path_iterator)
			{
				std::string RLFolders_WQoute = rl_path_iterator->filename().string();
				if (RLFolders_WQoute.front() == '"') {
					RLFolders_WQoute.erase(0, 1);  //algo to remove quote
					RLFolders_WQoute.erase(RLFolders_WQoute.size() - 1);
				}
				j_root["rl_folders"].push_back(RLFolders_WQoute);
			}
		}
		
		//for (auto fl_path_iterator = fl_folder_vector.begin(); fl_path_iterator != fl_folder_vector.end(); ++fl_path_iterator)
		//{
		//	std::string FLFolders_WQoute = fl_path_iterator->filename().string();
		//	if (FLFolders_WQoute.front() == '"') {
		//		FLFolders_WQoute.erase(0, 1);  //algo to remove quote
		//		FLFolders_WQoute.erase(FLFolders_WQoute.size() - 1);
		//	}
		//	j_root["fl_folders"].push_back(FLFolders_WQoute);
		//}

		//for (auto rl_path_iterator = rl_folder_vector.begin(); rl_path_iterator != rl_folder_vector.end(); ++rl_path_iterator)
		//{
		//	std::string RLFolders_WQoute = rl_path_iterator->filename().string();
		//	if (RLFolders_WQoute.front() == '"') {
		//		RLFolders_WQoute.erase(0, 1);  //algo to remove quote
		//		RLFolders_WQoute.erase(RLFolders_WQoute.size() - 1);
		//	}
		//	j_root["rl_folders"].push_back(RLFolders_WQoute);
		//}

		//pcap_to_jsonnlohmann << j_root; //for debug
		pcap_to_json->close();
	}
	else
	{
		std::cout << "the output file could not be opened." << std::endl;
		j_root["status"] = "ERROR: Output File Could not be Opened.";
	}
	
	return getJSON_string_from_jsonC(j_root);
}

std::string get_database_data_config() /*to get database in the configuration nav bar*/
{
	jsonnlohmann									j_json = jsonnlohmann::object();
	std::stringstream								JSon;
	string											linesRead;
	vector<string>									string_array;
	std::ifstream									read_icmp_json_file("icmp_database.json");
	std::ifstream									read_pcap_json_file("pcap_database.json");
	std::ifstream									read_tcp_json_file("tcp_database.json");
	std::ifstream									read_protocol_json_file("protocol_database.json");
	std::ifstream									read_dns_json_file("dns_database.json");
	
	
	//data for overall jsonnlohmann data to be generated to send back to gui
	j_json["type"] = "database";

	if (read_pcap_json_file.is_open())
	{	
		std::stringstream strStream;
		strStream << read_pcap_json_file.rdbuf();//read the file
		string str = strStream.str();//str holds the content of the file
		while(std::getline(strStream,linesRead,'\n')){
			string_array.push_back(linesRead);
		}

		//iterator and savor for each jsonnlohmann data
		for (std::vector<string>::iterator it = string_array.begin() ; it != string_array.end(); ++it)
		{ 
			j_json["pcap_data"].push_back(*it);
		}		
		read_pcap_json_file.close();
	}
	else{ 
		cout << "File cannot be read";
	}	

	string_array.clear();

	if (read_icmp_json_file.is_open())
	{
		std::stringstream strStream;
		strStream << read_icmp_json_file.rdbuf();//read the file
		string str = strStream.str();//str holds the content of the file
		while (std::getline(strStream, linesRead, '\n')) {
			string_array.push_back(linesRead);
		}
		//iterator and savor for each jsonnlohmann data
		for (std::vector<string>::iterator it = string_array.begin(); it != string_array.end(); ++it)
		{ //to iterate vector with the string in each vector
			j_json["icmp_data"].push_back(*it);
		}
		read_icmp_json_file.close();
	}
	else {
		cout << "File cannot be read";
	}

	string_array.clear();
	
	if (read_tcp_json_file.is_open())
	{
		std::stringstream strStream;
		strStream << read_tcp_json_file.rdbuf();//read the file
		string str = strStream.str();//str holds the content of the file
		while (std::getline(strStream, linesRead, '\n')) {
			string_array.push_back(linesRead);
		}

		//iterator and savor for each jsonnlohmann data
		for (std::vector<string>::iterator it = string_array.begin(); it != string_array.end(); ++it) { //to iterate vector with the string in each vector																									
			j_json["tcp_data"].push_back(*it);
		}
		read_tcp_json_file.close();
	}
	else {
		cout << "File cannot be read";
	}
	string_array.clear();

	if (read_dns_json_file.is_open())
	{
		std::stringstream strStream;
		strStream << read_dns_json_file.rdbuf();//read the file
		string str = strStream.str();//str holds the content of the file
		while (std::getline(strStream, linesRead, '\n')) {
			string_array.push_back(linesRead);
		}

		//iterator and savor for each jsonnlohmann data
		for (std::vector<string>::iterator it = string_array.begin(); it != string_array.end(); ++it)
		{ //to iterate vector with the string in each vector
			j_json["dns_data"].push_back(*it);
		}
		read_dns_json_file.close();
	}
	else {
		cout << "File cannot be read";
	}
	string_array.clear();

	if (read_protocol_json_file.is_open())
	{
		std::stringstream strStream;
		strStream << read_protocol_json_file.rdbuf();//read the file
		string str = strStream.str();//str holds the content of the file
		while (std::getline(strStream, linesRead, '\n')) {
			string_array.push_back(linesRead);
		}

		//iterator and savor for each jsonnlohmann data
		for (std::vector<string>::iterator it = string_array.begin(); it != string_array.end(); ++it)
		{ //to iterate vector with the string in each vector
			j_json["protocol_data"].push_back(*it);
		}
		read_pcap_json_file.close();
	}
	else {
		cout << "File cannot be read";
	}

	string_array.clear();

	return getJSON_string_from_jsonC(j_json);
}

std::string load_database_data(std::string selected_database_file)
{
	jsonnlohmann j_selected_db = jsonnlohmann::object();
    std::stringstream JSon;
    string linesRead;
    std::ifstream ifs(selected_database_file);
	
    //data for overall jsonnlohmann data to be generated to send back to gui
	j_selected_db["type"] = "load_from_db";
    if (ifs.is_open())
    {
        std::stringstream strStream;
        strStream << ifs.rdbuf();
        linesRead = strStream.str();
        ifs.close();
    }
    else {
        cout << "File cannot be read";
    }
	j_selected_db["data"] = linesRead;
	return getJSON_string_from_jsonC(j_selected_db);
}

std::string get_database_data_all(std::string database_type) /*to get individual data from each file*/ /*new*/
{
	if (database_type.compare("tcp") == 0)
	{
		return getJSON_string_from_jsonC(read_database_file("tcp_database.json", "tcp"));
	}
	else if (database_type.compare("icmp") == 0)
	{
		return getJSON_string_from_jsonC(read_database_file("icmp_database.json", "icmp"));
	}
	else if (database_type.compare("dns") == 0)
	{
		return getJSON_string_from_jsonC(read_database_file("dns_database.json", "dns"));
	}
	else if (database_type.compare("protocol") == 0)
	{
		return getJSON_string_from_jsonC(read_database_file("protocol_database.json", "protocol"));
	}
	else if (database_type.compare("pcap") == 0)
	{
		return getJSON_string_from_jsonC(read_database_file("pcap_database.json", "pcap"));
	}
	else
		return "error";
}

jsonnlohmann read_database_file(std::string read_file,std::string type) /*to read the dataabse file containing list of individual database*/
{
	jsonnlohmann j_json = jsonnlohmann::object();
	std::ifstream read_database_file(read_file);
	std::stringstream json_stream;
	string linesRead;
	vector<string> string_array;

	type += "_database";
	j_json["type"] = type;
	type.clear();

	if (read_database_file.is_open())
	{
		std::stringstream strStream;
		strStream << read_database_file.rdbuf();//read the file
		string str = strStream.str();//str holds the content of the file
		while (std::getline(strStream, linesRead, '\n')) {
			string_array.push_back(linesRead);
		}

		//iterator and savor for each jsonnlohmann data
		for (std::vector<string>::iterator it = string_array.begin(); it != string_array.end(); ++it) { //to iterate vector with the string in each vector
			j_json["data"].push_back(*it);
		}
		read_database_file.clear();
		read_database_file.close();
	}
	else {
		cout << "File cannot be read";
	}
	return j_json;
}


//main Function
int main(int argc, char* argv[]) {

	config.read();

	uint32_t port = 7000;
	std::string docroot = "www/";

	std::cout << "Web Server started on port " << port << std::endl;
	server_instance.configure(docroot, port, callback);
	server_instance.start();
	_getch();

	server_instance.stop();
	return 0;

}