#include "Ip_Address_to_country_mapper.h"
#include "Check_internet.h"
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include <set>
#include <cpprest/json.h>
#include <json.hpp>
#include <iostream>
#include <conio.h>
#include "stdafx.h"
#include <initializer_list>
#include <boost/algorithm/string/join.hpp>
#include  <regex>
#include <map>
#include <boost/asio/ip/basic_resolver_entry.hpp>
#include <boost/thread/v2/thread.hpp>
//#include <complex.h>
//#include <minwindef.h>

using namespace utility; // Common utilities like string conversions
using namespace web; // Common features like URIs.
using namespace web::http; // Common HTTP functionality
using namespace web::http::client; // HTTP client features
using namespace concurrency::streams; // Asynchronous streams

using namespace std;
using jsonnlohmann = nlohmann::json;

extern void send_analysis_message_GUI(std::string progress_msg);
extern void send_message_GUI(std::string msg);
extern std::string getJSON_string_from_jsonC(jsonnlohmann json);

Ip_Address_to_country_mapper::Ip_Address_to_country_mapper()
{
}


Ip_Address_to_country_mapper::~Ip_Address_to_country_mapper()
{
}



bool Ip_Address_to_country_mapper::stringComp(std::string ip)
{ //private ip
	//10.0.0.0 -10.255.255.255
	//192.168.0.0. - 192.168.255.255
	//172.16.0.0 - 172.31.255.255

	/*if reserved or private ip then 
	 * the function will return false 
	 * else it will return true
	 * true == public ip
	 */

	regex ten("^10\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$");
	regex reserved("^100\.(6[4-9]|[7-9][0-9]|1([0-1][0-9]|2[0-7]))\.(0\.(0[ -9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))|([1-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))$");
	regex ninty("^192\.168\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$");
	regex one_seventy("^172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$");
	regex multicast_address("^(2(2[4-9]|3[0-9]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$");
	regex future_use_ip("^(2(4[0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.(([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-4]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))|255\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-4])))$");
	regex relay_ip("^192\.88\.99\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$");

	if (regex_match(ip, ten))
	{
		return false;
	}
	else if (regex_match(ip, relay_ip))
	{
		return false;
	}
	else if (regex_match(ip, ninty))
	{
		return false;
	}
	else if (regex_match(ip, one_seventy))
	{
		return false;
	}
	else if (regex_match(ip, reserved))
	{
		return false;
	}
	else if (regex_match(ip, multicast_address))
	{
		return false;
	}
	else
	{
		return true;
	}
}


jsonnlohmann Ip_Address_to_country_mapper::analyze(jsonnlohmann input_json)
{

	/**********************************************************************************************
	 * First the database file is being read and the json ip_to_country_map is filled witht he data
	 * input_json icmp_json_stream file sent from the icmp analyze, only stream object is being sent
	 * tfistrly the stream object is searched in the json
	 * if found it will go in and cpy it to stream json
	 * then the src and dst ip are checked for private and public
	 * if public it will go in and check if that ip exist in the ip_to_country _map
	 * if found the src or dst info being updated if not found it inserts it in the ip_address_set(std::set)
	 * after the for loop is finished, iteration of the set begins and inputBtach vector is filled with the ip addresses
	 * only 32 ip addresses are being entered in the vector, since it can only process a batch of 32 ip addresses
	 * if the vector size is 32 then the get_country_info function is called and the vector of the batch is being passed
	 * whrere it processes that batch of ip address aand stores in the result_ json object
	 *
	 *
	 */
	int							setSize;
	jsonnlohmann				j_json;
	std::size_t					found;
	std::string					ip_mask_src;
	std::string					ip_mask_dst;
	jsonnlohmann				streams;
	jsonnlohmann				ip_to_country_map = jsonnlohmann::object();
	std::stringstream			ip_string;
	std::vector<std::string>	inputBatch;											 //to create a vector of ip address to send to the api 
	std::set<std::string>		ip_address_set;
	std::ifstream myfile("ip_country.json");

	Check_internet check;

	bool checkI = check.checkInternet(); //check Internet connected or not

	if (myfile.is_open())
	{
		myfile.seekg(0, ios::end);													// put the "cursor" at the end of the file
		int64_t length = myfile.tellg();											// find the position of the cursor	

		if (length != 0)
		{
			try
			{
				myfile.seekg(0, ios::beg);											// put the "cursor" at the begin of the file to read from start
				myfile >> ip_to_country_map;
				myfile.close();
			}
			catch (jsonnlohmann::parse_error& e)
			{
				std::cerr << e.what() << std::endl;
			}
		}

		/*for (auto it = ip_to_country_map.begin(); it != ip_to_country_map.end(); ++it)
		{
			std::cout << it.key() << "\n" << std::endl;;
		}*/

	}


	if (input_json.find("streams") != input_json.end() || input_json.find("IPDetails") != input_json.end())/*if found*/
	{
		if (input_json.find("streams") != input_json.end())
		{
			streams = input_json["streams"];
		}

		if (input_json.find("IPDetails") != input_json.end())
		{
			streams = input_json["IPDetails"];
		}

		for (int i = 0; i < streams.size(); i++)
		{
			
			std::string ip_src = streams[i]["SrcIp"];
			std::string ip_dst = streams[i]["DstIp"];


			if (stringComp(ip_src) == true)
			{
				found = ip_src.find_last_of(".");										// to find the last period sign in the ip address so that the last digit can be replaced with "0"
				ip_mask_src = ip_src.substr(0, found);									//ip address without the last digit
				ip_mask_src = ip_mask_src + "." + "0";								    // replacing last digit with "0"

				if (ip_to_country_map.find(ip_mask_src) == ip_to_country_map.end())		/*ip mask not found*/
				{
					if (checkI)
					{
						ip_address_set.insert(ip_mask_src);//if inetrnet present then add to the vector
					}
					else
					{
						streams[i]["src_info"] = "NA";
					}
				}
				else
				{
					streams[i]["src_info"] = ip_to_country_map[ip_mask_src];
				}
			}

			if (stringComp(ip_dst) == true)
			{

				found = ip_dst.find_last_of(".");										// to find the last period sign in the ip address so that the last digit can be replaced with "0"
				ip_mask_dst = ip_dst.substr(0, found);									//ip address without the last digit
				ip_mask_dst = ip_mask_dst + "." + "0";									// replacing last digit with "0"

				if (ip_to_country_map.find(ip_mask_dst) == ip_to_country_map.end())		/*ip mask not found*/
				{
					if (checkI)
					{
						ip_address_set.insert(ip_mask_dst); //if inetrnet present then add to the vector
					}
					else
					{
						streams[i]["dst_info"] = "NA";
					}

				}
				else
				{
					streams[i]["dst_info"] = ip_to_country_map[ip_mask_dst];
				}
			}
			ip_mask_src.clear();
			ip_mask_dst.clear();
			ip_src.clear();
			ip_dst.clear();
		}

		// Get IP Address info from api
		//to check is internet is connected or not
		if (checkI)
		{
			if (!ip_address_set.empty())
			{
				int inputBatchSize = 0;
				std::set<std::string>::iterator penUltimate = ip_address_set.end();
				--penUltimate;

				setSize = ip_address_set.size();

				for (auto it = ip_address_set.begin(); it != ip_address_set.end(); ++it)
				{

					inputBatch.push_back(*it);
					if (inputBatch.size() == 32 || (penUltimate == it))
					{
						inputBatchSize = inputBatchSize + inputBatch.size();
						j_json["type"] = "api_progress";
						j_json["totalSetRead"] = inputBatchSize;
						j_json["fileSize"] = setSize;
						std::cout << (uint64_t)inputBatchSize << "/" << setSize << std::endl;
						send_analysis_message_GUI(getJSON_string_from_jsonC(j_json));
						j_json.clear();

						get_country_info(inputBatch);

						for (const auto &j : jsonnlohmann::iterator_wrapper(result_))
						{			
							ip_to_country_map[j.key()] = j.value();
						}

						/*jsonnlohmann ip = {};
						for (auto it = ip_to_country_map.begin(); it != ip_to_country_map.end(); ++it)
						{
							
							jsonnlohmann ipJson;
							ipJson["Ip"] = it.key();
							ipJson["data"] = it.value();
							ip.push_back(ipJson);
							
						}*/
					/*	std::ofstream o("pretty.json");
						o <<  ip << std::endl;

						std::string jsonString = ip_to_country_map.dump();*/

						inputBatch.clear();
						boost::this_thread::sleep(boost::posix_time::seconds(4));
					}
				}
			}


			// update the streams with new info
			/********************************************************/
			for (int i = 0; i < streams.size(); i++)
			{
				std::string ip_src = streams[i]["SrcIp"];
				std::string ip_dst = streams[i]["DstIp"];
				
				if (stringComp(ip_src) == true)
				{
					found = ip_src.find_last_of(".");						// to find the last period sign in the ip address so that the last digit can be replaced with "0"
					ip_mask_src = ip_src.substr(0, found);					//ip address without the last digit
					ip_mask_src = ip_mask_src + "." + "0";					// replacing last digit with "0"

					if (streams[i].find("src_info") == streams[i].end())	/*not found*/
					{
						streams[i]["src_info"] = ip_to_country_map[ip_mask_src];
					}
				}

				if (stringComp(ip_dst) == true)
				{
					found = ip_dst.find_last_of(".");						// to find the last period sign in the ip address so that the last digit can be replaced with "0"
					ip_mask_dst = ip_dst.substr(0, found);					//ip address without the last digit
					ip_mask_dst = ip_mask_dst + "." + "0";					// replacing last digit with "0"
					if (streams[i].find("dst_info") == streams[i].end())	/*not found*/
					{
						streams[i]["dst_info"] = ip_to_country_map[ip_mask_dst];
					}
				}
				ip_mask_src.clear();
				ip_mask_dst.clear();
			}

			std::ofstream outputFile("ip_country.json");
			if (outputFile.is_open())
			{
				outputFile << ip_to_country_map;
				ip_to_country_map.clear();
				outputFile.close();
			}
		}

	}
	return streams;
}

void Ip_Address_to_country_mapper::get_country_info(std::vector<std::string> ipBatch)
{
	std::string		joined = boost::algorithm::join(ipBatch, ",");
	std::wstring	url = U("http://api.db-ip.com/v2/af5e8c1d74ccd285bc133d42c8776904d04b186e/") + wstring(joined.begin(), joined.end());
	http_client		client(url);
	make_request(client, methods::GET, json::value::null());

}

void Ip_Address_to_country_mapper::make_request(http_client& client, method mtd, json::value const& jvalue)
{
	make_task_request(client, mtd, jvalue)
		.then([](http_response response)
	{
		if (response.status_code() == status_codes::OK)
		{
			return response.extract_json();
		}
		return pplx::task_from_result(json::value());
	})
		.then([this](pplx::task<json::value> previousTask)
	{
		try
		{
			wcout << previousTask.get().serialize() << endl;

			std::wstring s = previousTask.get().serialize();
			
			/*std::string k(s.begin(), s.end());
			
			std::string test = jsonnlohmann::parse(k);*/

			std::wstring wstr = previousTask.get().serialize();

			std::string str(wstr.begin(), wstr.end());

			str = stripUnicode(str);

			try {

				this->result_ = jsonnlohmann::parse(str);
			}
			catch (jsonnlohmann::parse_error &k)
			{
				std::cerr << k.what() << std::endl;
			}
			//this->result_ = jsonnlohmann::parse(str);
		}
		catch (http_exception const& e)
		{
			wcout << e.what() << endl;
		}
	})
		.wait();
}

pplx::task<http_response> Ip_Address_to_country_mapper::make_task_request(http_client& client, method mtd, json::value const& jvalue)
{
	return client.request(methods::GET);
}

bool invalidChar(char c)
{
	{
		return !(c >= 0 && c < 128);
	}
}

std::string Ip_Address_to_country_mapper::stripUnicode(std::string  &s)
{

	s.erase(std::remove_if(s.begin(), s.end(), invalidChar), s.end());

	return s;
}

//json Ip_::get_country_info(std::string ip_addr_str)
//{
//	// first check in ip_to_country_map; /// json
//
//	// if found return info
//
//	// if not found query db
//
//	// if found in db add the info to map and return
//
//	// if not found in db then call api and add to both map and db and return info
//}