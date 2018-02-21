#pragma once
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include <cpprest/json.h>
#include <iostream>
#include <conio.h>
#include "stdafx.h"
#include "json.hpp"

using jsonnlohmann = nlohmann::json;

using namespace utility;                    // Common utilities like string c
using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features
using namespace concurrency::streams;       // Asynchronous streams

class Ip_Address_to_country_mapper
{
private:
	jsonnlohmann result_;
	
public:
	Ip_Address_to_country_mapper();
	~Ip_Address_to_country_mapper();
	bool						stringComp(std::string ip);
	void						get_country_info(std::vector<std::string> ipBatch);

	jsonnlohmann				analyze(jsonnlohmann input_json);

	jsonnlohmann				ip_api_analyze_funct(jsonnlohmann input_json_file);

	void						make_request(http_client & client,
								method mtd,
								json::value const & jvalue);
	
	pplx::task<http_response>	make_task_request(http_client & client,
								method mtd,
								json::value const & jvalue);

	
	std::string						stripUnicode(std::string  &s);
	

};
