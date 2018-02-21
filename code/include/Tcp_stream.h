#pragma once
#include <string>
#include <iostream>
#include <map>
#include <vector>
#include <algorithm>
#include <fstream>
#include <set>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "boost/date_time/posix_time/posix_time.hpp"
#include "json.hpp"
#include <string>

using namespace std;

class Tcp_stream
{
private:
	uint32_t tcp_src_port;
	uint32_t tcp_dst_port;
	std::vector<uint64_t> tcp_seq_no_vec;
	std::vector<uint64_t> tcp_ack_no_vec;


public:
	Tcp_stream();
	~Tcp_stream();
	Tcp_stream(uint32_t s, uint32_t d, uint64_t se_n, uint64_t ack_n);
	void update_se_ack(uint64_t se , uint64_t ack); //se = sequence number and ack = acknowledgement number
	uint32_t get_src_port();
	uint32_t get_dst_port();
	vector<uint64_t> get_seq_num();
	vector<uint64_t> get_ack_num();
};

