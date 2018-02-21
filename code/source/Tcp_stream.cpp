#include "Tcp_stream.h"
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


Tcp_stream::Tcp_stream()
{
}


Tcp_stream::~Tcp_stream()
{
}

uint32_t Tcp_stream::get_src_port()
{
	return tcp_src_port;
}

uint32_t Tcp_stream::get_dst_port()
{
	return tcp_dst_port;
}

vector<uint64_t> Tcp_stream::get_seq_num()
{
	return tcp_seq_no_vec;
}

vector<uint64_t> Tcp_stream::get_ack_num()
{
		return tcp_ack_no_vec;
}

Tcp_stream::Tcp_stream(uint32_t s, uint32_t d, uint64_t se_n, uint64_t ack_n )
{
	tcp_src_port = s;
	tcp_dst_port = d;
	tcp_seq_no_vec.push_back(se_n);
	tcp_ack_no_vec.push_back(ack_n);
}

void Tcp_stream::update_se_ack(uint64_t se , uint64_t ack)
{
	tcp_seq_no_vec.push_back(se);
	tcp_ack_no_vec.push_back(ack);
}