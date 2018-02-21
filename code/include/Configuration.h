#pragma once
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

class Configuration
{
public:
	Configuration();
	~Configuration();

	std::vector<std::string> fl_folders;
	std::vector<std::string> rl_folders;

	int32_t read();
	std::string getJSON();
	int32_t write();
	
	std::string get_fl_path()
	{
		return fl_path;
	}
	void set_fl_path(std::string str)
	{
		fl_path = str;
	}

	std::string get_rl_path()
	{
		return rl_path;
	}

	void set_rl_path(std::string str)
	{
		rl_path = str;
	}

private:
	std::string fl_path;
	std::string rl_path;
};

