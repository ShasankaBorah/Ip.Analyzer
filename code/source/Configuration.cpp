#include "configuration.h"
#include <boost/foreach.hpp>
#include <json.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <fstream>

using jsonnlohmann = nlohmann::json;
using namespace std;

/*extern std::string getJSONString(boost::property_tree::ptree pt);*/
extern std::string getJSON_string_from_jsonC(jsonnlohmann json);

Configuration::Configuration()
{
}


Configuration::~Configuration()
{
}

int32_t Configuration::read()
{
	jsonnlohmann j_config = jsonnlohmann::object();
	
		std::ifstream i("config.json");
	
		i >> j_config;
		
		fl_path = j_config["fl_path"].get<std::string>();
		rl_path = j_config["rl_path"].get<std::string>();
	
		/* read fl folders*/
		for (jsonnlohmann::iterator it = j_config["fl_folders"].begin(); it != j_config["fl_folders"].end(); ++it)
		{
			fl_folders.push_back(it.value());
		}
	
		/* read rl folders*/
		for (jsonnlohmann::iterator it = j_config["rl_folders"].begin(); it != j_config["rl_folders"].end(); ++it)
		{
			rl_folders.push_back(it.value());
		}

	return 0;
}

std::string Configuration::getJSON()
{
	jsonnlohmann j_config = jsonnlohmann::object();

	j_config["fl_path"] = fl_path;
	j_config["rl_path"] = rl_path;

	/* save fl folders*/
	boost::property_tree::ptree pt_folder;
	boost::property_tree::ptree pt_folders;
	for (auto it = fl_folders.begin(); it != fl_folders.end(); ++it)
	{
		j_config["fl_folders"].push_back(*it);
	}

	/*save rl folders*/
	for (auto it = rl_folders.begin(); it != rl_folders.end(); ++it)
	{
		j_config["rl_folders"].push_back(*it);
	}

	return getJSON_string_from_jsonC(j_config);
}

int32_t Configuration::write()
{
	
	std::ofstream ofs("config.json");

	ofs << getJSON();
	ofs.close();
	return 0;
}
