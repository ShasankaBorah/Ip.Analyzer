//#include "Database_writer.h"
//#include <conio.h>
//#include <bson.h>
//#include <mongoc.h>
//#include <stdlib.h>
//#include <json.hpp>
//#include <iostream>
//#include <fstream>
//
//using namespace std;
//
//using jsonnlohmann = nlohmann::json;
//
//
//
//
//Database_writer::Database_writer()
//{
//}
//
//
//Database_writer::~Database_writer()
//{
//}
//
//
//void Database_writer::writeData(const char* colName)
//{
//	mongoc_client_t*					client;
//	mongoc_collection_t*				collection;
//	bson_error_t						error;
//	bson_oid_t							oid;
//	//bson_error_t error;
//	bson_t								*bson;
//	char								*string;
//
//	mongoc_init();
//
//	client = mongoc_client_new("mongodb://localhost:27017");
//	collection = mongoc_client_get_collection(client, "IpAnalayzer_db", colName);
//
//
//
//}
