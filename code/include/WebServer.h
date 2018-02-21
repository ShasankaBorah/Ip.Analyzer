/**

etta::WebServer is a header only library for including web server thread into any application.
To use it in ant project.
1. run cmake
2. run install
3. link your project to webserver installation directory
4. here is an example for main.cpp opening WebServer thread:

main.cpp
======================
#include <WebServer.h>
etta::WebServer* server_instance;
etta:NodeController* controller;  // controller implementation

void
callback(const std::string& c)
{
if (controller)
return controller->callback(c);
}

void sendData(const std::string& c, const std::string& d)
{
if (server_instance)
return server_instance->send_data(c, d);
}

int main(int argc, char* argv[])
{
// Do not forget to create etta::NodeController

try {
// Start a thread to run the processing loop
std::thread t(std::bind(&etta::WebServer::process_messages, server_instance));

// Run the asio loop with the main thread
server_instance->run("app", 8081, callback);

t.join();

} catch (websocketpp::exception const & e) {
std::cout << e.what() << std::endl;
}
return 0;
}
*/
#pragma once


#include <string>
#include <websocketpp/frame.hpp>
#include <boost/thread.hpp>

typedef void (CallbackFunc)(const std::string& uri, const std::string& data);


class WebServerImpl;

class WebServer {
public:
	WebServer();
	void configure(std::string app_location, uint16_t app_port, CallbackFunc* callback);

	int send_data(const std::string& uri, const std::string& data);
	int send_data(const std::string& uri, const uint8_t* data, uint32_t length);

	void start();
	void stop();
private:

	boost::thread m_thread;
	bool is_running;

	WebServerImpl* pimpl_;
	std::string app_location;
	uint16_t app_port;
	CallbackFunc* callback;

	void thread_handler();
	void process_messages();
};