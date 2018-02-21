#ifndef _WEBSOCKETPP_NO_CPP11_SYSTEM_ERROR_
#define _WEBSOCKETPP_CPP11_CHRONO_
#endif
#include "WebServer.h"
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>

#include <fstream>
#include <iostream>
#include <set>
#include <streambuf>
#include <string>

#include <websocketpp/common/thread.hpp>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string/predicate.hpp>

typedef websocketpp::server<websocketpp::config::asio> server;

using websocketpp::connection_hdl;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;


using websocketpp::lib::thread;
using websocketpp::lib::mutex;
using websocketpp::lib::unique_lock;
using websocketpp::lib::condition_variable;

/* on_open insert connection_hdl into channel
* on_close remove connection_hdl from channel
* on_message queue send to all channels
*/

enum action_type
{
	SUBSCRIBE,
	UNSUBSCRIBE,
	MESSAGE
};

struct action
{
	action(action_type t, connection_hdl h) : type(t), hdl(h)
	{
	}

	action(action_type t, connection_hdl h, server::message_ptr m)
		: type(t), hdl(h), msg(m)
	{
	}

	action_type type;
	websocketpp::connection_hdl hdl;
	server::message_ptr msg;
};

struct connection
{
	std::string uri;
	connection_hdl hdl;
};

//std::vector<connection> ws_connections;

class WebServerImpl
{
public:
	WebServerImpl() : m_should_run(true)
	{
		// Initialize Asio Transport
		m_server.init_asio();

		// Register handler callbacks
		m_server.set_open_handler(bind(&WebServerImpl::on_open, this, ::_1));
		m_server.set_close_handler(bind(&WebServerImpl::on_close, this, ::_1));
		m_server.set_message_handler(bind(&WebServerImpl::on_message, this, ::_1, ::_2));
		m_server.set_http_handler(bind(&WebServerImpl::on_http, this, ::_1));
	}

	void stop()
	{
		m_should_run = false;
		m_action_cond.notify_all();
		m_server.stop_listening();

		m_server.stop();
	}

	void run(std::string app_location, uint16_t app_port, CallbackFunc* callback)
	{
		m_docroot = app_location;
		m_port = app_port;
		m_callbackfunc = callback;

		m_server.clear_access_channels(websocketpp::log::alevel::all);
		m_server.set_access_channels(websocketpp::log::channel_type_hint::none);

		m_server.clear_error_channels(websocketpp::log::alevel::all);
		m_server.set_error_channels(websocketpp::log::channel_type_hint::none);

		std::stringstream ss;
		ss << "Running etta WebServerImpl on port " << m_port << " using docroot=" << m_docroot;
		m_server.get_alog().write(websocketpp::log::alevel::app, ss.str());
		//std::cout << ss.str() << std::endl;

		// listen on specified port
		m_server.listen(m_port);

		// Start the server accept loop
		m_server.start_accept();

		th_process_msgs = thread(std::bind(&WebServerImpl::process_messages, this));

		// Start the ASIO io_service run loop
		try
		{
			m_server.run();
		}
		catch (websocketpp::exception const& e)
		{
			std::cout << e.what() << std::endl;
		}
	}

	void on_http(connection_hdl hdl)
	{
		// Upgrade our connection handle to a full connection_ptr
		server::connection_ptr con = m_server.get_con_from_hdl(hdl);
		if (!con)
		{
			std::cout << "Skip on_http (bad connection)" << std::endl;
			return;
		}

		std::ifstream file;
		std::string filename = con->get_uri()->get_resource();
		std::string response;

		m_server.get_alog().write(websocketpp::log::alevel::app, "http request1: " + filename);

		if (filename == "/")
		{
			filename = m_docroot + "index.html";
		}
		else
		{
			filename = m_docroot + filename.substr(1);
		}

		m_server.get_alog().write(websocketpp::log::alevel::app, "http request2: " + filename);

		if (!boost::filesystem::exists(filename) || boost::filesystem::is_directory(filename))
		{
			// 404 error
			std::stringstream ss;

			ss << "<!doctype html><html><head>"
				<< "<title>Error 404 (Resource not found)</title><body>"
				<< "<h1>Error 404</h1>"
				<< "<p>The requested URL " << filename << " was not found on this server.</p>"
				<< "</body></head></html>";

			con->set_body(ss.str());
			con->set_status(websocketpp::http::status_code::not_found);
		} else if (boost::ends_with(filename, ".svg"))
		{
			file.open(filename.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
			std::streampos size = file.tellg();
			file.seekg(0, std::ios::beg);

			char* memblock = new char[size];

			file.read(memblock, size);

			con->set_body(std::string(memblock, size));
			con->replace_header("Content-Type", "image/svg+xml");
			con->set_status(websocketpp::http::status_code::ok);
			delete[] memblock;
		} else if (boost::ends_with(filename, ".css"))
		{
			file.open(filename.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
			std::streampos size = file.tellg();
			file.seekg(0, std::ios::beg);

			char* memblock = new char[size];

			file.read(memblock, size);

			con->set_body(std::string(memblock, size));
			con->replace_header("Content-Type", "text/css");
			con->set_status(websocketpp::http::status_code::ok);
			delete[] memblock;
		}
		else
		{
			file.open(filename.c_str(), std::ios::in | std::ios::ate);
			response.reserve(file.tellg());
			file.seekg(0, std::ios::beg);

			response.assign((std::istreambuf_iterator<char>(file)),
				std::istreambuf_iterator<char>());

			con->set_body(response);
			con->set_status(websocketpp::http::status_code::ok);
		}
	}

	int send_data(const std::string& uri, const std::string& data)
	{
		try
		{
			unique_lock<mutex> con_lock(m_connection_lock);

			con_list::iterator it;
			for (it = m_connections.begin(); it != m_connections.end(); ++it)
			{
				server::connection_ptr con = m_server.get_con_from_hdl(*it);
				if (!con)
				{
					std::cout << "Skip send_data (bad connection)" << std::endl;
					continue;
				}

				std::string filename = con->get_uri()->get_resource();
				if (filename != uri) continue;
				m_server.send(*it, data.c_str(), data.length(), websocketpp::frame::opcode::TEXT);
			}
		}
		catch (websocketpp::exception const& e)
		{
			std::cout << e.what() << std::endl;
			return -2;
		}

		return 0;
	}

	int send_data(const std::string& uri, const uint8_t* data, uint32_t length)
	{
		try
		{
			unique_lock<mutex> con_lock(m_connection_lock);

			con_list::iterator it;
			for (it = m_connections.begin(); it != m_connections.end(); ++it)
			{
				server::connection_ptr con = m_server.get_con_from_hdl(*it);
				if (!con)
				{
					std::cout << "Skip send_data (bad connection)" << std::endl;
					continue;
				}

				std::string filename = con->get_uri()->get_resource();
				if (filename != uri) continue;
				m_server.send(*it, data, length, websocketpp::frame::opcode::BINARY);
			}
		}
		catch (websocketpp::exception const& e)
		{
			std::cout << e.what() << std::endl;
			return -2;
		}

		return 0;
	}

	void on_open(connection_hdl hdl)
	{
		unique_lock<mutex> lock(m_action_lock);
		m_actions.push(action(SUBSCRIBE, hdl));
		lock.unlock();
		m_action_cond.notify_one();
	}

	void on_close(connection_hdl hdl)
	{
		unique_lock<mutex> lock(m_action_lock);
		m_actions.push(action(UNSUBSCRIBE, hdl));
		lock.unlock();
		m_action_cond.notify_one();
	}

	void on_message(connection_hdl hdl, server::message_ptr msg)
	{
		// queue message up for sending by processing thread
		unique_lock<mutex> lock(m_action_lock);
		m_actions.push(action(MESSAGE, hdl, msg));
		lock.unlock();
		m_action_cond.notify_one();
	}

	void process_messages()
	{
		std::string uri;
		try
		{
			while (m_should_run)
			{
				unique_lock<mutex> lock(m_action_lock);

				while (m_should_run && m_actions.empty())
				{
					m_action_cond.wait(lock);
				}
				if (!m_should_run)
					break;

				action a = m_actions.front();
				m_actions.pop();

				lock.unlock();

				if (a.type == SUBSCRIBE)
				{
					unique_lock<mutex> con_lock(m_connection_lock);
					m_connections.insert(a.hdl);
				}
				else if (a.type == UNSUBSCRIBE)
				{
					unique_lock<mutex> con_lock(m_connection_lock);
					m_connections.erase(a.hdl);
				}
				else if (a.type == MESSAGE)
				{
					server::connection_ptr con = m_server.get_con_from_hdl(a.hdl);
					if (!con)
					{
						std::cout << "Skip message (bad connection)" << std::endl;
						continue;
					}
					uri = con->get_uri()->get_resource();

					try
					{
						if (m_callbackfunc) (*m_callbackfunc)(uri, a.msg->get_payload());
					}
					catch (std::exception const& e)
					{
						std::cout << "Callback exception: " << e.what() << std::endl;
					}
				}
			}

			// clear all the pending actions
			unique_lock<mutex> lock(m_action_lock);
			while (!m_actions.empty())
			{
				m_actions.pop();
			}
			lock.unlock();
		}
		catch (const std::exception& e)
		{
			std::cout << "Websocket::process_messages:" << e.what() << std::endl;
		}
	}

private:
	typedef std::set<connection_hdl, std::owner_less<connection_hdl>> con_list;

	server m_server;
	con_list m_connections;
	std::queue<action> m_actions;

	mutex m_action_lock;
	mutex m_connection_lock;
	condition_variable m_action_cond;

	std::string m_docroot;
	uint16_t m_port;
	CallbackFunc* m_callbackfunc;

	thread th_process_msgs;
	bool m_should_run;
};

WebServer::WebServer()
{
	pimpl_ = new WebServerImpl();
}

void WebServer::configure(std::string a, uint16_t p, CallbackFunc* c)
{
	app_location = a;
	app_port = p;
	callback = c;
}

void
	WebServer::thread_handler()
{
	return pimpl_->run(app_location, app_port, callback);
}

void WebServer::start()
{
	is_running = true;
	m_thread = boost::thread(&WebServer::thread_handler, this);		
}

void
	WebServer::stop()
{
	is_running = false;
	pimpl_->stop();
	m_thread.join();
}

int32_t
	WebServer::send_data(const std::string& uri, const std::string& data)
{
	return pimpl_->send_data(uri, data);
}

int32_t
	WebServer::send_data(const std::string& uri, const uint8_t* data, uint32_t length)
{
	return pimpl_->send_data(uri, data, length);
}

void
	WebServer::process_messages()
{
	return pimpl_->process_messages();
}
