#include "database.hpp"
#include <sstream>
#include <iostream>
#include <memory>

using QVPNSocketData = QVPN::Core::QVPNSocketData;
using NetAddr = QVPN::Core::NetAddr;
using NetProtocol = QVPN::Core::NetProtocol;
using TransportProtocol = QVPN::Core::TransportProtocol;
using UShort = QVPN::Core::BaseTypes::UShort;
using UInt = QVPN::Core::BaseTypes::UInt;

SQLiteDatabase::SQLiteDatabase(std::string_view path)
{
	sqlite3_open(path.data(), &db_);
}

void SQLiteDatabase::add_statistic_data(std::string_view user, const QVPNSocketData& sock_data, size_t traffic_size, TrafficType traffic_type)
{
	char* msg_error;
	std::stringstream ss{};
	ss << "INSERT INTO stats VALUES(NULL, '" << sock_data.local_addr.to_string() << "', " << sock_data.local_port << ", '" << sock_data.remote_addr.to_string() << "', " << sock_data.remote_port << ", ";
	ss << static_cast<QVPN::Core::UShort>(sock_data.net_proto) << ", " << static_cast<QVPN::Core::UShort>(sock_data.transport_proto) << ", " << traffic_size << ", '" << user << "'" << ", " << static_cast<UInt>(traffic_type) << ");";
	auto sql = ss.str();
	auto exit = sqlite3_exec(db_, sql.c_str(), NULL, nullptr, &msg_error);
	if (exit != SQLITE_OK)
	{
		std::cerr << "Error inserting stats data." << std::endl;
		std::cerr << "Error data: " << msg_error << std::endl;
		std::cerr << "SQL Query: " << sql << std::endl;
		sqlite3_free(msg_error);
	}

}

int get_user_stats_callback(void* data, int argc, char** argv, char** azColName)
{
	std::vector<UserStatisticData>* res = static_cast<std::vector<UserStatisticData>*>(data);
	//QVPNSocketData user_data(std::string_view(argv[1]), static_cast<UShort>(std::stoi(argv[2])));
	//QVPNSocketData dst_data(std::string_view(argv[3]), static_cast<UShort>(std::stoi(argv[4])));
	NetAddr src{ std::string_view(argv[1]) };
	NetAddr dst{ std::string_view(argv[3]) };
	UShort src_port = static_cast<UShort>(std::stoi(argv[2]));
	UShort dst_port = static_cast<UShort>(std::stoi(argv[4]));
	NetProtocol net = static_cast<NetProtocol>(std::stoi(argv[5]));
	TransportProtocol transport = static_cast<TransportProtocol>(std::stoi(argv[6]));

	QVPNSocketData socket_data{ net, transport, src, src_port, dst, dst_port };

	
	size_t traffic_size = static_cast<size_t>(std::stoi(argv[7]));
	TrafficType traffic_type = static_cast<TrafficType>(std::stoi(argv[8]));
	for (size_t i = 0; i < argc; i++)
	{
		res->at(i).set_data(std::string_view(argv[0]), socket_data, traffic_size, traffic_type);
	}

	return 0;
}

std::vector<UserStatisticData> SQLiteDatabase::get_user_stats(std::string_view user)
{
	std::vector<UserStatisticData> user_data{};
	std::stringstream ss{};
	ss << "SELECT stats.user, stats.src_addr, stats.src_port, stats.dst_addr, stats.dst_port, stats.net_proto, stats.transport_proto, SUM(stats.traffic_size) FROM stats JOIN users ON stats.user = users.key WHERE stats.user LIKE '";
	ss << user << "'" << "GROUP BY stats.src_addr, stats.src_port, stats.dst_addr, stats.dst_port;";
	auto sql = ss.str();
	auto exit = sqlite3_exec(db_, sql.c_str(), get_user_stats_callback, &user_data, nullptr);
	return user_data;
}

int check_user_callback(void* data, int argc, char** argv, char** azColName)
{
	bool* res = static_cast<bool*>(data);
	if (argc > 0)
		*res = true;
	else
		*res = false;
	return 0;
}

bool SQLiteDatabase::check_user(std::string_view user)
{
	bool b = false;
	std::stringstream ss{};
	ss << "SELECT * FROM users WHERE key LIKE '" << user << "'";
	auto sql = ss.str();
	auto exit = sqlite3_exec(db_, sql.c_str(), check_user_callback, &b, nullptr);
	if (exit != SQLITE_OK)
	{
		b = false;
	}
	return b;
}

SQLiteDatabase::~SQLiteDatabase()
{
	sqlite3_close(db_);
}

ServerDatabaseAdapter::ServerDatabaseAdapter(SQLiteDatabase& db_instance)
{
	db_ = std::make_shared<SQLiteDatabase>(db_instance);
}

bool ServerDatabaseAdapter::check_user(std::string_view user)
{
	return db_->check_user(user);;
}

ServerStatsAdatper::ServerStatsAdatper(SQLiteDatabase& db_instance)
{
	db_ = std::make_shared<SQLiteDatabase>(db_instance);
}

void ServerStatsAdatper::add_user_stats(const UserStatisticData& data)
{
	const auto& socket_data = data.get_connection_data();
	db_->add_statistic_data(data.get_user(), socket_data, data.get_traffic_size(), data.get_traffic_type());
}

std::vector<UserStatisticData> ServerStatsAdatper::get_user_stats(std::string_view user)
{
	return db_->get_user_stats(user);
}
