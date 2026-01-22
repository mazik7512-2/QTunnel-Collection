#include "database.hpp"
#include <sstream>
#include <iostream>
#include <memory>

using QVPNConnectionElement = QVPN::Core::QVPNConnectionElement;

SQLiteDatabase::SQLiteDatabase(std::string_view path)
{
	sqlite3_open(path.data(), &db_);
}

void SQLiteDatabase::add_statistic_data(std::string_view user, NetProtocol net_proto, TransportProtocol transport_proto, const NetAddr& src_addr, UShort src_port, const NetAddr& dst_addr, UShort dst_port, size_t traffic_size)
{
	char* msg_error;
	std::stringstream ss{};
	ss << "INSERT INTO stats VALUES('" << src_addr.to_string() << "', " << src_port << ", '" << dst_addr.to_string() << "', " << dst_port << ", ";
	ss << net_proto << ", " << transport_proto << ", " << traffic_size << ", " << user << ");";
	auto sql = ss.str();
	auto exit = sqlite3_exec(db_, sql.c_str(), NULL, nullptr, &msg_error);
	if (exit != SQLITE_OK)
	{
		std::cerr << "Error inserting stats data" << std::endl;
		sqlite3_free(msg_error);
	}

}

int get_user_stats_callback(void* data, int argc, char** argv, char** azColName)
{
	std::vector<UserStatisticData>* res = static_cast<std::vector<UserStatisticData>*>(data);
	QVPNConnectionElement user_data(std::string_view(argv[1]), static_cast<UShort>(std::stoi(argv[2])));
	QVPNConnectionElement dst_data(std::string_view(argv[3]), static_cast<UShort>(std::stoi(argv[4])));

	NetProtocol net_proto = static_cast<NetProtocol>(std::stoi(argv[5]));
	TransportProtocol transport_proto = static_cast<TransportProtocol>(std::stoi(argv[6]));
	
	size_t traffic_size = static_cast<size_t>(std::stoi(argv[7]));
	for (size_t i = 0; i < argc; i++)
	{
		res->at(i).set_data(std::string_view(argv[0]), user_data, dst_data, transport_proto, traffic_size);
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
	const auto& user_con = data.get_user_con();
	const auto& dst_con = data.get_dest_con();
	db_->add_statistic_data(data.get_user(), data.get_net_proto(), data.get_transport_proto(), user_con.get_ip_address(), user_con.get_port(), dst_con.get_ip_address(), dst_con.get_port(), data.get_traffic_size());
}

std::vector<UserStatisticData> ServerStatsAdatper::get_user_stats(std::string_view user)
{
	return db_->get_user_stats(user);
}
