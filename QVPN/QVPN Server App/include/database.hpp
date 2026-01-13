#include <string_view>
#include <qvpn_lib.hpp>
#include <qvpn_driver.hpp>
#include <sqlite3.h>

#pragma comment(lib, "sqlite3.lib")

using NetAddr = QVPN::Core::NetAddr;
using UShort = QVPN::Core::BaseTypes::UShort;
using NetProtocol = QVPN::Core::NetProtocol;
using TransportProtocol = QVPN::Core::TransportProtocol;
using QVPNConnectionSettings = QVPN::Core::QVPNConnectionSettings;
using UserStatisticData = QVPN::Core::UserStatisticData;


class SQLiteDatabase
{
private:
	sqlite3* db_;

public:
	SQLiteDatabase(std::string_view path);


	void add_statistic_data(std::string_view user, NetProtocol net_proto, TransportProtocol transport_proto, const NetAddr& src_addr, UShort src_port, const NetAddr& dst_addr, UShort dst_port, size_t traffic_size);
	std::vector<UserStatisticData> get_user_stats(std::string_view user);
	bool check_user(std::string_view user);

	~SQLiteDatabase();
};


class ServerDatabaseAdapter
{
private:
	std::shared_ptr<SQLiteDatabase> db_;

public:

	ServerDatabaseAdapter(SQLiteDatabase& db_instance);

	bool check_user(std::string_view user);
	
};


class ServerStatsAdatper
{
private:
	std::shared_ptr<SQLiteDatabase> db_;

public:

	ServerStatsAdatper(SQLiteDatabase& db_instance);

	void add_user_stats(const UserStatisticData& data);
	std::vector<UserStatisticData> get_user_stats(std::string_view user);
};