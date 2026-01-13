#include <database.hpp>
#include <argparse/argparse.hpp>
#include <qvpn_api.hpp>

using QVPNServerSettings = QVPN::QVPNServerSettings;
using QVPNServer = QVPN::QVPNServer<ServerDatabaseAdapter, ServerStatsAdatper>;
using QVPNLayers = QVPN::QVPNLayersStrategy;

int main(int argc, const char* argv[])
{

    // TODO: доделать перехват seq, ack через WinSock

    argparse::ArgumentParser program("QVPN Server App", "0.5");

    program.add_argument("-s", "--settings", "-c", "--config")
        .help("”кажите путь до файла с настройками (по умолчанию) server_settings.json")
        .default_value(std::string("Z:\\Files\\Projects\\C++\\MaxVPN\\build\\bin\\Windows\\server_settings.json"));

    program.parse_args(argc, argv);
    
    QVPNServerSettings settings{};
    std::string path = program.get<std::string>("--settings");
    settings.parse_settings(path);
    
	SQLiteDatabase database(settings.get_db_host());
    ServerDatabaseAdapter db_adapter(database);
    ServerStatsAdatper stats_adatper(database);

    QVPNServer vpn_server(settings);
    vpn_server.init(db_adapter, stats_adatper);
    
    std::cin.get();
	return 0;
}