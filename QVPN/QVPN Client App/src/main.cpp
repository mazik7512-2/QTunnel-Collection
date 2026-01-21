
#include <iostream>
#include <argparse/argparse.hpp>
#include <qvpn_api.hpp>


using QVPNClientSettings = QVPN::QVPNClientSettings;
using QVPNClient = QVPN::QVPNClient;
using QVPNLayers = QVPN::QVPNLayersStrategy;

void EnableANSI() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

int main(int argc, const char* argv[])
{
    EnableANSI();
    argparse::ArgumentParser program("QVPN Client App", "0.5");

    program.add_argument("-s", "--settings", "-c", "--config")
        .help("”кажите путь до файла с настройками (по умолчанию) client_settings.json")
        .default_value(std::string("Z:\\Files\\Projects\\C++\\MaxVPN\\build\\bin\\Windows\\client_settings.json"));
    
    program.parse_args(argc, argv);

    QVPNClientSettings settings{};
    std::string path = program.get<std::string>("--settings");
    settings.parse_settings(path);

    QVPNLayers layers{};
    settings.apply_strategy(std::move(layers));

    auto addr = settings.get_ip_address();

    QVPNClient vpn_client(settings);
    vpn_client.init_vpn();

//    vpn_client.add_outgoing_traffic_filter(vpn_client.ipv4() && vpn_client.tcp() && vpn_client.udp());
//    vpn_client.add_incoming_traffic_filter(vpn_client.ipv4() && vpn_client.tcp() && vpn_client.udp());
    vpn_client.add_outgoing_traffic_filter(vpn_client.ipv4() && vpn_client.tcp() || vpn_client.udp());
    vpn_client.add_incoming_traffic_filter(vpn_client.ipv4() && vpn_client.tcp() || vpn_client.udp());

    vpn_client.start_capture_outgoing_traffic(addr.to_ipv4(), 1);
    vpn_client.start_capture_incoming_traffic(addr.to_ipv4());
    std::cin.get();
    return 0;
}