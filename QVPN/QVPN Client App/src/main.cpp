
#include <iostream>
#include <argparse/argparse.hpp>
#include <qvpn_api.hpp>


using QVPNClientSettings = QVPN::QVPNClientSettings;
using QVPNClient = QVPN::QVPNClient;
using QVPNLayers = QVPN::QVPNLayersStrategy;

void EnableANSI() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
#endif   
}


// TODO: возможно стоит добавить свой DNS (заместо secure)

int main(int argc, const char* argv[])
{
    EnableANSI();
    argparse::ArgumentParser program("QVPN Client App", "0.5");

    program.add_argument("-s", "--settings", "-c", "--config")
        .help("Укажите путь до файла с настройками (по умолчанию) client_settings.json")
        .default_value(std::string("client_settings.json"));
    
    program.parse_args(argc, argv);

    QVPNClientSettings settings{};
    std::string path = program.get<std::string>("--settings");
    settings.parse_settings(path);

    QVPNLayers layers{};
    settings.apply_strategy(std::move(layers));

    QVPNClient vpn_client(settings);
    vpn_client.init_vpn();
    vpn_client.add_outgoing_traffic_filter(vpn_client.ipv4() && vpn_client.tcp());
    vpn_client.add_incoming_traffic_filter(vpn_client.ipv4() && vpn_client.tcp());
    // TODO: Почему-то ломается && vpn_client.udp(), возможно из-за wsl?
    //vpn_client.add_outgoing_traffic_filter(vpn_client.ipv4() && vpn_client.tcp() && vpn_client.udp());
    //vpn_client.add_incoming_traffic_filter(vpn_client.ipv4() && vpn_client.tcp() && vpn_client.udp());
    //vpn_client.add_outgoing_traffic_filter(vpn_client.ipv4() && (vpn_client.tcp() || vpn_client.udp()));
    //vpn_client.add_incoming_traffic_filter(vpn_client.ipv4() && (vpn_client.tcp() || vpn_client.udp()));

    vpn_client.start_vpn_client();
    std::cin.get();
    return 0;
}