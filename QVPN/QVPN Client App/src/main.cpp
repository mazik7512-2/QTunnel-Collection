
#include <iostream>
#include <argparse/argparse.hpp>
#include <qvpn_api.hpp>


using VPNClientSettings = QVPN::VPNClientSettings;
using VPNClient = QVPN::VPNClient;
using VPNLayers = QVPN::VPNLayersStrategy;

int main(int argc, char* argv[])
{

    argparse::ArgumentParser program("QVPN Client App", "0.5");

    program.add_argument("-s", "--settings", "-c", "--config")
        .default_value(std::string("client_settings.json"))
        .help("”кажите путь до файла с настройками (по умолчанию) client_settings.json");
    
    VPNClientSettings settings{};
    std::string path = program.get<std::string>("--settings");
    settings.parse_settings(path);

    VPNLayers layers{};
    settings.apply_strategy(std::move(layers));

    auto addr = settings.get_ip_address();

    VPNClient vpn_client(settings);

    vpn_client.add_outgoing_traffic_filter(vpn_client.ipv4() && vpn_client.tcp() && vpn_client.udp());
    vpn_client.add_incoming_traffic_filter(vpn_client.ipv4() && vpn_client.tcp() && vpn_client.udp());

    vpn_client.start_capture_outgoing_traffic(std::get<VPNClientSettings::Ipv4AddressType>(addr), 1);
    vpn_client.start_capture_incoming_traffic(std::get<VPNClientSettings::Ipv4AddressType>(addr));
    std::cin.get();
    return 0;
}