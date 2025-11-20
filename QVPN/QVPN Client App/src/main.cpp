#include <qvpn_lib.hpp>
#include <iostream>
#include <bitset>
//#include <pcap_ext.hpp>
#include <wintun_ext.hpp>
#include <windivert.h>
//#include <windivert_ext.hpp>
#include <qvpn_api.h>

#include <winsock2.h>
#include <ws2tcpip.h>


#include <qvpn_structures.hpp>
#include <cstdint>
#include <vector>
#include <algorithm>
#pragma comment(lib, "Ws2_32.lib")


#pragma comment(lib, "windivert.lib")

//using PcapDriver = QVPN::Core::AdapterDriver<QVPN::PcapExt::PcapNetDriver>;
using WinTunAdapterDriver = QVPN::Core::AdapterDriver<QVPN::WinTunExt::WinTunDriver>;
using TrafficFilter = QVPN::Core::TrafficFilter_<QVPN::WinDivertExt::WinDivertTrafficFilter>;


void test(std::string_view t) {
    std::cout << t << std::endl;
}
using UByte = unsigned char;
using UShort = unsigned short;

using TLSSupVerExt = QVPN::Core::DataStructures::TLSSupportedVersionsExtensionLittleEndian;
using TLSExtensionLittleEndian = QVPN::Core::DataStructures::TLSExtensionLittleEndian;
using TLSExtensionsLittleEndian = QVPN::Core::DataStructures::TLSExtensionsLittleEndian;
using TLSDefaultGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultGenerationStrategy;
using SupVerIter = QVPN::Core::DataStructures::SupVerIter;

using TLSClientHello = QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian;

int main()
{
    TLSDefaultGenStrategy gen_strategy;
    /*
    using TLSExtWrapper = QVPN::Core::DataStructures::TLSExtensionWrapper<TLSExtensionLittleEndian, TLSSupVerExt, UShort, std::pair<SupVerIter, SupVerIter>>;

    
    UShort sup_ver_length = gen_strategy.get_supported_versions_length();
    auto sup_versions = gen_strategy.get_supported_versions();
    std::pair<SupVerIter, SupVerIter> sup_versions_iters = std::pair<SupVerIter, SupVerIter>(sup_versions.begin(), sup_versions.end());

    TLSExtWrapper ex1( std::move(sup_ver_length), std::move(sup_versions_iters));
    TLSExtWrapper ex2( std::move(sup_ver_length), std::move(sup_versions_iters));

    //TLSExtensionsLittleEndian exts;
    auto test_obj = TLSExtensionsLittleEndian::generate_object<TLSExtWrapper, TLSExtWrapper>(ex1, ex2);
    */

    auto client_hello = TLSClientHello::generate_object<>(gen_strategy);
    QVPN::WinDivertExt::WinDivertTrafficFilter filter;

    test(!filter.ipv4() && filter.tcp() && filter.udp());

    QVPN::Core::IPv4Address ip4(1, 2, 3, 4);

    test(!filter.source(ip4));

    std::cout << ip4.to_string() << std::endl;
    
    QVPN::VPNClient vpn;
    //vpn.create_adapter_ipv4();
    //vpn.capture_adapter();

    /*
    // Инициализация WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Ошибка инициализации WinSock.\n";
        return 1;
    }

    // Создаем UDP-сокет
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Ошибка создания сокета: " << WSAGetLastError() << '\n';
        WSACleanup();
        return 1;
    }
    
    struct sockaddr_in local_address;
    memset(&local_address, 0, sizeof(local_address)); // очищаем структуру

    local_address.sin_family = AF_INET;              // Семейство протоколов (IPv4)
    local_address.sin_port = htons(1212);      // Ваш выбранный порт (сетевой порядок байтов)
    local_address.sin_addr.s_addr = inet_addr("192.168.50.25"); // Адрес, с которого будут отправляться данные

    if (bind(sock, (const struct sockaddr*)&local_address, sizeof(local_address)) == -1) {
        perror("Ошибка привязки");
        exit(EXIT_FAILURE);
    }

    // Заполняем структуру адреса
    sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(12345);      // Порт назначения
    inet_pton(AF_INET, "8.8.8.8", &destAddr.sin_addr);  // Адрес назначения (локальная машина)

    // Данные для отправки
    const char* message = "Привет, мир!";

    // Отправляем данные
    int result = sendto(sock, message, strlen(message), 0, (sockaddr*)&destAddr, sizeof(destAddr));
    if (result == SOCKET_ERROR) {
        std::cerr << "Send error: " << WSAGetLastError() << '\n';
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "Данные успешно отправлены!\n";

    // Освобождаем ресурсы
    closesocket(sock);
    WSACleanup();
    */
    vpn.init_vpn();
    vpn.add_incoming_traffic_filter(filter.ipv4() && filter.tcp());
    vpn.add_outgoing_traffic_filter(filter.ipv4() && filter.tcp());
    vpn.start_vpn_client();

    /*
    PcapDriver driver;
    auto d_list = driver.get_adapters_list();
    for (const auto& it : *d_list)
    {
        std::cout << it.get_name() << "  " << it.get_desc() << std::endl;
    }
    system("chcp 1251");
    auto a = d_list->get_default_adapter<AdapterCriteria>();
    std::cout << a->get_friendly_name() << std::endl;
    driver.capture_adapter(a->get_friendly_name());
    */
    /*
    for (size_t i = 0; i < 10; i++)
    {
        std::cout << (t << i) << std::endl;
    }
    std::cout << std::endl << std::endl;
    std::cout << std::bitset<sizeof(unsigned long long) * 8>(QVPN::Core::DataStructures::AdapterFlags::DdnsEnabled) << std::endl;
    std::cout << std::bitset<sizeof(unsigned long long) * 8>(QVPN::Core::DataStructures::AdapterFlags::RegisterAdapterSuffix) << std::endl;
    std::cout << std::bitset<sizeof(unsigned long long) * 8>(QVPN::Core::DataStructures::AdapterFlags::DhcpvEnabled) << std::endl;
    std::cout << std::bitset<sizeof(unsigned long long) * 8>(QVPN::Core::DataStructures::AdapterFlags::ReceiveOnly) << std::endl;
    std::cout << std::bitset<sizeof(unsigned long long) * 8>(QVPN::Core::DataStructures::AdapterFlags::NoMulticast) << std::endl;
    std::cout << std::bitset<sizeof(unsigned long long) * 8>(QVPN::Core::DataStructures::AdapterFlags::Ipv6OtherStatefulConfig) << std::endl;
    std::cout << std::bitset<sizeof(unsigned long long) * 8>(QVPN::Core::DataStructures::AdapterFlags::NetbiosOverTcpipEnabled) << std::endl;
    std::cout << std::bitset<sizeof(unsigned long long) * 8>(QVPN::Core::DataStructures::AdapterFlags::Ipv4Enabled) << std::endl;
    std::cout << std::bitset<sizeof(unsigned long long) * 8>(QVPN::Core::DataStructures::AdapterFlags::Ipv6Enabled) << std::endl;
    std::cout << std::bitset<sizeof(unsigned long long) * 8>(QVPN::Core::DataStructures::AdapterFlags::Ipv6ManagedAddressConfigurationSupported) << std::endl
    */
    std::cin.get();
    return 0;
}