#include <lib.hpp>
#include <iostream>
#include <bitset>
//#include <pcap_ext.hpp>
#include <wintun_ext.hpp>
#include <windivert.h>
#include <windivert_ext.hpp>
#include <qvpn_api.h>

#pragma comment(lib, "windivert.lib")

//using PcapDriver = QVPN::Core::AdapterDriver<QVPN::PcapExt::PcapNetDriver>;
using WinTunAdapterDriver = QVPN::Core::AdapterDriver<QVPN::WinTunExt::WinTunDriver>;
using TrafficFilter = QVPN::Core::TrafficFilter_<QVPN::WinDivertExt::WinDivertTrafficFilter>;


void test(std::string_view t) {
    std::cout << t << std::endl;
}




int main()
{
    QVPN::VPNDriver vpn;
    vpn.create_adapter_ipv4();
    

    QVPN::WinDivertExt::WinDivertTrafficFilter filter;

    test(filter.ipv4() && filter.tcp() && filter.udp());

    QVPN::Core::IPv4Address ip4(1, 2, 3, 4);

    test(filter.source(ip4));

    std::cout << ip4.to_string() << std::endl;

    HANDLE hDivert = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);
    if (hDivert != INVALID_HANDLE_VALUE)
    {
        printf("Driver is working correctly.\n");
        WinDivertClose(hDivert);
    }
    else
    {
        printf("Error opening driver.\n");
        return 0;
    }
    WinTunAdapterDriver d;
    d.create_adapter_ipv4();
    d.capture_adapter();
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