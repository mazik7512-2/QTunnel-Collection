#include "wintun_ext.hpp"
#include <iostream>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")


static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC* WintunSetLogger;
static WINTUN_START_SESSION_FUNC* WintunStartSession;
static WINTUN_END_SESSION_FUNC* WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC* WintunSendPacket;



QVPN::WinTunExt::WinTunDriver::WinTunDriver()
{
    init_wintun();
}

QVPN::WinTunExt::WinTunDriver::~WinTunDriver()
{
    WintunEndSession(session_);
}

void QVPN::WinTunExt::WinTunDriver::create_adapter_ipv4()
{
    QVPN::Core::IPv4Address address(192, 168, 50, 25);
    create_adapter_ipv4("QVPN Adapter", "Quiet and fast", address);
    
}

void QVPN::WinTunExt::WinTunDriver::create_adapter_ipv4(std::string_view a_name, std::string_view a_desc, const QVPN::Core::IPv4Address& address)
{
    QVPN::WinTunExt::WinTunDriver::AdapterHandle_t adapter;
    GUID ExampleGuid = { 0xdeadbabe, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    int try_numbers = 20;
    bool trying = true;
    std::wstring adapter_name(a_name.begin(), a_name.end());
    std::wstring adapter_desc(a_desc.begin(), a_desc.end());
    while (trying && try_numbers-- > 0)
    {
        adapter = WintunCreateAdapter(adapter_name.c_str(), adapter_desc.c_str(), &ExampleGuid);
        if (!adapter) {
            auto LastError = GetLastError();
            std::cout << "Error while creating adapter. Error ¹" << LastError << std::endl;
            continue;
        }
        trying = false;
    }


    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl(address.to_uint());
    AddressRow.OnLinkPrefixLength = 24;
    AddressRow.DadState = IpDadStatePreferred;
    auto LastError = CreateUnicastIpAddressEntry(&AddressRow);

    if (LastError)
    {
        std::cout << "Error while creating unicast ip address. Error ¹" << LastError << std::endl;
    }

    MIB_IPFORWARDROW row;
    ZeroMemory(&row, sizeof(row));
    row.dwForwardDest = inet_addr("0.0.0.0");     // Destination address
    row.dwForwardMask = inet_addr("0.0.0.0");    // Netmask
    row.dwForwardNextHop = inet_addr("192.168.50.1");// Gateway
    row.dwForwardIfIndex = 0x10;    // Interface index
    row.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;// Route type
    row.dwForwardProto = PROTO_IP_NETMGMT;       // Protocol source
    CreateIpForwardEntry(&row);                  // Add the route

    adapter_ = QVPN::WinTunExt::WinTunDriver::Adapter_t(a_name, a_desc, address, adapter, 0x10); // ???
}


void QVPN::WinTunExt::WinTunDriver::capture_main_adapter()
{
}

void QVPN::WinTunExt::WinTunDriver::close_adapter(Adapter_t& adapter)
{
}

void QVPN::WinTunExt::WinTunDriver::close_all_adapters()
{
}

std::unique_ptr<QVPN::WinTunExt::WinTunDriver::AdapterList_t> QVPN::WinTunExt::WinTunDriver::get_adapters_list() const
{
    return std::unique_ptr<QVPN::WinTunExt::WinTunDriver::AdapterList_t>();
}

void QVPN::WinTunExt::WinTunDriver::main_adapter_loop_handler()
{
    for (;;)
    {
        DWORD IncomingPacketSize;
        BYTE* IncomingPacket = WintunReceivePacket(session_, &IncomingPacketSize);
        if (IncomingPacket)
        {
            std::cout << IncomingPacketSize << std::endl;

            auto packet = (unsigned char*)IncomingPacket;
            QVPN::Core::DataStructures::Ipv4Packet package(IncomingPacket, IncomingPacket + IncomingPacketSize);
            WintunReleaseReceivePacket(session_, IncomingPacket);
        }
        else if (GetLastError() == ERROR_NO_MORE_ITEMS)
            WaitForSingleObject(WintunGetReadWaitEvent(session_), INFINITE);
        else
        {
            std::cout << "fail to read packet" << std::endl;
            break;
        }


    }
}

void QVPN::WinTunExt::WinTunDriver::adapter_loop_handler(Adapter_t& adapter)
{
}

void QVPN::WinTunExt::WinTunDriver::choose_main_adapter(AdapterList_t& adapters)
{
}

void QVPN::WinTunExt::WinTunDriver::init_wintun()
{
    HMODULE Wintun =
        LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Wintun)
    {
        wintun_ = nullptr;
        return;
    }
        
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        wintun_ = nullptr;
        return;
    }
    wintun_ = Wintun;
}

void QVPN::WinTunExt::WinTunDriver::capture_adapter()
{
    session_ = WintunStartSession(adapter_.get_handle(), 0x400000);
}

void QVPN::WinTunExt::WinTunDriver::capture_adapter(std::string_view adapter)
{
    
}

void QVPN::WinTunExt::WinTunDriver::capture_adapter(Adapter_t& adapter)
{
}

std::shared_ptr<const QVPN::WinTunExt::WinTunDriver::Adapter_t> QVPN::WinTunExt::WinTunDriver::get_ipv4_adapter() const
{
    return std::make_shared<const decltype(adapter_)>(adapter_);
}

void QVPN::WinTunExt::WinTunDriver::close_adapter()
{
}
