#include "wintun_ext.hpp"
#include <iostream>
#include <winsock2.h>
#include <netioapi.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <WS2tcpip.h>


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


DWORD ConvertIpv4StringToPrefix(const char* ipCidrString, IP_ADDRESS_PREFIX* outPrefix) {
    if (!ipCidrString || !outPrefix) return ERROR_INVALID_PARAMETER;

    // Копируем строку, так как inet_pton не умеет работать с CIDR
    char buffer[64];
    strncpy_s(buffer, ipCidrString, _TRUNCATE);

    // Разделяем строку по '/'
    char* ipPart = buffer;
    char* maskPart = strchr(buffer, '/');
    if (!maskPart) {
        return ERROR_INVALID_PARAMETER;
    }
    *maskPart++ = '\0'; // Заменяем '/' на '\0' для разделения частей

    // Преобразуем IP-адрес
    outPrefix->Prefix.si_family = AF_INET;
    if (inet_pton(AF_INET, ipPart, &outPrefix->Prefix.Ipv4.sin_addr) != 1) {
        return ERROR_INVALID_PARAMETER;
    }

    // Преобразуем длину маски (например, 24) в число
    int maskLength = atoi(maskPart);
    if (maskLength < 0 || maskLength > 32) {
        return ERROR_INVALID_PARAMETER;
    }
    outPrefix->PrefixLength = (UINT8)maskLength;

    return NO_ERROR;
}


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
    QVPN::Core::IPv4Address address(100, 64, 0, 0);
    create_adapter_ipv4("QVPN Adapter", "Quiet and fast", address);
    
}

void QVPN::WinTunExt::WinTunDriver::create_adapter_ipv4(std::string_view a_name, std::string_view a_desc, const QVPN::Core::IPv4Address& address)
{
    QVPN::WinTunExt::WinTunDriver::AdapterHandle_t adapter;
    int try_numbers = 20;
    bool trying = true;
    std::wstring adapter_name(a_name.begin(), a_name.end());
    std::wstring adapter_desc(a_desc.begin(), a_desc.end());
    while (trying && try_numbers-- > 0)
    {
        adapter = WintunCreateAdapter(adapter_name.c_str(), adapter_desc.c_str(), NULL);
        if (!adapter) {
            auto LastError = GetLastError();
            std::cout << "Error while creating adapter. Error №" << LastError << std::endl;
            continue;
        }
        trying = false;
    }

    DWORD LastError = 0;
    NET_LUID luid;
    WintunGetAdapterLUID(adapter, &luid);
  
    ULONG ifIndex;
    if (ConvertInterfaceLuidToIndex(&luid, &ifIndex) != NO_ERROR) {
        printf("Failed to convert luid to index: %lu\n", LastError);
    }

    MIB_IPFORWARD_ROW2 routeRow;
    InitializeIpForwardEntry(&routeRow);

    // 2. Указываем интерфейс для маршрута
    routeRow.InterfaceLuid = luid;

    // 3. Настраиваем префикс назначения (сеть, куда направляем трафик)
    //    Пример: "192.168.1.0/24" или "0.0.0.0/0" для шлюза по умолчанию
    if (ConvertIpv4StringToPrefix("0.0.0.0/0", &routeRow.DestinationPrefix) != NO_ERROR) {
        std::cerr << "Invalid destination prefix format." << std::endl;
    }

    // 4. Настраиваем следующий шлюз (Next Hop) — адрес на вашем TUN-адаптере
    //    Например, для маршрута по умолчанию это может быть IP самого TUN-адаптера
    routeRow.NextHop.si_family = AF_INET; // Для IPv6 используйте AF_INET6
    if (inet_pton(AF_INET, address.to_string().c_str(), &routeRow.NextHop.Ipv4.sin_addr) != 1) {
        std::cerr << "Invalid next-hop address format." << std::endl;
    }

    // 5. Настраиваем метрику маршрута (чем меньше, тем выше приоритет)
    routeRow.Metric = 0;

    // 6. Указываем протокол, добавляющий маршрут. Для статических маршрутов используем MIB_IPPROTO_NETMGMT
    routeRow.Protocol = MIB_IPPROTO_NETMGMT;

    // 7. Добавляем маршрут в таблицу
    DWORD dwRet = CreateIpForwardEntry2(&routeRow);
    if (dwRet == NO_ERROR) {
        std::cout << "Route added successfully." << std::endl;
    }
    else if (dwRet == ERROR_OBJECT_ALREADY_EXISTS) {
        std::cout << "Route already exists." << std::endl;
    }
    else {
        std::cerr << "Failed to add route. Error: " << dwRet << std::endl;
    }


    MIB_IPINTERFACE_ROW adapter_data = { 0 };
    InitializeIpInterfaceEntry(&adapter_data);
    adapter_data.Family = AF_INET;
    WintunGetAdapterLUID(adapter, &adapter_data.InterfaceLuid);
    adapter_data.Metric = 0; //
    adapter_data.UseAutomaticMetric = false;
    adapter_data.SitePrefixLength = 0;
    LastError = SetIpInterfaceEntry(&adapter_data);
    if (LastError != NO_ERROR) {
        printf("Failed to set metric. Error %d\n", LastError);
    }
    
    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl(address.to_uint());
    WintunGetAdapterLUID(adapter, &AddressRow.InterfaceLuid);
    AddressRow.OnLinkPrefixLength = 10;
    AddressRow.DadState = IpDadStatePreferred;
    LastError = CreateUnicastIpAddressEntry(&AddressRow);

    if (LastError)
    {
        std::cout << "Error while creating unicast ip address. Error #" << LastError << std::endl;
    }
    adapter_ = QVPN::WinTunExt::WinTunDriver::Adapter_t(a_name, a_desc, address, adapter); // ???
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
