#include <qvpn_socket_filters.hpp>
#include <WinSock2.h>


#ifdef QVPN_BPF_CLASSIC
/*
void QVPN::NetTools::QVPN_SocketFilter::ipv4()
{
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0));
    code.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0));
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 1, 0));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));
}

void QVPN::NetTools::QVPN_SocketFilter::ipv6()
{
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0));
    code.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0));
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x60, 1, 0));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));
}

void QVPN::NetTools::QVPN_SocketFilter::net_ver(UByte net)
{
    auto net_ = net << 4;
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0));
    code.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0));
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, net_, 1, 0));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));
}

void QVPN::NetTools::QVPN_SocketFilter::src(const NetAddr& addr)
{

    // Проверка версии IP
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0));
    code.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0));
    // Если версия 4 -> перейти к обработке IPv4 (инструкция 4)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 2, 0));
    // Если версия 6 -> перейти к обработке IPv6 (инструкция 6)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x60, 4, 0));
    // Иначе reject
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));

    // ipv4
    code.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 12));        // src IP
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(addr.to_uint()), 1, 0)); //  в network byte order
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0)); // reject


    // ipv6
    auto bytes = addr.to_bytes();
    auto size = bytes.size();
    for (size_t i = 0; i < size; i++)
    {
        code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 8));   // первые 32 бита src
        code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, bytes[i], 1, 0));
        code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));
    }
}

void QVPN::NetTools::QVPN_SocketFilter::dst(const NetAddr& addr)
{
    // Проверка версии IP
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0));
    code.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0));
    // Если версия 4 -> перейти к обработке IPv4 (инструкция 4)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 2, 0));
    // Если версия 6 -> перейти к обработке IPv6 (инструкция 6)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x60, 4, 0));
    // Иначе reject
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));

    // ipv4
    code.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 16));        // src IP
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(addr.to_uint()), 1, 0)); //  в network byte order
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0)); // reject


    // ipv6
    auto bytes = addr.to_bytes();
    auto size = bytes.size();
    for (size_t i = 0; i < size; i++)
    {
        code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 24));   // первые 32 бита src
        code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, bytes[i], 1, 0));
        code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));
    }
}

void QVPN::NetTools::QVPN_SocketFilter::src_port(UShort port)
{

}

void QVPN::NetTools::QVPN_SocketFilter::dst_port(UShort port)
{

}

void QVPN::NetTools::QVPN_SocketFilter::tcp()
{
    // Проверка версии IP
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0));
    code.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0));
    // Если версия 4 -> перейти к обработке IPv4 (инструкция 4)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 2, 0));
        // Если версия 6 -> перейти к обработке IPv6 (инструкция 6)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x60, 4, 0));
        // Иначе reject
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));

        // === Обработка IPv4 ===
        // Загружаем protocol (смещение 9)
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9));
        // Проверяем TCP (6) или UDP (17)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 4, 0)); // если TCP -> accept
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0)); // иначе reject (для IPv4)

        // === Обработка IPv6 ===
        // Загружаем Next Header (смещение 6)
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6));
        // Проверяем TCP/UDP
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 1, 0));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));
}

void QVPN::NetTools::QVPN_SocketFilter::udp()
{
    // Проверка версии IP
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0));
    code.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0));
    // Если версия 4 -> перейти к обработке IPv4 (инструкция 4)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 2, 0));
    // Если версия 6 -> перейти к обработке IPv6 (инструкция 6)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x60, 4, 0));
    // Иначе reject
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));

    // === Обработка IPv4 ===
    // Загружаем protocol (смещение 9)
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9));
    // Проверяем TCP (6) или UDP (17)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 4, 0)); // если UDP -> accept
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0)); // иначе reject (для IPv4)

    // === Обработка IPv6 ===
    // Загружаем Next Header (смещение 6)
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6));
    // Проверяем TCP/UDP
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 1, 0));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));
}

void QVPN::NetTools::QVPN_SocketFilter::custom_protocol(UByte proto)
{
    // Проверка версии IP
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0));
    code.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0));
    // Если версия 4 -> перейти к обработке IPv4 (инструкция 4)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 2, 0));
    // Если версия 6 -> перейти к обработке IPv6 (инструкция 6)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x60, 4, 0));
    // Иначе reject
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));

    // === Обработка IPv4 ===
    // Загружаем protocol (смещение 9)
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9));
    // Проверяем TCP (6) или UDP (17)
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, proto, 4, 0)); // если UDP -> accept
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0)); // иначе reject (для IPv4)

    // === Обработка IPv6 ===
    // Загружаем Next Header (смещение 6)
    code.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6));
    // Проверяем TCP/UDP
    code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, proto, 1, 0));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0));
}



QVPN::NetTools::QVPN_SocketFilter::SocketFilter_t QVPN::NetTools::QVPN_SocketFilter::get_filters()
{
    code.push_back(BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF));
    SocketFilter_t bpf_prog = {
        .len = code.size(),
        .filter = code.data()
    };
    return bpf_prog;
}*/
#endif

QVPN::NetTools::QVPN_SocketFilter::QVPN_SocketFilter(const QVPN::Core::QVPNSocketData& s_data)
{
    filter_.net_proto = static_cast<UByte>(s_data.net_proto);
    filter_.transport_proto = static_cast<UByte>(s_data.transport_proto);

    switch (s_data.net_proto)
    {
    case QVPN::Core::NetProtocol::IPv4:
        filter_.src_ip = s_data.local_addr.to_uint();
        filter_.dst_ip = s_data.remote_addr.to_uint();
        break;
    case QVPN::Core::NetProtocol::IPv6:
        break;
    default:
        break;
    }

    filter_.src_port = s_data.local_port;
    filter_.dst_port = s_data.remote_port;
}

QVPN::NetTools::QVPN_SocketFilter::QVPN_SocketFilter(const QVPN::Core::QVPNServerSocketData& s_data)
{
    filter_.net_proto = static_cast<UByte>(s_data.net_proto);
    filter_.transport_proto = static_cast<UByte>(s_data.transport_proto);

    switch (s_data.net_proto)
    {
    case QVPN::Core::NetProtocol::IPv4:
        filter_.src_ip = s_data.server_local_addr.to_uint();
        filter_.dst_ip = s_data.remote_addr.to_uint();
        break;
    case QVPN::Core::NetProtocol::IPv6:
        break;
    default:
        break;
    }

    filter_.src_port = s_data.local_port;
    filter_.dst_port = s_data.remote_port;
}

void QVPN::NetTools::QVPN_SocketFilter::ipv4()
{
    filter_.net_proto = static_cast<UByte>(NetProtocol::IPv4);
}

void QVPN::NetTools::QVPN_SocketFilter::ipv6()
{
    filter_.net_proto = static_cast<UByte>(NetProtocol::IPv6);
}

void QVPN::NetTools::QVPN_SocketFilter::net_ver(UByte net)
{
    filter_.net_proto = net;
}

void QVPN::NetTools::QVPN_SocketFilter::src(const NetAddr& addr)
{
    auto addr_type = addr.get_addr_family();
    switch (addr_type) {
    case NetProtocol::IPv4:
        filter_.src_ip = htonl(addr.to_uint());
        break;
    case NetProtocol::IPv6:
        break;
    default:
        break;
    }
}

void QVPN::NetTools::QVPN_SocketFilter::dst(const NetAddr& addr)
{
    auto addr_type = addr.get_addr_family();
    switch (addr_type) {
    case NetProtocol::IPv4:
        filter_.dst_ip = htonl(addr.to_uint());
        break;
    case NetProtocol::IPv6:
        break;
    default:
        break;
    }
}

void QVPN::NetTools::QVPN_SocketFilter::src_port(UShort port)
{
    filter_.src_port = htons(port);
}

void QVPN::NetTools::QVPN_SocketFilter::dst_port(UShort port)
{
    filter_.dst_port = htons(port);
}

void QVPN::NetTools::QVPN_SocketFilter::tcp()
{
    filter_.transport_proto = static_cast<UByte>(TransportProtocol::TCP);
}

void QVPN::NetTools::QVPN_SocketFilter::udp()
{
    filter_.transport_proto = static_cast<UByte>(TransportProtocol::UDP);
}

void QVPN::NetTools::QVPN_SocketFilter::custom_protocol(UByte proto)
{
    filter_.transport_proto = proto;
}

QVPN::NetTools::QVPN_SocketFilter::SocketFilter_t& QVPN::NetTools::QVPN_SocketFilter::get_filters()
{
    return filter_;
}