#include "lib.hpp"

QVPN::Core::IPv4Address::IPv4Address()
{
}

QVPN::Core::IPv4Address::IPv4Address(UByte first, UByte second, UByte third, UByte four)
{
}

QVPN::Core::IPv4Address::IPv4Address(const IPv4Address& other)
{
}

QVPN::Core::IPv4Address::IPv4Address(IPv4Address&& other)
{
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(const IPv4Address& other)
{
    // TODO: вставьте здесь оператор return
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(IPv4Address&& other)
{
    // TODO: вставьте здесь оператор return
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(const std::array<UByte, 4>& other)
{
    // TODO: вставьте здесь оператор return
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(std::array<UByte, 4>&& other)
{
    // TODO: вставьте здесь оператор return
}

QVPN::Core::IPv4Address::UByte QVPN::Core::IPv4Address::operator[](size_t elem)
{
    return ip_[elem];
}

QVPN::Core::IPv4Address::~IPv4Address()
{
}
