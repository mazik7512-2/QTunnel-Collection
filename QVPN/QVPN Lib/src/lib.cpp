#include "lib.hpp"
#include <sstream>

QVPN::Core::IPv4Address::IPv4Address()
{
}

QVPN::Core::IPv4Address::IPv4Address(UByte first, UByte second, UByte third, UByte four)
    : ip_{first, second, third, four}
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
    if (this == &other)
        return *this;
    std::copy(other.ip_.begin(), other.ip_.end(), ip_.begin());
    return *this;
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(IPv4Address&& other)
{
    if (this == &other)
        return *this;
    ip_ = std::exchange(other.ip_, {});
    return *this;
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(const std::array<UByte, 4>& other)
{
    std::copy(other.begin(), other.end(), ip_.begin());
    return *this;
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(std::array<UByte, 4>&& other)
{
    ip_ = std::exchange(other, {});
    return *this;
}

QVPN::Core::IPv4Address::UByte QVPN::Core::IPv4Address::operator[](size_t elem)
{
    return ip_[elem];
}

std::unique_ptr<std::array<QVPN::Core::IPv4Address::UByte, 4>> QVPN::Core::IPv4Address::to_bytes()
{
    return std::make_unique<decltype(ip_)>(ip_);
}

std::string QVPN::Core::IPv4Address::to_string()
{
    std::stringstream ip;
    ip << (int)ip_[0] << "." << (int)ip_[1] << "." << (int)ip_[2] << "." << (int)ip_[3];
    return ip.str();

}

QVPN::Core::IPv4Address::~IPv4Address()
{
}
