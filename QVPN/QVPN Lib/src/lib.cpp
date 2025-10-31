#include "lib.hpp"
#include <sstream>

QVPN::Core::IPv4Address::IPv4Address()
{
}

QVPN::Core::IPv4Address::IPv4Address(BaseTypes::UInt data)
{
    UByte first = data >> 24 & 0xFF;
    UByte second = data >> 16 & 0xFF;
    UByte third = data >> 8 & 0xFF;
    UByte four = data & 0xFF;
    ip_ = { first, second, third, four };
}

QVPN::Core::IPv4Address::IPv4Address(UByte first, UByte second, UByte third, UByte four)
    : ip_{first, second, third, four}
{
}

QVPN::Core::IPv4Address::IPv4Address(const IPv4Address& other)
{
    std::copy(other.ip_.begin(), other.ip_.end(), ip_.begin());
}

QVPN::Core::IPv4Address::IPv4Address(IPv4Address&& other)
{
    ip_ = std::exchange(other.ip_, {});
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

QVPN::Core::IPv4Address::UByte QVPN::Core::IPv4Address::operator[](int elem) const
{
    return ip_[elem];
}

std::array<QVPN::Core::IPv4Address::UByte, 4> QVPN::Core::IPv4Address::to_bytes() const
{
    return ip_;
}

std::string QVPN::Core::IPv4Address::to_string() const
{
    std::stringstream ip;
    ip << (int)ip_[0] << "." << (int)ip_[1] << "." << (int)ip_[2] << "." << (int)ip_[3];
    return ip.str();

}

QVPN::Core::BaseTypes::UInt QVPN::Core::IPv4Address::to_uint() const
{
    return (ip_[0] << 24 | ip_[1] << 16 | ip_[2] << 8 | ip_[3]);
}

QVPN::Core::IPv4Address::~IPv4Address()
{
}
