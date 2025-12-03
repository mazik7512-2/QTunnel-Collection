#include "qvpn_lib.hpp"
#include <sstream>
#include <qvpn_defs.hpp>


QVPN::Core::IPv4Address::IPv4Address()
{
}

QVPN::Core::IPv4Address::IPv4Address(AddrInt_t data)
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

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(const AddrBytes_t& other)
{
    std::copy(other.begin(), other.end(), ip_.begin());
    return *this;
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(AddrBytes_t&& other)
{
    ip_ = std::exchange(other, {});
    return *this;
}

QVPN::Core::IPv4Address::UByte QVPN::Core::IPv4Address::operator[](int elem) const
{
    return ip_[elem];
}

constexpr int QVPN::Core::IPv4Address::get_addr_family()
{
    return AF_INET;
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

// Net Addr

QVPN::Core::BaseTypes::UByte QVPN::Core::NetAddr::operator[](int elem) const
{
    return addr_[elem];
}

constexpr int QVPN::Core::NetAddr::get_addr_family()
{
    return 0;
}

QVPN::Core::NetAddr::AddrBytes_t QVPN::Core::NetAddr::to_bytes() const
{
    return addr_;
}

std::string QVPN::Core::NetAddr::to_string() const
{
    std::stringstream ip;
    for (size_t i = 0; i < addr_.size(); i++)
    {
        ip << static_cast<int>(addr_[i]) << ".";
    }
    auto temp = ip.str();
    auto str = temp.substr(0, temp.size() - 2);
    str.append("\0");
    return str;
}

QVPN::Core::NetAddr::AddrInt_t QVPN::Core::NetAddr::to_uint() const
{
    std::pair<BaseTypes::ULong, BaseTypes::ULong> res {0ull, 0ull};

    for (size_t i = 0; i < addr_.size() / 2; i++)
    {
        res.first += addr_[i];
    }

    for (size_t i = addr_.size() / 2; i < addr_.size(); i++)
    {
        res.second += addr_[i];
    }
    return res;
}
