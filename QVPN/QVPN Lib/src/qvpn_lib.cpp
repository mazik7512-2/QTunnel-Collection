#include "qvpn_lib.hpp"
#include <sstream>
#include <qvpn_defs.hpp>
#include <fstream>
#include <random>
#include <qvpn_tools.hpp>


QVPN::Core::IPv4Address::IPv4Address()
{
}

QVPN::Core::IPv4Address::IPv4Address(AddrBytes_t data)
{
    ip_[0] = data[0];
    ip_[1] = data[1];
    ip_[2] = data[2];
    ip_[3] = data[3];
}

QVPN::Core::IPv4Address::IPv4Address(std::string_view data)
{
    auto vec = Tools::parse_net_addr(data);
    std::copy(vec.begin(), vec.end(), ip_.begin());
}

QVPN::Core::IPv4Address::IPv4Address(std::initializer_list<UByte> list)
{
    std::copy(list.begin(), list.end(), ip_.begin());
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

bool QVPN::Core::IPv4Address::operator==(const IPv4Address& other) const
{
    return to_uint() == other.to_uint();
}

consteval QVPN::Core::NetProtocol QVPN::Core::IPv4Address::get_addr_family()
{
    return NetProtocol::IPv4;
}

consteval size_t QVPN::Core::IPv4Address::get_addr_size()
{
    return 4;
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


// ipv6

QVPN::Core::IPv6Address::IPv6Address()
{
}

QVPN::Core::IPv6Address::IPv6Address(AddrBytes_t data)
{
    std::copy(data.begin(), data.end(), ip_.begin());
}

QVPN::Core::IPv6Address::IPv6Address(std::initializer_list<UByte> list)
{
    std::copy(list.begin(), list.end(), ip_.begin());
}

QVPN::Core::IPv6Address::IPv6Address(UByte data[16])
{
    std::copy(data, data + 16, ip_.begin());
}

QVPN::Core::IPv6Address::IPv6Address(std::string_view data)
{
    auto vec = Tools::parse_net_addr(data);
    std::copy(vec.begin(), vec.end(), ip_.begin());
}

consteval QVPN::Core::NetProtocol QVPN::Core::IPv6Address::get_addr_family()
{
    return NetProtocol::IPv6;
}

consteval size_t QVPN::Core::IPv6Address::get_addr_size()
{
    return 6;
}

QVPN::Core::IPv6Address::AddrBytes_t QVPN::Core::IPv6Address::to_bytes() const
{
    return ip_;
}

std::string QVPN::Core::IPv6Address::to_string() const
{
    std::stringstream ip;
    for (size_t i = 0; i < ip_.size(); i++)
    {
        ip << static_cast<int>(ip_[i]) << ".";
    }
    auto temp = ip.str();
    auto str = temp.substr(0, temp.size() - 2);
    str.append("\0");
    return str;
}

QVPN::Core::IPv6Address::AddrInt_t QVPN::Core::IPv6Address::to_uint() const
{
    return ip_;
}

QVPN::Core::QVPNWhitelistElement::QVPNWhitelistElement()
    : host_(""), priority_(QVPNWhitelistElement::default_priority)
{
}

QVPN::Core::QVPNWhitelistElement::QVPNWhitelistElement(std::string_view host, int priority)
    : host_(host), priority_(priority)
{
}

void QVPN::Core::QVPNWhitelistElement::set_host(std::string_view host)
{
    host_ = host;
}

void QVPN::Core::QVPNWhitelistElement::set_priority(int priority)
{
    priority_ = priority;
}

std::string_view QVPN::Core::QVPNWhitelistElement::get_host() const
{
    return host_;
}

int QVPN::Core::QVPNWhitelistElement::get_priority() const
{
    return priority_;
}

QVPN::Core::QVPNWhitelistDefaultStrategy::QVPNWhitelistDefaultStrategy()
    : map_{}
{
}

QVPN::Core::QVPNWhitelistElementView QVPN::Core::QVPNWhitelistDefaultStrategy::get_host_by_params(const StrategyFilter& param)
{
    return map_[param];
}

QVPN::Core::QVPNWhitelistElementView::QVPNWhitelistElementView(const QVPNWhitelistElement& elem)
    : host_(elem.get_host()), priority_(elem.get_priority())
{
}

std::string_view QVPN::Core::QVPNWhitelistElementView::get_host() const
{
    return host_;
}

int QVPN::Core::QVPNWhitelistElementView::get_priority() const
{
    return priority_;
}

QVPN::Core::QVPNWhitelist::QVPNWhitelist()
    : whitelist_{}
{
}

QVPN::Core::QVPNWhitelist::QVPNWhitelist(std::string_view path)
    : QVPNWhitelist()
{
    parse_whitelist(path);
}

void QVPN::Core::QVPNWhitelist::parse_whitelist(std::string_view path)
{
    std::ifstream wlist(path.data());
    std::string line;

    if (!wlist.is_open())
        return;

    std::string host;
    int priority;
    while (wlist >> host >> priority)
        whitelist_.emplace_back(host, priority);
    
    wlist.close();
}

std::string_view QVPN::Core::QVPNWhitelist::get_random_host() const
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, whitelist_.size());

    return whitelist_[dist(gen)].get_host();
}

std::string_view QVPN::Core::QVPNWhitelist::get_host(size_t i) const
{
    return whitelist_[i].get_host();
}

size_t QVPN::Core::QVPNWhitelist::get_size() const
{
    return whitelist_.size();
}

// IP Address

QVPN::Core::NetAddr::NetAddr()
{
}

QVPN::Core::NetAddr::NetAddr(AddrBytes_t data)
{
    std::copy(data.cbegin(), data.cend(), std::back_inserter(ip_));
}

QVPN::Core::NetAddr::NetAddr(std::initializer_list<UByte> list)
{
    std::copy(list.begin(), list.end(), std::back_inserter(ip_));
}

QVPN::Core::NetAddr::NetAddr(const IPv4Address& data)
{
    auto bytes = data.to_bytes();
    std::copy(bytes.cbegin(), bytes.cend(), std::back_inserter(ip_));
}

QVPN::Core::NetAddr::NetAddr(const IPv6Address& data)
{
    auto bytes = data.to_bytes();
    std::copy(bytes.cbegin(), bytes.cend(), std::back_inserter(ip_));
}

QVPN::Core::NetAddr::NetAddr(std::string_view data)
{
    ip_ = Tools::parse_net_addr(data);
}

size_t QVPN::Core::NetAddr::get_addr_size()
{
    return ip_.size();
}

QVPN::Core::NetProtocol QVPN::Core::NetAddr::get_addr_family() const
{
    if (ip_.size() == 4)
        return NetProtocol::IPv4;
    else if (ip_.size() == 16)
        return NetProtocol::IPv6;
    return NetProtocol::NET_UNDEFINED;
}

QVPN::Core::IPv4Address QVPN::Core::NetAddr::to_ipv4() const
{
    std::array<UByte, 4> data { ip_[0], ip_[1], ip_[2], ip_[3]};
    return IPv4Address(data);
}

QVPN::Core::IPv6Address QVPN::Core::NetAddr::to_ipv6() const
{
    std::array<UByte, 16> data{};
    std::copy(ip_.cbegin(), ip_.cbegin() + 16, data.begin());
    return IPv6Address(data);
}

QVPN::Core::BaseTypes::UByte QVPN::Core::NetAddr::operator[](int elem) const
{
    return ip_[elem];
}

QVPN::Core::NetAddr::AddrBytes_t QVPN::Core::NetAddr::to_bytes() const
{
    return ip_;
}

std::string QVPN::Core::NetAddr::to_string() const
{
    std::stringstream ip;
    for (size_t i = 0; i < ip_.size(); i++)
    {
        ip << static_cast<int>(ip_[i]) << ".";
    }
    auto temp = ip.str();
    auto str = temp.substr(0, temp.size() - 1);
    str.append("\0");
    return str;
}

QVPN::Core::NetAddr::AddrInt_t QVPN::Core::NetAddr::to_uint() const
{
    return ip_;
}

bool QVPN::Core::NetAddr::operator==(const NetAddr& other) const
{
    for (size_t i = 0; i < ip_.size(); i++)
    {
        if (ip_[i] != other.ip_[i])
            return false;
    }
    return true;
}

// QVPN Socket Data

std::string QVPN::Core::QVPNSocketData::to_string() const
{
    std::stringstream ss{};

    ss << "(" << transport_proto << ") " << local_addr.to_string() << ":" << local_port << "-" << remote_addr.to_string() << ":" << remote_port;

    auto str = ss.str();
    return str;
}

QVPN::Core::QVPNSocketSettings::QVPNSocketSettings(bool ip_data)
{
    ip_header_ = ip_data;
}

bool QVPN::Core::QVPNSocketSettings::ip_header() const
{
    return ip_header_;
}
