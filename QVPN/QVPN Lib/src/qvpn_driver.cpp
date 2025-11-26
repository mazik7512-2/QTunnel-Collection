#include <qvpn_driver.hpp>
#include <qvpn_structures.hpp>


using UByte = QVPN::Core::BaseTypes::UByte;


std::variant<QVPN::Core::QVPNConnectionSettings::Ipv4AddressType, QVPN::Core::QVPNConnectionSettings::Ipv6AddressType> QVPN::Core::QVPNConnectionSettings::get_ip_address() const
{
    return addr_;
}

QVPN::Core::BaseTypes::UShort QVPN::Core::QVPNConnectionSettings::get_port() const
{
    return port_;
}


QVPN::Core::QVPNAuthenticationSettings::QVPNAuthenticationSettings(std::string key)
{
    key_ = key;
}

std::string_view QVPN::Core::QVPNAuthenticationSettings::get_key() const
{
    return key_;
}




