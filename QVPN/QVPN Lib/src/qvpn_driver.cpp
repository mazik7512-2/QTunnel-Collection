#include <qvpn_driver.hpp>
#include <qvpn_structures.hpp>


using UByte = QVPN::Core::BaseTypes::UByte;


QVPN::Core::QVPNAuthenticationSettings::QVPNAuthenticationSettings(std::string key)
{
    key_ = key;
}

std::string_view QVPN::Core::QVPNAuthenticationSettings::get_key() const
{
    return key_;
}




