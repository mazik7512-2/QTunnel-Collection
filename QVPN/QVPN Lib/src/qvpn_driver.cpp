#include <qvpn_driver.hpp>


using UByte = QVPN::Core::BaseTypes::UByte;


QVPN::Core::QVPNAuthenticationSettings::QVPNAuthenticationSettings(QVPN_Crypto method, std::string key)
{
    key_ = key;
    crypto_method_ = method;
}

std::string_view QVPN::Core::QVPNAuthenticationSettings::get_key() const
{
    return key_;
}

QVPN::Core::QVPN_Crypto QVPN::Core::QVPNAuthenticationSettings::get_crypto_method() const
{
    return crypto_method_;
}




