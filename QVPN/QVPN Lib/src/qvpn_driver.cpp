#include <qvpn_driver.hpp>


using UByte = QVPN::Core::BaseTypes::UByte;


QVPN::Core::QVPNCryptoSettings::QVPNCryptoSettings(QVPN_Crypto method, std::string key)
{
    key_ = key;
    crypto_method_ = method;
}

void QVPN::Core::QVPNCryptoSettings::set_key(std::string_view key)
{
    key_ = key;
}

void QVPN::Core::QVPNCryptoSettings::set_crypto_method(QVPN_Crypto method)
{
    crypto_method_ = method;
}

std::string_view QVPN::Core::QVPNCryptoSettings::get_key() const
{
    return key_;
}

QVPN::Core::QVPN_Crypto QVPN::Core::QVPNCryptoSettings::get_crypto_method() const
{
    return crypto_method_;
}

QVPN::Core::QVPNAuthSettings::QVPNAuthSettings(std::string_view auth_data)
{
    auth_data_ = auth_data_;
}

void QVPN::Core::QVPNAuthSettings::set_auth_data(std::string_view auth_data)
{
    auth_data_ = auth_data;
}

std::string_view QVPN::Core::QVPNAuthSettings::get_auth_data() const
{
    return auth_data_;
}
