#include <qvpn_driver.hpp>


using UByte = QVPN::Core::BaseTypes::UByte;


QVPN::Core::QVPNClientCryptoSettings::QVPNClientCryptoSettings(QVPN_Crypto method, std::string key)
{
    key_ = key;
    crypto_method_ = method;
}

void QVPN::Core::QVPNClientCryptoSettings::set_key(std::string_view key)
{
    key_ = key;
}

void QVPN::Core::QVPNClientCryptoSettings::set_crypto_method(QVPN_Crypto method)
{
    crypto_method_ = method;
}

std::string_view QVPN::Core::QVPNClientCryptoSettings::get_key() const
{
    return key_;
}

QVPN::Core::QVPN_Crypto QVPN::Core::QVPNClientCryptoSettings::get_crypto_method() const
{
    return crypto_method_;
}

QVPN::Core::QVPNClientAuthSettings::QVPNClientAuthSettings(std::string_view auth_data)
{
    auth_data_ = auth_data_;
}

void QVPN::Core::QVPNClientAuthSettings::set_auth_data(std::string_view auth_data)
{
    auth_data_ = auth_data;
}

std::string_view QVPN::Core::QVPNClientAuthSettings::get_auth_data() const
{
    return auth_data_;
}

// QVPN Net Settings

void QVPN::Core::QVPNNetSettings::add_addr(const Ipv4AddressType& addr, UShort port)
{
    data_.emplace_back(addr, port);
}

void QVPN::Core::QVPNNetSettings::add_addr(const Ipv6AddressType& addr, UShort port)
{
    data_.emplace_back(addr, port);
}

std::pair<QVPN::Core::QVPNNetSettings::DataIterator_t, QVPN::Core::QVPNNetSettings::DataIterator_t> QVPN::Core::QVPNNetSettings::get_addrs() const
{
    return std::pair<DataIterator_t, DataIterator_t>(data_.cbegin(), data_.cend());
}

// QVPN Crypto Server Settings

void QVPN::Core::QVPNServerCryptoSettings::add_crypto_method(QVPN_Crypto crypto)
{
    data_.push_back(crypto);
}

std::pair<QVPN::Core::QVPNServerCryptoSettings::DataIterator_t, QVPN::Core::QVPNServerCryptoSettings::DataIterator_t> QVPN::Core::QVPNServerCryptoSettings::get_supported_crypto() const
{
    return std::pair<DataIterator_t, DataIterator_t>(data_.cbegin(), data_.cend());
}

// QVPN Database settings

void QVPN::Core::QVPNDatabaseSettings::set_db_host(std::string_view path)
{
    db_host = path;
}

void QVPN::Core::QVPNDatabaseSettings::set_db_user(std::string_view user)
{
    db_user = user;
}

void QVPN::Core::QVPNDatabaseSettings::set_db_password(std::string_view pass)
{
    db_password = pass;
}

void QVPN::Core::QVPNDatabaseSettings::set_db_name(std::string_view name)
{
    db_name = name;
}

void QVPN::Core::QVPNDatabaseSettings::set_db_port(UShort port)
{
    db_port = port;
}

std::string_view QVPN::Core::QVPNDatabaseSettings::get_db_host() const
{
    return std::string_view(db_host);
}

std::string_view QVPN::Core::QVPNDatabaseSettings::get_db_user() const
{
    return std::string_view(db_user);
}

std::string_view QVPN::Core::QVPNDatabaseSettings::get_db_password() const
{
    return std::string_view(db_password);
}

std::string_view QVPN::Core::QVPNDatabaseSettings::get_db_name() const
{
    return std::string_view(db_name);
}

QVPN::Core::BaseTypes::UShort QVPN::Core::QVPNDatabaseSettings::get_db_port() const
{
    return db_port;
}
