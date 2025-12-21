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

// Splitted Packet

void QVPN::Core::SplittedPacket::set_packet_id(UByte id)
{
    packet_id_ = id;
}

std::vector<UByte> QVPN::Core::SplittedPacket::get(size_t elem)
{
    auto [b, e] = separators_[elem];
    auto full_size = data_.size();
    std::vector<UByte> res{};
    res.push_back(static_cast<UByte>(packet_id_));

    res.push_back(static_cast<UByte>(b >> 8 & 0xFF));
    res.push_back(static_cast<UByte>(b & 0xFF));

    res.push_back(static_cast<UByte>(full_size >> 8 & 0xFF));
    res.push_back(static_cast<UByte>(full_size & 0xFF));
    std::copy(data_.begin() + b, data_.begin() + e, std::back_inserter(res));
    return res;
}

std::vector<UByte> QVPN::Core::SplittedPacket::operator[](size_t elem)
{
    auto [b, e] = separators_[elem];
    auto full_size = data_.size();
    std::vector<UByte> res{};
    res.push_back(static_cast<UByte>(packet_id_));

    res.push_back(static_cast<UByte>(b >> 8 & 0xFF));
    res.push_back(static_cast<UByte>(b & 0xFF));

    res.push_back(static_cast<UByte>(full_size >> 8 & 0xFF));
    res.push_back(static_cast<UByte>(full_size & 0xFF));
    std::copy(data_.begin() + b, data_.begin() + e, std::back_inserter(res));
    return res;
}

std::pair<UByte*, UByte*> QVPN::Core::SplittedPacket::get_raw_packet(size_t elem)
{
    auto [b, e] = separators_[elem];    
    return std::pair<UByte*, UByte*>(data_.data() + b, data_.data() + e);
}

size_t QVPN::Core::SplittedPacket::size() const
{
    return separators_.size();
}

std::pair<QVPN::Core::SplittedPacket::DataIterator_t, QVPN::Core::SplittedPacket::DataIterator_t> QVPN::Core::SplittedPacket::to_bytes()
{
    return std::pair<DataIterator_t, DataIterator_t>(data_.begin(), data_.end());
}



// Packet Builder

bool QVPN::Core::PacketBuilder::is_full() const
{
    return is_full_;
}

std::pair<UByte*, UByte*> QVPN::Core::PacketBuilder::get_raw_data()
{
    auto start = data_.data();
    auto end = data_.data() + data_.size();
    return std::pair<UByte*, UByte*>(start, end);
}


// Packet Manager

bool QVPN::Core::QVPNPacketManager::have_full_packets()
{
    for (auto& it : packets_)
    {
        if (it.second.is_full())
        {
            cache_.cached_full_packet = &it;
            cache_.cached = true;
            return true;
        }
    }
    return false;
}

QVPN::Core::PacketBuilder QVPN::Core::QVPNPacketManager::get_and_pop_packet()
{
    PacketBuilder packet{};
    if (cache_.cached)
    {
        packet = std::move(cache_.cached_full_packet->second);
        pop_last_packet();
    }
    else
    {
        for (auto& it : packets_)
        {
            if (it.second.is_full())
            {
                packet = std::move(it.second);
                packets_.erase(it.first);
            }
        }
    }
    return packet;
}

std::pair<UByte*, UByte*> QVPN::Core::QVPNPacketManager::get_raw_packet()
{
    PacketBuilder* packet{};
    if (cache_.cached)
    {
        packet = &cache_.cached_full_packet->second;
    }
    else
    {
        for (auto& it : packets_)
        {
            if (it.second.is_full())
            {
                packet = &it.second;
            }
        }
    }
    return packet->get_raw_data();
}

void QVPN::Core::QVPNPacketManager::pop_last_packet()
{
    if (!cache_.cached)
        return;
    packets_.erase(cache_.cached_full_packet->first);
    cache_.cached = false;
    cache_.cached_full_packet = nullptr;
}

void QVPN::Core::QVPNPacketManager::set_data_max_size(UInt size)
{
    if (size > USHRT_MAX - QVPNPacketManager::data_meta_qvpn_size)
        return;
    data_max_size = size - QVPNPacketManager::data_meta_qvpn_size;
}

void QVPN::Core::QVPNPacketManager::set_data_split_size(UShort size)
{
    if (size > data_max_size)
        return;
    data_split_size = size;
}


// SplittedPacket View

void QVPN::Core::SplittedPacketView::set_packet_id(UByte id)
{
    packet_id_ = id;
}

std::vector<UByte> QVPN::Core::SplittedPacketView::get(size_t elem)
{
    auto [b, e] = separators_[elem];
    auto full_size = data_size_;
    std::vector<UByte> res{};
    res.push_back(static_cast<UByte>(packet_id_));

    res.push_back(static_cast<UByte>(b >> 8 & 0xFF));
    res.push_back(static_cast<UByte>(b & 0xFF));

    res.push_back(static_cast<UByte>(full_size >> 8 & 0xFF));
    res.push_back(static_cast<UByte>(full_size & 0xFF));
    std::copy(data_ + b, data_ + e, std::back_inserter(res));
    return res;
}

std::vector<UByte> QVPN::Core::SplittedPacketView::operator[](size_t elem)
{
    auto [b, e] = separators_[elem];
    auto full_size = data_size_;
    std::vector<UByte> res{};
    res.push_back(static_cast<UByte>(packet_id_));

    res.push_back(static_cast<UByte>(b >> 8 & 0xFF));
    res.push_back(static_cast<UByte>(b & 0xFF));

    res.push_back(static_cast<UByte>(full_size >> 8 & 0xFF));
    res.push_back(static_cast<UByte>(full_size & 0xFF));
    std::copy(data_ + b, data_ + e, std::back_inserter(res));
    return res;
}

std::pair<UByte*, UByte*> QVPN::Core::SplittedPacketView::get_raw_packet(size_t elem)
{
    auto [b, e] = separators_[elem];
    return std::pair<UByte*, UByte*>(data_ + b, data_ + e);
}

size_t QVPN::Core::SplittedPacketView::size() const
{
    return data_size_;
}

std::pair<QVPN::Core::SplittedPacketView::DataIterator_t, QVPN::Core::SplittedPacketView::DataIterator_t> QVPN::Core::SplittedPacketView::to_bytes()
{
    return std::pair<DataIterator_t, DataIterator_t>(data_, data_ + data_size_);
}


// User statistic data

QVPN::Core::UserStatisticData::UserStatisticData(std::string_view user, QVPNConnectionElement user_conn, QVPNConnectionElement dest_conn, TransportProtocols t_proto, size_t traffic_size)
    : user_(user), user_conn_(user_conn), dest_conn_(dest_conn), transport_proto_(t_proto), traffic_size_(traffic_size)
{
    net_proto_ = user_conn_.get_ip_address().get_addr_family();
}

std::string_view QVPN::Core::UserStatisticData::get_user() const
{
    return user_;
}

const QVPN::Core::QVPNConnectionElement& QVPN::Core::UserStatisticData::get_user_con() const
{
    return user_conn_;
}

const QVPN::Core::QVPNConnectionElement& QVPN::Core::UserStatisticData::get_dest_con() const
{
    return dest_conn_;
}

QVPN::Core::NetProtocols QVPN::Core::UserStatisticData::get_net_proto() const
{
    return net_proto_;
}

QVPN::Core::TransportProtocols QVPN::Core::UserStatisticData::get_transport_proto() const
{
    return transport_proto_;
}

size_t QVPN::Core::UserStatisticData::get_traffic_size() const
{
    return traffic_size_;
}