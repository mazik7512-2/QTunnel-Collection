#include <vpn_driver.h>


QVPN::Core::LayerTypes QVPN::Core::BaseLayer::get_layer_type() const
{
    return LayerTypes::BASE_LAYER;
}

std::string_view QVPN::Core::BaseLayer::get_layer_name() const
{
    return "Base Layer";
}

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::BaseLayer::layer_encode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const
{
    return std::vector<BaseTypes::UByte>(begin, end);
}

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::BaseLayer::layer_decode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const
{
    return std::vector<BaseTypes::UByte>(begin, end);
}


std::variant<QVPN::Core::QVPNConnectionSettings::Ipv4AddressType, QVPN::Core::QVPNConnectionSettings::Ipv6AddressType> QVPN::Core::QVPNConnectionSettings::get_ip_address() const
{
    return addr_;
}

QVPN::Core::BaseTypes::UShort QVPN::Core::QVPNConnectionSettings::get_port() const
{
    return port_;
}


QVPN::Core::QVPNSettings::QVPNSettings(QVPNLayersSettings layers, QVPNConnectionSettings connection, QVPNAuthenticationSettings auth)
    : QVPNSettings::QVPNLayersSettings(std::move(layers)), QVPNSettings::QVPNConnectionSettings(std::move(connection)), QVPNSettings::QVPNAuthenticationSettings(std::move(auth))
{
}


QVPN::Core::QVPNAuthenticationSettings::QVPNAuthenticationSettings(std::string key)
{
    key_ = key;
}

std::string_view QVPN::Core::QVPNAuthenticationSettings::get_key() const
{
    return key_;
}

QVPN::Core::LayerWrapper::LayerWrapper(std::unique_ptr<BaseLayer> layer, bool active)
    : layer_(std::move(layer)), active_(active)
{

}

bool QVPN::Core::LayerWrapper::is_active() const
{
    return active_;
}

void QVPN::Core::LayerWrapper::set_activity(bool status)
{
    active_ = status;
}

QVPN::Core::LayerTypes QVPN::Core::LayerWrapper::get_layer_type() const
{
    return layer_->get_layer_type();
}

std::string_view QVPN::Core::LayerWrapper::get_layer_name() const
{
    return layer_->get_layer_name();
}

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::LayerWrapper::layer_encode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const
{
    return layer_->layer_encode(begin, end);
}

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::LayerWrapper::layer_decode(const QVPN::Core::BaseTypes::UByte* begin, const QVPN::Core::BaseTypes::UByte* end) const
{
    return layer_->layer_decode(begin, end);
}

void QVPN::Core::QVPNLayersSettings::add_layer(std::unique_ptr<BaseLayer> l, bool status)
{
   layers_.emplace_back(std::move(l), status);
}


std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::QVPNLayersSettings::layers_encode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const
{
    std::vector<BaseTypes::UByte> res_data(begin, end);
    for (auto& l : layers_)
    {
        if (l.is_active())
            res_data = l.layer_encode(res_data.data(), res_data.data() + res_data.size());
    }
    return res_data;
}

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::QVPNLayersSettings::layers_decode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const
{
    return std::vector<BaseTypes::UByte>();
}

QVPN::Core::QVPNDriver::QVPNDriver(QVPNSettings settings)
    : settings_(std::move(settings))
{
    
}

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::QVPNDriver::encode_data(const BaseTypes::UByte* begin, const BaseTypes::UByte* end)
{
    return settings_.layers_encode(begin, end);
}

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::QVPNDriver::decode_data(const BaseTypes::UByte* begin, const BaseTypes::UByte* end)
{
    return settings_.layers_decode(begin, end);
}

