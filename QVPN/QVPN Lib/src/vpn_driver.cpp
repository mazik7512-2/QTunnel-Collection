#include <vpn_driver.h>

QVPN::Core::LayerTypes QVPN::Core::BaseLayer::get_layer_type() const
{
    return LayerTypes::BASE_LAYER;
}

std::string_view QVPN::Core::BaseLayer::get_layer_name() const
{
    return "Base Layer";
}

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::BaseLayer::layer_transformation(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const
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

QVPN::Core::QVPNSettigns::QVPNSettigns(QVPNLayersSettings layers, QVPNConnectionSettings connection, QVPNAuthenticationSettings settings)
    : QVPNLayersSettings(layers), QVPNConnectionSettings(connection), QVPNAuthenticationSettings(settings)
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

QVPN::Core::LayerWrapper::LayerWrapper(BaseLayer* layer, bool active = 1)
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

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::LayerWrapper::layer_transformation(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const
{
    return layer_->layer_transformation(begin, end);
}

void QVPN::Core::QVPNLayersSettings::add_layer(BaseLayer* l)
{
    layers_.emplace_back(l);
}

void QVPN::Core::QVPNLayersSettings::add_layer(LayerWrapper& l)
{
    layers_.push_back(l);
}

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::QVPNLayersSettings::apply_layers(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const
{
    std::vector<BaseTypes::UByte> res_data(begin, end);
    for (auto& l : layers_)
    {
        res_data = l.layer_transformation(res_data.data(), res_data.data() + res_data.size());
    }
    return res_data;
}
