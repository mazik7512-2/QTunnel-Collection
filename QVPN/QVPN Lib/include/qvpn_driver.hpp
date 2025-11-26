#pragma once
#include <qvpn_lib.hpp>
#include <type_traits>
#include <variant>
#include <memory>

namespace QVPN
{
	namespace Core
	{

		using UByte = QVPN::Core::BaseTypes::UByte;
		using UShort = QVPN::Core::BaseTypes::UShort;
		using UInt = QVPN::Core::BaseTypes::UInt;

		enum class LayerTypes
		{
			BASE_LAYER = 0,
			QUIET_LAYER = 1,
			OPTIMIZATION_LAYER,
			DEFENCE_LAYER
		};

		template <std::random_access_iterator Iter>
		class BaseLayer
		{
		public:

			virtual LayerTypes get_layer_type() const = 0;
			virtual std::string_view get_layer_name() const = 0;
			
			virtual std::vector<BaseTypes::UByte> layer_encode(Iter begin, Iter end) const = 0;
			virtual std::vector<BaseTypes::UByte> layer_decode(Iter begin, Iter end) const = 0;

			virtual ~BaseLayer() = default;
		};


		template <std::random_access_iterator Iter>
		class LayerWrapper final
		{
		private:
			std::unique_ptr<BaseLayer<Iter>> layer_;
			bool active_;

		public:
			LayerWrapper(std::unique_ptr<BaseLayer<Iter>> layer, bool active = true)
				: layer_(std::move(layer)), active_(active) {}

			bool is_active() const
			{
				return active_;
			}

			void set_activity(bool status)
			{
				active_ = status;
			}

			LayerTypes get_layer_type() const
			{
				return layer_->get_layer_type();
			}

			std::string_view get_layer_name() const
			{
				return layer_->get_layer_name();
			}

			std::vector<BaseTypes::UByte> layer_encode(Iter begin, Iter end) const
			{
				return layer_->layer_encode(begin, end);
			}

			std::vector<BaseTypes::UByte> layer_decode(Iter begin, Iter end) const
			{
				return layer_->layer_decode(begin, end);
			}

		}; 


		template <class Generator, std::random_access_iterator Iter>
		class QLayer : public BaseLayer<Iter>
		{
		private:

		public:

			LayerTypes get_layer_type() const override
			{
				return LayerTypes::QUIET_LAYER;
			}

			std::string_view get_layer_name() const override
			{
				return "Quiet layer";
			}

			
			std::vector<UByte> layer_encode(Iter begin, Iter end) const override
			{
				return std::vector<UByte>();
			}

			std::vector<BaseTypes::UByte> layer_decode(Iter begin, Iter end) const override
			{
				return std::vector<UByte>();
			}
		};


		template <class Layer, class Iter>
		concept is_layer = 
			requires (Layer l, Iter begin, Iter end) {
			
				{ l.get_layer_type() } -> std::same_as<LayerTypes>;
				{ l.get_layer_name() } -> std::same_as <std::string_view> ;
				{ l.layer_encode(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;
				{ l.layer_decode(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;

		} && std::is_base_of<BaseLayer<Iter>, Layer>::value;


		template <std::random_access_iterator Iter>
		class QVPNLayersSettings
		{
		private:
			std::vector<LayerWrapper<Iter>> layers_;

		public:

			void add_layer(std::unique_ptr<BaseLayer<Iter>> l, bool status = true)
			{
				layers_.emplace_back(std::move(l), status);
			}

			std::vector<BaseTypes::UByte> layers_encode(Iter begin, Iter end) const
			{
				std::vector<BaseTypes::UByte> res_data(begin, end);
				for (auto& l : layers_)
				{
					if (l.is_active())
						res_data = l.layer_encode(res_data.data(), res_data.data() + res_data.size());
				}
				return res_data;
			}

			std::vector<BaseTypes::UByte> layers_decode(Iter begin, Iter end) const
			{
				return std::vector<BaseTypes::UByte>();
			}

		};


		class QVPNConnectionSettings
		{
		public:

			using Ipv4AddressType = IPv4Address;
			using Ipv6AddressType = nullptr_t;

		private:
			std::variant<Ipv4AddressType, Ipv6AddressType> addr_;
			BaseTypes::UShort port_;

		public:

			template <class AddrType>
			requires is_addr<AddrType>
			QVPNConnectionSettings(AddrType address, BaseTypes::UShort port)
			{
				addr_ = address;
				port_ = port;
			}

			std::variant<Ipv4AddressType, Ipv6AddressType> get_ip_address() const;
			BaseTypes::UShort get_port() const;

		};
		

		class QVPNAuthenticationSettings
		{
		private:
			std::string key_;

		public:
			QVPNAuthenticationSettings(std::string key);

			std::string_view get_key() const;
		};

		template <std::random_access_iterator Iter>
		class QVPNSettings : public QVPNLayersSettings<Iter>, public QVPNConnectionSettings, public QVPNAuthenticationSettings
		{
		private:

		public:
			QVPNSettings(QVPNLayersSettings<Iter> layers, QVPNConnectionSettings connection, QVPNAuthenticationSettings auth)
				: QVPNSettings:: template QVPNLayersSettings<Iter>(std::move(layers)), QVPNSettings::QVPNConnectionSettings(std::move(connection)), QVPNSettings::QVPNAuthenticationSettings(std::move(auth)) {}

		};

		template <class VPNDriver>
		concept is_vpn_driver = 
			requires (VPNDriver d, const BaseTypes::UByte* begin, const BaseTypes::UByte* end) {

				{ d.encode_data(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;
				{ d.decode_data(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;

		};

		template <std::random_access_iterator Iter>
		class QVPNDriver
		{
		private:

			QVPNSettings<Iter> settings_;

		public:

			QVPNDriver(QVPNSettings<Iter> settings)
				: settings_(std::move(settings)) {}

			std::vector<BaseTypes::UByte> encode_data(Iter begin, Iter end)
			{
				return settings_.layers_encode(begin, end);
			}

			std::vector<BaseTypes::UByte> decode_data(Iter begin, Iter end)
			{
				return settings_.layers_decode(begin, end);
			}

		};
}
}