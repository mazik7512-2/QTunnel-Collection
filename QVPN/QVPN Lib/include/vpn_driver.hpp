#pragma once
#include <lib.hpp>
#include <type_traits>
#include <variant>
#include <memory>

namespace QVPN
{
	namespace Core
	{

		enum class LayerTypes
		{
			BASE_LAYER = 0,
			QUIET_LAYER = 1,
			OPTIMIZATION_LAYER,
			DEFENCE_LAYER
		};

		class BaseLayer
		{
		public:

			virtual LayerTypes get_layer_type() const;
			virtual std::string_view get_layer_name() const;
			virtual std::vector<BaseTypes::UByte> layer_encode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const;
			virtual std::vector<BaseTypes::UByte> layer_decode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const;

			virtual ~BaseLayer() = default;
		};


		class LayerWrapper final
		{
		private:
			std::unique_ptr<BaseLayer> layer_;
			bool active_;

		public:
			LayerWrapper(std::unique_ptr<BaseLayer> layer, bool active = true);

			bool is_active() const;
			void set_activity(bool status);

			LayerTypes get_layer_type() const;
			std::string_view get_layer_name() const;
			std::vector<BaseTypes::UByte> layer_encode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const;
			std::vector<BaseTypes::UByte> layer_decode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const;

		}; 

		template <class Layer>
		concept is_layer = 
			requires (Layer l, const BaseTypes::UByte * begin, const BaseTypes::UByte * end) {
			
				{ l.get_layer_type() } -> std::same_as<LayerTypes>;
				{ l.get_layer_name() } -> std::same_as <std::string_view> ;
				{ l.layer_encode(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;
				{ l.layer_decode(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;

		} && std::is_base_of<BaseLayer, Layer>::value;


		class QVPNLayersSettings
		{
		private:
			std::vector<LayerWrapper> layers_;

		public:

			void add_layer(std::unique_ptr<BaseLayer> l, bool status = true);

			std::vector<BaseTypes::UByte> layers_encode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const;
			std::vector<BaseTypes::UByte> layers_decode(const BaseTypes::UByte* begin, const BaseTypes::UByte* end) const;

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

		class QVPNSettings : public QVPNLayersSettings, public QVPNConnectionSettings, public QVPNAuthenticationSettings
		{
		private:

		public:
			QVPNSettings(QVPNLayersSettings layers, QVPNConnectionSettings connection, QVPNAuthenticationSettings auth);

		};

		template <class VPNDriver>
		concept is_vpn_driver = 
			requires (VPNDriver d, const BaseTypes::UByte* begin, const BaseTypes::UByte* end) {

				{ d.encode_data(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;
				{ d.decode_data(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;

		};

		class QVPNDriver
		{
		private:

			QVPNSettings settings_;

		public:

			QVPNDriver(QVPNSettings settings);
			std::vector<BaseTypes::UByte> encode_data(const BaseTypes::UByte* begin, const BaseTypes::UByte* end);
			std::vector<BaseTypes::UByte> decode_data(const BaseTypes::UByte* begin, const BaseTypes::UByte* end);

		};
	}
}