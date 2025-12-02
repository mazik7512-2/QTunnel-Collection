#pragma once
#include <qvpn_net_tools.hpp>
#include <qvpn_lib.hpp>
#include <type_traits>
#include <variant>
#include <memory>
#include <qvpn_structures.hpp>


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

		enum QVPN_Crypto : UShort
		{
			NO_CRYPTO = 0,

		};

		template <std::random_access_iterator Iter>
		class BaseLayer
		{
		public:

			virtual LayerTypes get_layer_type() const = 0;
			virtual std::string_view get_layer_name() const = 0;

			virtual std::vector<BaseTypes::UByte> layer_encode(QVPN::Core::DataStructures::QVPNProxyData_Ipv4& data, Iter begin, Iter end) const = 0;
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
				: layer_(std::move(layer)), active_(active) {
			}

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

			std::vector<BaseTypes::UByte> layer_encode(QVPN::Core::DataStructures::QVPNProxyData_Ipv4& data, Iter begin, Iter end) const
			{
				return layer_->layer_encode(data, begin, end);
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
			using TLS13_RecordGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultRecordGenerationStrategy;
			using TLSRecordGenerator = QVPN::Core::DataStructures::TLS13_RecordLittleEndian;
			using TLSAppDataGenerator = QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian;

			using TLSRecordView = QVPN::Core::DataStructures::TLS13_RecordView;
			using TLSAppDataView = QVPN::Core::DataStructures::TLS13_ApplicationDataView;

			TLS13_RecordGenStrategy rec_strategy{};
		public:

			LayerTypes get_layer_type() const override
			{
				return LayerTypes::QUIET_LAYER;
			}

			std::string_view get_layer_name() const override
			{
				return "Quiet layer";
			}


			std::vector<UByte> layer_encode(QVPN::Core::DataStructures::QVPNProxyData_Ipv4& data, Iter begin, Iter end) const override
			{
				std::vector<UByte> data = TLSRecordGenerator::generate_object_bytes<TLSRecordGenerator, TLSAppDataGenerator, Iter, QVPN::Core::DataStructures::QVPNProxyData_Ipv4>(rec_strategy, data, begin, end);
				return data;
			}

			std::vector<BaseTypes::UByte> layer_decode(Iter begin, Iter end) const override
			{
				TLSRecordView record(begin, end);
				auto [b, e] = record.get_tls_record_data();
				TLSAppDataView app_data(b, e);
				auto [b1, e1] = app_data.get_app_data();
				std::vector<UByte> data(b1, e1);
				return data;
			}
		};


		template <class Layer, class Iter>
		concept is_layer =
			requires (Layer l, Iter begin, Iter end, QVPN::Core::DataStructures::QVPNProxyData_Ipv4& data) {

				{ l.get_layer_type() } -> std::same_as<LayerTypes>;
				{ l.get_layer_name() } -> std::same_as <std::string_view>;
				{ l.layer_encode(data, begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;
				{ l.layer_decode(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;

		}&& std::is_base_of<BaseLayer<Iter>, Layer>::value;


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

			std::vector<BaseTypes::UByte> layers_encode(QVPN::Core::DataStructures::QVPNProxyData_Ipv4& data, Iter begin, Iter end) const
			{
				std::vector<BaseTypes::UByte> res_data;
				for (auto& l : layers_)
				{
					if (l.is_active())
						res_data = l.layer_encode(data, begin, end);
				}
				return res_data;
			}

			std::vector<BaseTypes::UByte> layers_decode(Iter begin, Iter end) const
			{
				return std::vector<BaseTypes::UByte>();
			}

		};


		template <is_addr AddrType>
		class QVPNConnectionSettings
		{
		public:

			using Ipv4AddressType = IPv4Address;
			using Ipv6AddressType = nullptr_t;

		private:
			QVPN::Core::UnifiedNetAddr<AddrType> addr_;
			BaseTypes::UShort port_;

		public:


			QVPNConnectionSettings(QVPN::Core::UnifiedNetAddr<AddrType>& address, BaseTypes::UShort port)
			{
				addr_ = address;
				port_ = port;
			}

			QVPN::Core::UnifiedNetAddr<AddrType> get_ip_address() const
			{
				return addr_;
			}

			BaseTypes::UShort get_port() const
			{
				return port_;
			}

		};


		class QVPNAuthenticationSettings
		{
		private:
			std::string key_;
			QVPN_Crypto crypto_method_;

		public:
			QVPNAuthenticationSettings(QVPN_Crypto method, std::string key);

			std::string_view get_key() const;
			QVPN_Crypto get_crypto_method() const;
		};

		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr>
		class QVPNSettings : public QVPNLayersSettings<Iter>, public QVPNConnectionSettings<Addr>, public QVPNAuthenticationSettings
		{
		private:

		public:
			QVPNSettings(QVPNLayersSettings<Iter> layers, QVPNConnectionSettings<Addr> connection, QVPNAuthenticationSettings auth)
				: QVPNSettings:: template QVPNLayersSettings<Iter>(std::move(layers)), QVPNSettings:: template QVPNConnectionSettings<Addr>(std::move(connection)), QVPNSettings::QVPNAuthenticationSettings(std::move(auth)) {}

		};

		template <class VPNDriver, class Addr>
		concept is_vpn_driver =
			requires (VPNDriver d, const BaseTypes::UByte * begin, const BaseTypes::UByte * end, QVPN::Core::DataStructures::QVPNProxyData_Ipv4& data) {

				{ d.encode_data(data, begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;
				{ d.decode_data(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;

				{ d.connect() } -> std::same_as<bool>;
				{ d.init() } -> std::same_as<bool>;
				{ d.disconnect() } -> std::same_as<bool>;

				{ d.get_vpn_port() } -> std::same_as<UShort>;
				{ d.get_vpn_address() } -> std::same_as<UnifiedNetAddr<Addr>>;

		};

		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class Socket, class NetTools>
			requires is_socket<Socket, Addr>&& is_net_tools<NetTools, Socket>
		class QVPNDriver
		{
		private:

			QVPNSettings<Iter, Addr> settings_;
			Socket socket_;

			using TLS13_RecordLittleEndian = QVPN::Core::DataStructures::TLS13_RecordLittleEndian;
			using TLS13_RecordGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultRecordGenerationStrategy;

			using TLS13_MessageLittleEndian = QVPN::Core::DataStructures::TLS13_MessageLittleEndian;

			using TLS13_ClientHello = QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian;
			using TLS13_ClienthHelloGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy;

		public:

			QVPNDriver(QVPNSettings<Iter, Addr> settings)
				: settings_(std::move(settings))
			{
				socket_ = NetTools::create_socket();
			}

			bool connect() const
			{
				auto addr = settings_.get_ip_address();
				auto port = settings_.get_port();
				auto res = socket_.connect(addr, port);
				return res.success;
			}

			bool init() const
			{
				using Iter = std::vector<UByte>::const_iterator;
				TLS13_RecordGenStrategy rec_strategy{};
				TLS13_ClienthHelloGenStrategy client_strategy{};
				std::vector<UByte> crypto_data{};

				auto m = settings_.get_crypto_method();

				crypto_data.push_back(static_cast<UByte>(m >> 8 & 0xFF));
				crypto_data.push_back(static_cast<UByte>(m & 0xFF));

				auto k = settings_.get_key();
				std::copy(k.begin(), k.end(), std::back_inserter(crypto_data));

				auto tls_data =
					TLS13_RecordLittleEndian::generate_object_bytes<TLS13_RecordGenStrategy, TLS13_MessageLittleEndian, TLS13_ClientHello, TLS13_ClienthHelloGenStrategy, Iter>
					(rec_strategy, client_strategy, crypto_data.cbegin(), crypto_data.cend());

				auto res = socket_.send(tls_data.begin(), tls_data.end());
				return res.success;
			}

			bool disconnect() const
			{
				auto res = socket_.disconnect();
				return res.success;
			}

			UShort get_vpn_port() const
			{
				return settings_.get_port();
			}

			auto get_vpn_address() const
			{
				return settings_.get_ip_address();
			}

			std::vector<BaseTypes::UByte> encode_data(QVPN::Core::DataStructures::QVPNProxyData_Ipv4& data, Iter begin, Iter end)
			{
				return settings_.layers_encode(data, begin, end);
			}

			std::vector<BaseTypes::UByte> decode_data(Iter begin, Iter end)
			{
				return settings_.layers_decode(begin, end);
			}

		};

	}
}