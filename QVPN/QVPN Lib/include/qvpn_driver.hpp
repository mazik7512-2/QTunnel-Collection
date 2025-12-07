#pragma once
#include <qvpn_net_tools.hpp>
#include <qvpn_lib.hpp>
#include <type_traits>
#include <variant>
#include <memory>
#include <qvpn_structures.hpp>

#include <nlohmann/json.hpp>

using json = nlohmann::json;
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
			std::shared_ptr<BaseLayer<Iter>> layer_;
			bool active_;

		public:

			LayerWrapper() = default;
			
			LayerWrapper(std::shared_ptr<BaseLayer<Iter>> layer, bool active = true)
				: layer_(layer), active_(active) 
			{

			}

			bool is_active() const
			{
				return active_;
			}

			void set_layer(std::unique_ptr<BaseLayer<Iter>> layer)
			{
				layer_ = std::move(layer);
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


		template <std::random_access_iterator Iter>
		class QLayer : public BaseLayer<Iter>
		{
		private:
			using TLS13_RecordGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultRecordGenerationStrategy;
			using TLSRecordGenerator = QVPN::Core::DataStructures::TLS13_RecordLittleEndian;
			using TLSAppDataGenerator = QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian;

			using TLSRecordView = QVPN::Core::DataStructures::TLS13_RecordView;
			using TLSAppDataView = QVPN::Core::DataStructures::TLS13_ApplicationDataView;

			mutable TLS13_RecordGenStrategy rec_strategy{};
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
				std::vector<UByte> res = TLSRecordGenerator::generate_object_bytes<TLS13_RecordGenStrategy, TLSAppDataGenerator>(std::move(rec_strategy), data, std::move(begin), std::move(end));
				return res;
			}

			std::vector<BaseTypes::UByte> layer_decode(Iter begin, Iter end) const override
			{
				TLSRecordView record(begin, end);
				auto [b, e] = record.get_tls_record_data();
				TLSAppDataView app_data(b, e);
				auto [b1, e1] = app_data.get_app_data();
				std::vector<UByte> data(b, e);
				return data;
			}
		};


		template <class Layer, class Iter>
		concept is_layer =
			requires (Layer l, Iter begin, Iter end, QVPN::Core::DataStructures::QVPNProxyData_Ipv4 & data) {

				{ l.get_layer_type() } -> std::same_as<LayerTypes>;
				{ l.get_layer_name() } -> std::same_as <std::string_view>;
				{ l.layer_encode(data, begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;
				{ l.layer_decode(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;

		}&& std::is_base_of<BaseLayer<Iter>, Layer>::value;


		template <class LayersStrategyImpl>
		concept is_layers_strategy =
			requires (LayersStrategyImpl ls) {

			typename LayersStrategyImpl::LayersIterator;

				{ ls.get_layers() } -> std::same_as<std::pair<typename LayersStrategyImpl::LayersIterator, typename LayersStrategyImpl::LayersIterator>>;

		};


		template <std::random_access_iterator Iter>
		class DefaultLayersStrategy
		{
		private:
			std::vector<LayerWrapper<Iter>> layers_;

		public:

			using LayersIterator = std::vector<LayerWrapper<Iter>>::iterator;

			DefaultLayersStrategy()
			{
				std::shared_ptr<QLayer<Iter>> ql{};
				LayerWrapper<Iter> lw{ ql };

				layers_.push_back(lw);
			}

			std::pair<LayersIterator, LayersIterator> get_layers()
			{
				return std::pair<LayersIterator, LayersIterator>(layers_.begin(), layers_.end());
			}
		};


		template <std::random_access_iterator Iter>
		class QVPNLayersSettings
		{
		private:
			std::vector<LayerWrapper<Iter>> layers_;

		public:

			QVPNLayersSettings() = default;

			void add_layer(std::shared_ptr<BaseLayer<Iter>> l, bool status = true)
			{
				layers_.emplace_back(l, status);
			}

			template <is_layers_strategy Strategy>
			void apply_strategy(Strategy&& strategy)
			{
				auto [b, e] = strategy.get_layers();
				for (auto i = b; i < e; i++)
				{
					layers_.emplace_back(*i);
				}
			}

			std::vector<BaseTypes::UByte> layers_encode(QVPN::Core::DataStructures::QVPNProxyData_Ipv4& data, Iter begin, Iter end) const
			{
				std::vector<BaseTypes::UByte> res_data(begin, end);
				for (auto& l : layers_)
				{
					if (l.is_active())
						res_data = l.layer_encode(data, res_data.data(), res_data.data() + res_data.size());
				}
				return res_data;
			}

			std::vector<BaseTypes::UByte> layers_decode(Iter begin, Iter end) const
			{
				std::vector<BaseTypes::UByte> res_data(begin, end);
				for (auto& l : layers_)
				{
					if (l.is_active())
						res_data = l.layer_decode(res_data.data(), res_data.data() + res_data.size());
				}
				return res_data;
			}

		};


		class QVPNConnectionSettings
		{
		public:

			using Ipv4AddressType = IPv4Address;
			using Ipv6AddressType = Ipv6Address;
			using AddrType = std::variant<Ipv4AddressType, Ipv6AddressType>;

		private:
			AddrType addr_;
			BaseTypes::UShort port_;

		public:

			QVPNConnectionSettings() = default;

			QVPNConnectionSettings(const Ipv4AddressType& address, BaseTypes::UShort port)
				: addr_(address), port_(port)
			{

			}

			QVPNConnectionSettings(const Ipv6AddressType& address, BaseTypes::UShort port)
				: addr_(address), port_(port)
			{
			}

			void set_ip_address(const Ipv4AddressType& address)
			{
				addr_ = address;
			}

			void set_ip_address(const Ipv6AddressType& address)
			{
				addr_ = address;
			}

			void set_ip_address(std::string_view addr, QVPN::Core::DataStructures::NetProtocols addr_type)
			{
				switch (addr_type)
				{
				case QVPN::Core::DataStructures::IPv4:
				{
					addr_ = Ipv4AddressType(addr);
					break;
				}
				case QVPN::Core::DataStructures::IPv6:
				{
					addr_ = Ipv6AddressType(addr);
					break;
				}
				}
			}

			void set_port(UShort port)
			{
				port_ = port;
			}

			decltype(auto) get_ip_address() const
			{
				return addr_;
			}

			BaseTypes::UShort get_port() const
			{
				return port_;
			}

		};


		class QVPNCryptoSettings
		{
		private:
			std::string key_;
			QVPN_Crypto crypto_method_;

		public:
			QVPNCryptoSettings() = default;
			QVPNCryptoSettings(QVPN_Crypto method, std::string key);

			void set_key(std::string_view key);
			void set_crypto_method(QVPN_Crypto method);

			std::string_view get_key() const;
			QVPN_Crypto get_crypto_method() const;
		};


		class QVPNAuthSettings
		{
		private:
			std::string auth_data_;

		public:
			QVPNAuthSettings() = default;
			QVPNAuthSettings(std::string_view auth_data);

			void set_auth_data(std::string_view auth_data);

			std::string_view get_auth_data() const;
		};


		template <std::random_access_iterator Iter>
		class QVPNSettings_ : public QVPNLayersSettings<Iter>, public QVPNConnectionSettings, public QVPNCryptoSettings, public QVPNAuthSettings
		{
		private:

		public:

			void parse_settings(std::string_view path)
			{
				std::ifstream f;
				f.open(path);
				auto settings = json::parse(f);

				auto addr_type = static_cast<QVPN::Core::DataStructures::NetProtocols>(settings["addr_type"].get<UInt>());
				auto addr = settings["addr"].get<std::string>();
				auto port = static_cast<UShort>(settings["port"].get<UShort>());

				set_ip_address(addr, addr_type);
				set_port(port);

				auto crypto_method = static_cast<QVPN_Crypto>(settings["crypto_method"].get<UInt>());
				auto key = settings["key"].get<std::string>();

				set_crypto_method(crypto_method);
				set_key(key);

				auto auth_data = settings["auth_data"].get<std::string>();
				set_auth_data(auth_data);

				f.close();
				
			}


			QVPNSettings_()
				: QVPNLayersSettings<Iter>(), QVPNConnectionSettings(), QVPNCryptoSettings(), QVPNAuthSettings()
			{

			}

			QVPNSettings_(std::string_view path)
				: QVPNLayersSettings<Iter>()
			{
				parse_settings(path);
			}

			QVPNSettings_(QVPNLayersSettings<Iter> layers, QVPNConnectionSettings connection, QVPNCryptoSettings crypto, QVPNAuthSettings auth)
				: QVPNSettings_:: template QVPNLayersSettings<Iter>(std::move(layers)), QVPNSettings_::QVPNConnectionSettings(std::move(connection)), QVPNSettings_::QVPNCryptoSettings(std::move(crypto)), QVPNSettings_::QVPNAuthSettings(std::move(auth)) {}


		};


		using QVPNSettings = QVPNSettings_<UByte*>;

		template <class VPNDriver>
		concept is_vpn_driver =
			requires (VPNDriver d, typename VPNDriver::DataIterator begin, typename VPNDriver::DataIterator end, QVPN::Core::DataStructures::QVPNProxyData_Ipv4 & data) {

			typename VPNDriver::AddrType;

			{ d.encode_data(data, begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;
			{ d.decode_data(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;

			{ d.connect() } -> std::same_as<bool>;
			{ d.init() } -> std::same_as<bool>;
			{ d.disconnect() } -> std::same_as<bool>;

			{ d.get_vpn_port() } -> std::same_as<UShort>;
			{ d.get_vpn_address() } -> std::same_as<typename VPNDriver::AddrType>;

		};

		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class Socket, class NetTools>
			requires is_socket<Socket, Addr>&& is_net_tools<NetTools, Socket>
		class QVPNDriver
		{
		private:

			QVPNSettings_<Iter> settings_;
			Socket socket_;

			using TLS13_RecordLittleEndian = QVPN::Core::DataStructures::TLS13_RecordLittleEndian;
			using TLS13_RecordGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultRecordGenerationStrategy;

			using TLS13_MessageLittleEndian = QVPN::Core::DataStructures::TLS13_MessageLittleEndian;

			using TLS13_ClientHello = QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian;
			using TLS13_ClienthHelloGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy;

			using TLS13_AppData = QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian;
			using QVPNProxyData = QVPN::Core::DataStructures::QVPNProxyData_Ipv4;

		public:

			using DataIterator = Iter;
			using AddrType = QVPNSettings_<Iter>::AddrType;

			QVPNDriver(QVPNSettings_<Iter> settings)
				: settings_(std::move(settings)), socket_(NetTools::create_socket())
			{
				//socket_ = NetTools::create_socket();
			}

			bool connect()
			{
				const auto addr = settings_.get_ip_address();
				const auto port = settings_.get_port();
				auto res = std::visit([this, port](const auto& a) { return socket_.connect(a, port); }, addr);
				return res.success;
			}

			bool init()
			{
				using DataIter = std::vector<UByte>::const_iterator;
				TLS13_RecordGenStrategy rec_strategy{};
				TLS13_ClienthHelloGenStrategy client_strategy{};
				std::vector<UByte> crypto_data{};

				auto m = settings_.get_crypto_method();

				crypto_data.push_back(static_cast<UByte>(m >> 8 & 0xFF));
				crypto_data.push_back(static_cast<UByte>(m & 0xFF));

				auto k = settings_.get_key();
				std::copy(k.begin(), k.end(), std::back_inserter(crypto_data));

				auto tls_data =
					TLS13_RecordLittleEndian::generate_object_bytes<TLS13_RecordGenStrategy, TLS13_MessageLittleEndian, TLS13_ClientHello, TLS13_ClienthHelloGenStrategy, DataIter>
					(std::move(rec_strategy), std::move(client_strategy), crypto_data.cbegin(), crypto_data.cend());

				auto res = socket_.send(tls_data.data(), tls_data.data() + tls_data.size());
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

			decltype(auto) get_vpn_address() const
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


		template <is_adapter_driver AdapterDriver, is_net_driver NetDriver>
		class VPNClient_ : public AdapterDriver, public NetDriver
		{
		private:
			QVPN::Core::IPv4Address default_addr;
		public:

			VPNClient_(QVPN::Core::QVPNSettings settings)
				: AdapterDriver(), NetDriver(std::move(settings))
			{
				default_addr = QVPN::Core::IPv4Address(192, 168, 50, 193);
			}

			void init_vpn()
			{
				auto adapter_ = AdapterDriver::get_ipv4_adapter();
				auto addr = adapter_->get_addr();
				NetDriver::init_driver(addr);
			}

			void start_vpn_client()
			{
				auto adapter_ = AdapterDriver::get_ipv4_adapter();
				auto addr = adapter_->get_addr();
				auto id = adapter_->get_id();

				NetDriver::start_capture_outgoing_traffic(addr, id);
				NetDriver::start_capture_incoming_traffic(default_addr);
			}

		};

	}
}