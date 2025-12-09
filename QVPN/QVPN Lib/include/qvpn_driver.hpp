#pragma once
#include <qvpn_lib.hpp>
#include <type_traits>
#include <variant>
#include <memory>
#include <qvpn_structures.hpp>
#include <qvpn_tools.hpp>

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
			virtual std::vector<BaseTypes::UByte> layer_encode(Iter begin, Iter end) const = 0;
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

			std::vector<UByte> layer_encode(Iter begin, Iter end) const override
			{
				std::vector<UByte> res = TLSRecordGenerator::generate_object_bytes<TLS13_RecordGenStrategy, TLSAppDataGenerator>(std::move(rec_strategy), std::move(begin), std::move(end));
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
				{ l.layer_encode(begin, end) } -> std::same_as<std::vector<BaseTypes::UByte>>;
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
				std::shared_ptr<QLayer<Iter>> ql = std::make_shared<QLayer<Iter>>();
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

		class QVPNConnectionElement
		{
		public:
			using Ipv4AddressType = IPv4Address;
			using Ipv6AddressType = IPv6Address;
			using AddrType = NetAddr;//std::variant<Ipv4AddressType, Ipv6AddressType>;

		private:
			AddrType addr_;
			BaseTypes::UShort port_;

		public:

			QVPNConnectionElement() = default;

			QVPNConnectionElement(const Ipv4AddressType& address, BaseTypes::UShort port)
				: addr_(address), port_(port)
			{

			}

			QVPNConnectionElement(const Ipv6AddressType& address, BaseTypes::UShort port)
				: addr_(address), port_(port)
			{
			}

			QVPNConnectionElement(std::string_view data, BaseTypes::UShort port)
				: addr_(data), port_(port)
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

			void set_ip_address(std::string_view addr, QVPN::Core::NetProtocols addr_type)
			{
				switch (addr_type)
				{
				case QVPN::Core::IPv4:
				{
					addr_ = Ipv4AddressType(addr);
					break;
				}
				case QVPN::Core::IPv6:
				{
					addr_ = Ipv6AddressType(addr);
					break;
				}
				}
			}

			void set_ip_address(std::string_view addr)
			{
				addr_ = Tools::parse_net_addr(addr);
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

		class QVPNConnectionSettings
		{
		public:

			using Ipv4AddressType = QVPNConnectionElement::Ipv4AddressType;
			using Ipv6AddressType = QVPNConnectionElement::Ipv6AddressType;
			using AddrType = QVPNConnectionElement::AddrType;

		private:
			QVPNConnectionElement data_;

		public:

			QVPNConnectionSettings() = default;

			QVPNConnectionSettings(const Ipv4AddressType& address, BaseTypes::UShort port)
				: data_(address, port)
			{

			}

			QVPNConnectionSettings(const Ipv6AddressType& address, BaseTypes::UShort port)
				: data_(address, port)
			{
			}

			void set_ip_address(const Ipv4AddressType& address)
			{
				data_.set_ip_address(address);
			}

			void set_ip_address(const Ipv6AddressType& address)
			{
				data_.set_ip_address(address);
			}

			void set_ip_address(std::string_view addr, QVPN::Core::NetProtocols addr_type)
			{
				switch (addr_type)
				{
				case QVPN::Core::IPv4:
				{
					data_.set_ip_address(Ipv4AddressType(addr));
					break;
				}
				case QVPN::Core::IPv6:
				{
					data_.set_ip_address(Ipv6AddressType(addr));
					break;
				}
				}
			}

			void set_ip_address(std::string_view addr)
			{
				data_.set_ip_address(addr);
			}

			void set_port(UShort port)
			{
				data_.set_port(port);
			}

			decltype(auto) get_ip_address() const
			{
				return data_.get_ip_address();
			}

			BaseTypes::UShort get_port() const
			{
				return data_.get_port();
			}

		};


		class QVPNClientCryptoSettings
		{
		private:
			std::string key_;
			QVPN_Crypto crypto_method_;

		public:
			QVPNClientCryptoSettings() = default;
			QVPNClientCryptoSettings(QVPN_Crypto method, std::string key);

			void set_key(std::string_view key);
			void set_crypto_method(QVPN_Crypto method);

			std::string_view get_key() const;
			QVPN_Crypto get_crypto_method() const;
		};


		class QVPNClientAuthSettings
		{
		private:
			std::string auth_data_;

		public:
			QVPNClientAuthSettings() = default;
			QVPNClientAuthSettings(std::string_view auth_data);

			void set_auth_data(std::string_view auth_data);

			std::string_view get_auth_data() const;
		};


		template <std::random_access_iterator Iter>
		class QVPNClientSettings_ : public QVPNLayersSettings<Iter>, public QVPNConnectionSettings, public QVPNClientCryptoSettings, public QVPNClientAuthSettings
		{
		private:

		public:

			void parse_settings(std::string_view path)
			{
				std::ifstream f;
				f.open(path.data());

				if (!f.is_open())
					return;

				auto settings = json::parse(f);

				auto addr_type = static_cast<QVPN::Core::NetProtocols>(settings["addr_type"].get<UInt>());
				auto addr = settings["addr"].get<std::string>();
				auto port = static_cast<UShort>(settings["port"].get<UShort>());

				set_ip_address(addr);
				set_port(port);

				auto crypto_method = static_cast<QVPN_Crypto>(settings["crypto_method"].get<UInt>());
				auto key = settings["key"].get<std::string>();

				set_crypto_method(crypto_method);
				set_key(key);

				auto auth_data = settings["auth_data"].get<std::string>();
				set_auth_data(auth_data);

				f.close();
				
			}


			QVPNClientSettings_()
				: QVPNLayersSettings<Iter>(), QVPNConnectionSettings(), QVPNClientCryptoSettings(), QVPNClientAuthSettings()
			{

			}

			QVPNClientSettings_(std::string_view path)
				: QVPNLayersSettings<Iter>()
			{
				parse_settings(path);
			}

			QVPNClientSettings_(QVPNLayersSettings<Iter> layers, QVPNConnectionSettings connection, QVPNClientCryptoSettings crypto, QVPNClientAuthSettings auth)
				: QVPNClientSettings_:: template QVPNLayersSettings<Iter>(std::move(layers)), QVPNClientSettings_::QVPNConnectionSettings(std::move(connection)), QVPNClientSettings_::QVPNClientCryptoSettings(std::move(crypto)), QVPNClientSettings_::QVPNClientAuthSettings(std::move(auth)) {}


		};


		using QVPNClientSettings = QVPNClientSettings_<UByte*>;

		template <class VPNDriver>
		concept is_vpn_client_driver =
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
		class QVPNClientDriver
		{
		private:

			QVPNClientSettings_<Iter> settings_;
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
			using AddrType = QVPNClientSettings_<Iter>::AddrType;

			QVPNClientDriver(QVPNClientSettings_<Iter> settings)
				: settings_(std::move(settings)), socket_(NetTools::create_socket())
			{
				//socket_ = NetTools::create_socket();
			}

			bool connect()
			{
				const auto addr = settings_.get_ip_address();
				const auto port = settings_.get_port();
				auto res = socket_.connect(addr, port);//std::visit([this, port](const auto& a) { return socket_.connect(a, port); }, addr);
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

			VPNClient_(QVPN::Core::QVPNClientSettings settings)
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


		class QVPNDatabaseSettings
		{
		private:
			std::string db_host;
			std::string db_user;
			std::string db_password;
			std::string db_name;
			UShort db_port;

		public:

			void set_db_host(std::string_view path);
			void set_db_user(std::string_view user);
			void set_db_password(std::string_view pass);
			void set_db_name(std::string_view name);
			void set_db_port(UShort port);

			std::string_view get_db_host() const;
			std::string_view get_db_user() const;
			std::string_view get_db_password() const;
			std::string_view get_db_name() const;
			UShort get_db_port() const;
		};


		class QVPNNetSettings
		{
		public:
			using Ipv4AddressType = QVPNConnectionElement::Ipv4AddressType;
			using Ipv6AddressType = QVPNConnectionElement::Ipv6AddressType;
			using AddrType = QVPNConnectionElement::AddrType;
			using DataIterator_t = std::vector<QVPNConnectionElement>::const_iterator;

		private:
			std::vector<QVPNConnectionElement> data_;

		public:

			void add_addr(const Ipv4AddressType& addr, UShort port);
			void add_addr(const Ipv6AddressType& addr, UShort port);

			std::pair<DataIterator_t, DataIterator_t> get_addrs() const;
		};


		class QVPNServerCryptoSettings
		{
		private:
			std::vector<QVPN_Crypto> data_;
			
		public:

			using DataIterator_t = std::vector<QVPN_Crypto>::const_iterator;

			void add_crypto_method(QVPN_Crypto crypto);
			std::pair<DataIterator_t, DataIterator_t> get_supported_crypto() const;

		};

		template <std::random_access_iterator Iter>
		class QVPNServerSettings_ : public QVPNLayersSettings<Iter>, public QVPNNetSettings, public QVPNServerCryptoSettings, public QVPNDatabaseSettings
		{
		private:

		public:

			void parse_settings(std::string_view path)
			{
				using NetProtocols = QVPN::Core::NetProtocols;
				std::ifstream f;
				f.open(path);
				auto settings = json::parse(f);

				auto& addrs = settings["addrs"];

				for (auto& addr_obj : addrs.items())
				{
					auto addr_type = static_cast<NetProtocols>(addr_obj["addr_type"].get<UInt>());

					auto addr = addr_obj["addr"].get<std::string>();
					auto port = addr_obj["port"].get<UShort>();

					switch (addr_type)
					{
					case NetProtocols::IPv4:
						add_addr(Ipv4AddressType(addr), port);
						break;
					case NetProtocols::IPv6:
						add_addr(Ipv6AddressType(addr), port);
						break;
					default:
						break;
					}
				}


				auto& sup_crypto = settings["supported_crypto"];

				for (auto& crypto_obj : sup_crypto.items())
				{
					auto crypto = crypto_obj.get<UShort>();
					add_crypto_method(crypto);
				}


				auto& database = settings["database"];

				set_db_host(database["host"].get<std::string>());
				set_db_user(database["user"].get<std::string>());
				set_db_password(database["pass"].get<std::string>());
				set_db_name(database["name"].get<std::string>());
				set_db_port(database["port"].get<UShort>());

				f.close();

			}


			QVPNServerSettings_()
				: QVPNLayersSettings<Iter>(), QVPNNetSettings(), QVPNServerCryptoSettings(), QVPNDatabaseSettings()
			{

			}

			QVPNServerSettings_(std::string_view path)
				: QVPNLayersSettings<Iter>()
			{
				parse_settings(path);
			}

			QVPNServerSettings_(QVPNLayersSettings<Iter> layers, QVPNConnectionSettings connection, QVPNClientCryptoSettings crypto, QVPNClientAuthSettings auth)
				: QVPNServerSettings_:: template QVPNLayersSettings<Iter>(std::move(layers)), QVPNServerSettings_::QVPNConnectionSettings(std::move(connection)), QVPNServerSettings_::QVPNClientCryptoSettings(std::move(crypto)), QVPNServerSettings_::QVPNDatabaseSettings(std::move(auth)) {}


		};


		template <class VPNDriverImpl>
		concept is_vpn_server_driver =
			requires (VPNDriverImpl t) {
				{ true };
		};

		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class Socket, class NetTools>
			requires is_socket<Socket, Addr> && is_net_tools<NetTools, Socket>
		class QVPNServerDriver
		{
		private:
			QVPNClientSettings_<Iter> settings_;
			Socket socket_;

		public:

			QVPNServerDriver(QVPNServerSettings_<Iter> settings)
				: settings_(std::move(settings)), socket_(NetTools::create_socket())
			{

			}


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