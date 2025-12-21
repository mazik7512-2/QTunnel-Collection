#pragma once
#include <qvpn_lib.hpp>
#include <type_traits>
#include <variant>
#include <memory>
#include <qvpn_structures.hpp>
#include <qvpn_tools.hpp>
#include <algorithm>
#include <thread>

#include <nlohmann/json.hpp>

using json = nlohmann::json;



namespace QVPN
{
	namespace Core
	{

		using UByte = QVPN::Core::BaseTypes::UByte;
		using UShort = QVPN::Core::BaseTypes::UShort;
		using UInt = QVPN::Core::BaseTypes::UInt;

		template <is_addr Addr>
		using QVPNData = QVPN::Core::DataStructures::QVPNData<Addr>;

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


		template <std::random_access_iterator Iter, is_addr Addr>
		class BaseLayer
		{
		public:

			virtual LayerTypes get_layer_type() const = 0;
			virtual std::string_view get_layer_name() const = 0;

			virtual std::vector<UByte> layer_encode(const QVPN::Core::DataStructures::QVPNProxyData<Addr>& data, Iter begin, Iter end) const = 0;
			virtual std::vector<UByte> layer_encode(Iter begin, Iter end) const = 0;
			virtual std::vector<UByte> layer_decode(Iter begin, Iter end) const = 0;

			virtual ~BaseLayer() = default;
		};


		template <std::random_access_iterator Iter, is_addr Addr>
		class LayerWrapper final
		{
		private:
			std::shared_ptr<BaseLayer<Iter, Addr>> layer_;
			bool active_;

		public:

			LayerWrapper() = default;

			LayerWrapper(std::shared_ptr<BaseLayer<Iter, Addr>> layer, bool active = true)
				: layer_(layer), active_(active)
			{

			}

			bool is_active() const
			{
				return active_;
			}

			void set_layer(std::unique_ptr<BaseLayer<Iter, Addr>> layer)
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

			std::vector<UByte> layer_encode(const QVPN::Core::DataStructures::QVPNProxyData<Addr>& data, Iter begin, Iter end) const
			{
				return layer_->layer_encode(data, begin, end);
			}

			std::vector<UByte> layer_encode(Iter begin, Iter end) const
			{
				return layer_->layer_encode(begin, end);
			}

			std::vector<UByte> layer_decode(Iter begin, Iter end) const
			{
				return layer_->layer_decode(begin, end);
			}

		};


		template <std::random_access_iterator Iter, is_addr Addr>
		class QLayer : public BaseLayer<Iter, Addr>
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


			std::vector<UByte> layer_encode(const QVPN::Core::DataStructures::QVPNProxyData<Addr>& data, Iter begin, Iter end) const override
			{
				std::vector<UByte> res = TLSRecordGenerator::generate_object_bytes<TLS13_RecordGenStrategy, TLSAppDataGenerator>(std::move(rec_strategy), data, std::move(begin), std::move(end));
				return res;
			}

			std::vector<UByte> layer_encode(Iter begin, Iter end) const override
			{
				std::vector<UByte> res = TLSRecordGenerator::generate_object_bytes<TLS13_RecordGenStrategy, TLSAppDataGenerator>(std::move(rec_strategy), std::move(begin), std::move(end));
				return res;
			}

			std::vector<UByte> layer_decode(Iter begin, Iter end) const override
			{
				TLSRecordView record(begin, end);
				auto [b, e] = record.get_tls_record_data();
				TLSAppDataView app_data(b, e);
				auto [b1, e1] = app_data.get_app_data();
				std::vector<UByte> data(b, e);
				return data;
			}
		};


		template <class Layer, class Iter, class Addr>
		concept is_layer =
			requires (Layer l, Iter begin, Iter end, QVPN::Core::DataStructures::QVPNProxyData<Addr> &data) {

				{ l.get_layer_type() } -> std::same_as<LayerTypes>;
				{ l.get_layer_name() } -> std::same_as <std::string_view>;
				{ l.layer_encode(data, begin, end) } -> std::same_as<std::vector<UByte>>;
				{ l.layer_encode(begin, end) } -> std::same_as<std::vector<UByte>>;
				{ l.layer_decode(begin, end) } -> std::same_as<std::vector<UByte>>;

		}&& std::is_base_of<BaseLayer<Iter, Addr>, Layer>::value;


		template <class LayersStrategyImpl>
		concept is_layers_strategy =
			requires (LayersStrategyImpl ls) {

			typename LayersStrategyImpl::LayersIterator;

			{ ls.get_layers() } -> std::same_as<std::pair<typename LayersStrategyImpl::LayersIterator, typename LayersStrategyImpl::LayersIterator>>;

		};


		template <std::random_access_iterator Iter, is_addr Addr>
		class DefaultLayersStrategy
		{
		private:
			std::vector<LayerWrapper<Iter, Addr>> layers_;

		public:

			using LayersIterator = std::vector<LayerWrapper<Iter, Addr>>::iterator;

			DefaultLayersStrategy()
			{
				std::shared_ptr<QLayer<Iter, Addr>> ql = std::make_shared<QLayer<Iter, Addr>>();
				LayerWrapper<Iter, Addr> lw{ ql };

				layers_.push_back(lw);
			}

			std::pair<LayersIterator, LayersIterator> get_layers()
			{
				return std::pair<LayersIterator, LayersIterator>(layers_.begin(), layers_.end());
			}
		};


		class SplittedPacket
		{
		private:
			using SeparatorType = std::pair<size_t, size_t>;

			UByte packet_id_;

			std::vector<UByte> data_{};
			std::vector<SeparatorType> separators_{};

		public:
			using DataIterator_t = std::vector<UByte>::iterator;

			SplittedPacket() = default;

			void set_packet_id(UByte id);

			template <std::random_access_iterator Iter>
			void add_data(Iter begin, Iter end)
			{
				auto data_start = data_.size();
				auto data_end = std::distance(begin, end);

				std::copy(begin, end, std::back_inserter(data_));
				separators_.emplace_back(std::make_pair<>(data_start, data_end));
			}

			template <std::ranges::range Range>
			void add_data(Range&& range)
			{
				auto begin = range.begin();
				auto end = range.end();
				add_data<decltype(begin)>(begin, end);
			}

			std::vector<UByte> get(size_t elem);
			std::vector<UByte> operator[](size_t elem);

			std::pair<UByte*, UByte*> get_raw_packet(size_t elem);

			size_t size() const;

			std::pair<DataIterator_t, DataIterator_t> to_bytes();

		};


		class SplittedPacketView
		{
		private:
			using SeparatorType = std::pair<size_t, size_t>;

			UByte packet_id_;

			UByte* data_ = nullptr;
			UShort data_size_ = 0;
			std::vector<SeparatorType> separators_{};

		public:
			using DataIterator_t = UByte*;

			SplittedPacketView() = default;

			void set_packet_id(UByte id);

			template <std::random_access_iterator Iter>
			void add_data(Iter begin, Iter end)
			{
				auto data_start = data_size_;
				auto data_end = std::distance(begin, end);
				data_size_ += data_end;

				//std::copy(begin, end, std::back_inserter(data_));
				if (data_ == nullptr)
					data_ = begin;

				separators_.emplace_back(std::make_pair<>(data_start, data_end));
			}

			template <std::ranges::range Range>
			void add_data(Range&& range)
			{
				auto begin = range.begin();
				auto end = range.end();
				add_data(begin, end);
			}

			std::vector<UByte> get(size_t elem);
			std::vector<UByte> operator[](size_t elem);

			std::pair<UByte*, UByte*> get_raw_packet(size_t elem);

			size_t size() const;

			std::pair<DataIterator_t, DataIterator_t> to_bytes();
		};


		class PacketBuilder
		{
		private:

			UShort original_size_ = 0;
			std::vector<UByte> data_{};
			bool is_full_ = false;

		public:

			PacketBuilder() = default;

			template <std::random_access_iterator Iter>
			PacketBuilder(Iter begin, Iter end)
			{
				auto offset = static_cast<UShort>(begin[0] << 8 | begin[1]);
				auto orig_size = static_cast<UShort>(begin[2] << 8 | begin[3]);

				original_size_ = orig_size;
				data_.reserve(orig_size);

				add_data(begin, end);
			}

			bool is_full() const;

			template <std::random_access_iterator Iter>
			void add_data(Iter begin, Iter end)
			{
				auto orig_size = static_cast<UShort>(begin[2] << 8 | begin[3]);
				auto offset = static_cast<UShort>(begin[0] << 8 | begin[1]);

				auto it = std::find(data_.begin(), data_.end(), offset);
				std::copy(begin + 4, end, std::inserter(data_, it));

				if (data_.size() == original_size_)
					is_full_ = true;
			}

			std::vector<UByte>& get_data()
			{
				return data_;
			}

			std::pair<UByte*, UByte*> get_raw_data();

		};

		class QVPNPacketManager
		{
		public:
			// 5 - packet builder data (package id - 1 byte, data_offset - 2 bytes, original_packet_size - 2 bytes), 5 - size of tls record, 
			// 38 - size of qtunnel data (net proto - 1 byte, transport proto - 1 byte, src_net addr - 16 bytes, src_port - 2 bytes, dst_net_addr - 16 bytes, dst_port - 2 bytes)
			constexpr static UShort data_meta_qvpn_size = 5 + 5 + 38;

		private:

			struct CachedFullPacket
			{
				std::pair<const UByte, PacketBuilder>* cached_full_packet = nullptr;
				bool cached = false;
			};

			std::unordered_map<UByte, PacketBuilder> packets_;
			mutable UByte last_packet_id_ = 0; // при переполнении должен обнуляться

			mutable CachedFullPacket cache_{};


			UInt data_max_size = USHRT_MAX - QVPNPacketManager::data_meta_qvpn_size;
			UShort data_split_size = data_max_size / 2 + 1;

		public:

			void set_data_max_size(UInt size);

			void set_data_split_size(UShort size);

			template <std::random_access_iterator Iter>
			SplittedPacketView split_packet(Iter begin, Iter end) const
			{
				SplittedPacketView spacket{};
				spacket.set_packet_id(last_packet_id_++);
				auto size = std::distance(begin, end);
				if (size >= QVPNPacketManager::data_max_size)
				{
					auto p_count = static_cast<UByte>(size / QVPNPacketManager::data_split_size);
					auto start_split = begin;
					auto end_split = begin + QVPNPacketManager::data_split_size;
					for (size_t i = 0; i < p_count; i++)
					{
						start_split = start_split + (i * QVPNPacketManager::data_split_size);
						end_split = (end < end_split) ? end : (start_split + QVPNPacketManager::data_split_size);
						spacket.add_data(start_split, end_split);
					}
				}
				return spacket;
			}


			template <std::random_access_iterator Iter>
			void build_packet(Iter begin, Iter end)
			{
				auto p_id = static_cast<UByte>(begin[0]);
				auto it = packets_.find(p_id);

				if (it != packets_.end())
					it->second.add_data(begin + 1, end);
				else
					packets_.emplace(std::piecewise_construct, std::forward_as_tuple(p_id), std::forward_as_tuple(begin + 1, end));
			}

			bool have_full_packets();

			PacketBuilder get_and_pop_packet();
			std::pair<UByte*, UByte*> get_raw_packet();
			void pop_last_packet();

		};


		template <std::random_access_iterator Iter, is_addr Addr>
		class QVPNLayersSettings
		{
		private:
			std::vector<LayerWrapper<Iter, Addr>> layers_;

		public:

			QVPNLayersSettings() = default;

			void add_layer(std::shared_ptr<BaseLayer<Iter, Addr>> l, bool status = true)
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

			std::vector<BaseTypes::UByte> layers_encode(QVPN::Core::DataStructures::QVPNProxyData<Addr>& data, Iter begin, Iter end) const
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
				// при декодировании нужен обратный порядок
				std::vector<BaseTypes::UByte> res_data(begin, end);
				for (auto& l : layers_ | std::views::reverse)
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

			QVPNConnectionElement(const AddrType& address, BaseTypes::UShort port)
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

			std::string to_string() const
			{
				std::stringstream ss{};

				ss << addr_.to_string() << ":" << port_;

				auto res = ss.str();
				return res;
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
		class QVPNClientSettings_ : public QVPNConnectionSettings, public QVPNLayersSettings<Iter, QVPNConnectionSettings::AddrType>, public QVPNClientCryptoSettings, public QVPNClientAuthSettings
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
				: QVPNLayersSettings<Iter, AddrType>(), QVPNConnectionSettings(), QVPNClientCryptoSettings(), QVPNClientAuthSettings()
			{

			}

			QVPNClientSettings_(std::string_view path)
				: QVPNLayersSettings<Iter>()
			{
				parse_settings(path);
			}

			QVPNClientSettings_(QVPNLayersSettings<Iter, AddrType> layers, QVPNConnectionSettings connection, QVPNClientCryptoSettings crypto, QVPNClientAuthSettings auth)
				: QVPNClientSettings_:: template QVPNLayersSettings<Iter, AddrType>(std::move(layers)), QVPNClientSettings_::QVPNConnectionSettings(std::move(connection)), QVPNClientSettings_::QVPNClientCryptoSettings(std::move(crypto)), QVPNClientSettings_::QVPNClientAuthSettings(std::move(auth)) {}


		};


		using QVPNClientSettings = QVPNClientSettings_<UByte*>;

		template <class VPNDriver>
		concept is_vpn_client_driver =
			requires (VPNDriver d, typename VPNDriver::DataIterator begin, typename VPNDriver::DataIterator end, QVPN::Core::DataStructures::QVPNProxyData<typename VPNDriver::AddrType> &data) {

			typename VPNDriver::AddrType;
			typename VPNDriver::DataIterator;

			{ d.encode_data(data, begin, end) } -> std::same_as<SplittedPacket>;
			{ d.decode_data(begin, end) } -> std::same_as<std::optional<QVPNData<typename VPNDriver::AddrType>>>;

			{ d.connect() } -> std::same_as<bool>;
			{ d.init() } -> std::same_as<bool>;
			{ d.disconnect() } -> std::same_as<bool>;

			{ d.base_send_data(begin, end) } -> std::same_as<bool>;
			{ d.encode_and_send(data, begin, end) } -> std::same_as<void>;
			{ d.get_data() } -> std::ranges::range;

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

			QVPNPacketManager packet_manager_;

			using TLS13_RecordLittleEndian = QVPN::Core::DataStructures::TLS13_RecordLittleEndian;
			using TLS13_RecordGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultRecordGenerationStrategy;

			using TLS13_MessageLittleEndian = QVPN::Core::DataStructures::TLS13_MessageLittleEndian;

			using TLS13_ClientHello = QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian;
			using TLS13_ClienthHelloGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy;

			using TLS13_AppData = QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian;


		public:

			using DataIterator = Iter;
			using AddrType = QVPNClientSettings_<Iter>::AddrType;
			using QVPNProxyData = QVPN::Core::DataStructures::QVPNProxyData<QVPNClientDriver::AddrType>;

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

			bool base_send_data(const UByte* begin, const UByte* end)
			{
				auto res = socket_.send(begin, end);
				return res.success;
			}

			void encode_and_send(QVPN::Core::DataStructures::QVPNProxyData<AddrType>& proxy_data, Iter begin, Iter end)
			{
				auto splitted_packet = encode_data(proxy_data, begin, end);
				for (size_t i = 0; i < splitted_packet.size(); i++)
				{
					//auto [b, e] = splitted_packet.get_raw_packet(i);
					auto data = splitted_packet.get(i);
					base_send_data(data.data(), data.data() + data.size());
				}
			}

			decltype(auto) get_data()
			{
				auto [status, res] = socket_.receive();
				return res;
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

			SplittedPacket encode_data(QVPN::Core::DataStructures::QVPNProxyData<AddrType>& data, Iter begin, Iter end)
			{
				SplittedPacket res;
				auto sp = packet_manager_.split_packet(begin, end);
				for (size_t i = 0; i < sp.size(); i++)
				{
					//auto [b, e] = sp.get_raw_packet(i);
					auto s_packet = sp.get(i);
					res.add_data(std::move(settings_.layers_encode(data, s_packet.data(), s_packet.data() + s_packet.size())));
				}
				return res;
			}

			std::optional<QVPNData<Addr>> decode_data(Iter begin, Iter end)
			{
				packet_manager_.build_packet(begin, end);
				if (packet_manager_.have_full_packets())
				{
					auto [b, e] = packet_manager_.get_raw_packet();
					auto res = settings_.layers_decode(b, e);
					packet_manager_.pop_last_packet();
					QVPNData<Addr> data(std::move(res));
					return data;
				}
				return std::nullopt;
			}

		};


		template <is_adapter_driver AdapterDriver, is_net_driver NetDriver>
		class VPNClient : public AdapterDriver, public NetDriver
		{
		private:
			QVPN::Core::IPv4Address default_addr;
		public:

			VPNClient(QVPN::Core::QVPNClientSettings settings)
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
		class QVPNServerSettings_ : public QVPNNetSettings, public QVPNLayersSettings<Iter, QVPNNetSettings::AddrType>, public QVPNServerCryptoSettings, public QVPNDatabaseSettings
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
				: QVPNLayersSettings<Iter, AddrType>(), QVPNNetSettings(), QVPNServerCryptoSettings(), QVPNDatabaseSettings()
			{

			}

			QVPNServerSettings_(std::string_view path)
				: QVPNLayersSettings<Iter, AddrType>()
			{
				parse_settings(path);
			}

			QVPNServerSettings_(QVPNLayersSettings<Iter, AddrType> layers, QVPNConnectionSettings connection, QVPNClientCryptoSettings crypto, QVPNClientAuthSettings auth)
				: QVPNServerSettings_:: template QVPNLayersSettings<Iter, AddrType>(std::move(layers)), QVPNServerSettings_::QVPNConnectionSettings(std::move(connection)), QVPNServerSettings_::QVPNClientCryptoSettings(std::move(crypto)), QVPNServerSettings_::QVPNDatabaseSettings(std::move(auth)) {}


		};


		using QVPNServerSettings = QVPNServerSettings_<UByte*>;


		class UserStatisticData
		{
		private:

			std::string user_;

			QVPNConnectionElement user_conn_;
			QVPNConnectionElement dest_conn_;

			NetProtocols net_proto_;
			TransportProtocols transport_proto_;

			size_t traffic_size_;

		public:

			UserStatisticData(std::string_view user, QVPNConnectionElement user_conn, QVPNConnectionElement dest_conn, TransportProtocols t_proto, size_t traffic_size);

			std::string_view get_user() const;

			const QVPNConnectionElement& get_user_con() const;
			const QVPNConnectionElement& get_dest_con() const;

			NetProtocols get_net_proto() const;
			TransportProtocols get_transport_proto() const;

			size_t get_traffic_size() const;

		};


		template <class DatabaseAdapterImpl>
		concept is_database_adapter =
			requires (DatabaseAdapterImpl d, std::string_view user) {

				{ d.check_user(user) } -> std::same_as<bool>;

		};


		template <class StatisticsAdapterImpl>
		concept is_statistic_adapter =
			requires (StatisticsAdapterImpl s, std::string_view user, UserStatisticData data) {

				{ s.add_user_stats(data) }-> std::same_as<void>;
				{ s.get_user_stats(user) } -> std::same_as<UserStatisticData>;

		};

		template <class VPNDriverImpl>
		concept is_vpn_server_driver =
			requires (VPNDriverImpl d, typename VPNDriverImpl::DataIterator begin, typename VPNDriverImpl::DataIterator end,
		QVPN::Core::DataStructures::QVPNProxyData<typename VPNDriverImpl::AddrType> &data, VPNDriverImpl::SocketType& socket) {

			typename VPNDriverImpl::DataIterator;
			typename VPNDriverImpl::AddrType;
			typename VPNDriverImpl::SocketType;

			{ d.encode_data(data, begin, end) } -> std::same_as<SplittedPacket>;
			{ d.decode_data(begin, end) } -> std::same_as<std::optional<QVPNData<typename VPNDriverImpl::AddrType>>>;

			{ d.init() } -> std::same_as<void>;

			{ d.base_send_data(socket, begin, end) } -> std::same_as<bool>;
			{ d.encode_and_send(socket, data, begin, end) } -> std::same_as<void>;

		};


		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class Socket, class NetTools>
			requires is_socket<Socket, Addr>&& is_net_tools<NetTools, Socket>
		class QVPNServerDriver
		{
		private:


			using TLS13_Record = QVPN::Core::DataStructures::TLS13_RecordLittleEndian;
			using TLS13_RecordGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultRecordGenerationStrategy;

			using TLS13_Message = QVPN::Core::DataStructures::TLS13_MessageLittleEndian;

			using TLS13_ServerHello = QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian;
			using TLS13_DefaultServerHelloGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultServerHelloGenerationStrategy;

			using TLS13_RecordView = QVPN::Core::DataStructures::TLS13_RecordView;
			using TLS13_MessageView = QVPN::Core::DataStructures::TLS13_MessageView;
			using TLS13_ServerHelloView = QVPN::Core::DataStructures::TLS13_ServerHelloPacketView;

			using TLS13_AppData = QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian;

			QVPNServerSettings_<Iter> settings_;

			std::vector<Socket> vpn_sockets_;
			std::vector<Socket> client_sockets_{};

			std::vector<std::thread> socket_threads_{};
			std::vector<std::thread> socket_clients_threads_{};

			QVPNPacketManager packet_manager_;

		private:

			void clean_threads_()
			{
				for (auto& st : socket_clients_threads_)
				{
					if (st.joinable())
					{
						st.detach();
					}
				}
			}

			std::optional<Socket> connect_to_server_impl_(QVPNConnectionElement& key)
			{
				auto socket = NetTools::create_socket();
				auto res = socket.connect(key.get_ip_address(), key.get_port());
				if (res.success)
				{
					return socket;
				}
				return std::nullopt;
			}

			void connect_to_server_(QVPNSocketData& key, std::unordered_map<QVPNSocketData, Socket>& sock_map)
			{
				auto sock = connect_to_server_impl_(key);
				if (sock.has_value())
				{
					sock_map[key] = sock.value;
				}
			}

			void connect_if_not_to_server(QVPNSocketData& key, std::unordered_map<QVPNSocketData, Socket>& sock_map)
			{
				auto it = sock_map.find(key);
				if (it == sock_map.end())
				{
					connect_to_server_(key, sock_map);
				}
			}

			bool vpn_loop_iteration(Socket& client_socket, std::unordered_map<QVPNSocketData, Socket>& sock_map)
			{
				auto [status, data] = client_socket.receive();
				if (!status.success)
					return false;
				auto decoded_data = decode_data(data.data(), data.data() + data.size());
				const auto p_data = static_cast<QVPN::Core::DataStructures::QVPNProxyData<Addr>>(decoded_data);

				QVPN::Core::DataStructures::QVPNProxyData<Addr> proxy_data = std::move(p_data.create_and_inverse_addrs(p_data));

				if (!decoded_data.has_value())
					return false;

				QVPNSocketData key{ decoded_data->get_src_addr(), decoded_data->get_src_port(), decoded_data->get_dst_addr(), decoded_data->get_dst_port() };
				connect_if_not_to_server(key, sock_map);
				auto [b, e] = decoded_data->get_raw_data();

				auto& server_socket = sock_map[key];

				server_socket.send(b, e);
				auto server_data = server_socket.receive();
				encode_and_send(client_socket, proxy_data, server_data.data(), server_data.data() + server_data.size());
				return true;
			}

			void process_socket_(Socket& client_socket)
			{
				std::unordered_map<QVPNSocketData, Socket> socket_map{};
				bool status = true;
				while (status)
				{
					status = vpn_loop_iteration(client_socket, socket_map);
				}
			}

			void listen_and_connect_socket_(Socket& socket)
			{
				while (true)
				{
					auto res = socket.listen();
					if (res.success)
					{
						TLS13_RecordGenStrategy rec_strategy{};
						TLS13_DefaultServerHelloGenStrategy strategy{};

						auto client_socket = socket.accept();
						auto data = socket.receive();

						auto [rb, re] = data.to_bytes();

						auto rec = TLS13_RecordView(rb, re);

						if (rec.get_tls_record_type() != QVPN::Core::DataStructures::TLSRecordType::HANDSHAKE)
							continue;

						auto [mb, me] = rec.get_tls_record_data();
						auto mes = TLS13_MessageView(mb, me);

						if (mes.get_tls_msg_type() != QVPN::Core::DataStructures::TLSMessageType::SERVER_HELLO)
							continue;

						// TODO: сюда вставить проверку ключа авторизации

						auto tls_data = TLS13_Record::generate_object_bytes<TLS13_RecordGenStrategy, TLS13_Message, TLS13_ServerHello>(std::move(rec_strategy), std::move(strategy));

						auto res = socket.send(tls_data.data(), tls_data.data() + tls_data.size());

						if (res.success)
						{
							auto t = std::thread([this, &client_socket]() { process_socket_(client_socket); });
							socket_clients_threads_.push_back(t);
						}
					}
				}
				clean_threads_();
			}

		public:

			using AddrType = Addr;
			using SocketType = Socket;
			using DataIterator = Iter;

			QVPNServerDriver(QVPNServerSettings_<Iter> settings)
				: settings_(std::move(settings))
			{
				auto [b, e] = settings_.get_addrs();
				for (auto& i = b; b < e; ++i)
				{
					vpn_sockets_.push_back(NetTools::create_socket());
					auto& s = vpn_sockets_[vpn_sockets_.size() - 1];
					s.bind(i->get_ip_address(), i->get_port());
				}

			}

			void init()
			{
				for (auto& s : vpn_sockets_)
				{
					auto t = std::thread([this, &s]() { listen_and_connect_socket_(s); });
					socket_threads_.push_back(t);
				}
			}

			bool base_send_data(Socket& socket, const UByte* begin, const UByte* end)
			{
				auto res = socket.send(begin, end);
				return res.success;
			}

			void encode_and_send(Socket& socket, const QVPN::Core::DataStructures::QVPNProxyData<Addr>& proxy_data, Iter begin, Iter end)
			{
				auto splitted_packet = encode_data(proxy_data, begin, end);
				for (size_t i = 0; i < splitted_packet.size(); i++)
				{
					//auto [b, e] = splitted_packet.get_raw_packet(i);
					auto data = splitted_packet.get(i);

					//socket.send(data.data(), data.data() + data.size());
					base_send_data(data.data(), data.data() + data.size());
				}
			}

			SplittedPacket encode_data(const QVPN::Core::DataStructures::QVPNProxyData<Addr>& proxy_data, Iter begin, Iter end)
			{
				SplittedPacket res;
				auto sp = packet_manager_.split_packet(begin, end);
				for (size_t i = 0; i < sp.size(); i++)
				{
					//auto [b, e] = sp.get_raw_packet(i);
					auto data = sp.get(i);
					res.add_data(std::move(settings_.layers_encode(proxy_data, data.data(), data.data() + data.size())));
				}
				return res;
				//return settings_.layers_encode(begin, end);
			}

			std::optional<QVPNData<Addr>> decode_data(Iter begin, Iter end)
			{
				packet_manager_.build_packet(begin, end);
				if (packet_manager_.have_full_packets())
				{
					auto [b, e] = packet_manager_.get_raw_packet();
					auto res = settings_.layers_decode(b, e);
					packet_manager_.pop_last_packet();
					QVPNData<Addr> data(std::move(res));
					return data;
				}
				return std::nullopt;
				//return settings_.layers_decode(begin, end);
			}

		};


		template <std::random_access_iterator Iter, is_vpn_server_driver VPNServerDriver>
		class VPNServer_ : public VPNServerDriver
		{
		public:

			VPNServer_(QVPN::Core::QVPNServerSettings_<Iter> settings)
				: VPNServerDriver(std::move(settings))
			{
				
			}

			void start_vpn_server()
			{
				VPNServerDriver::init();
			}
		};

	}
}


// for server driver
namespace std
{
	template<>
	struct hash<QVPN::Core::QVPNSocketData> {

		size_t operator()(const QVPN::Core::QVPNSocketData& data) const {
			return hash<std::string>()(data.to_string());
		}

	};
}