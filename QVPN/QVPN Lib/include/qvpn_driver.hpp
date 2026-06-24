#pragma once
#include <qvpn_lib.hpp>
#include <type_traits>
#include <variant>
#include <memory>
#include <qvpn_structures.hpp>
#include <qvpn_tools.hpp>
#include <algorithm>
#include <thread>
#include <fstream>
#include <queue>

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
		using QTunnelData = QVPN::Core::DataStructures::QTunnelData<Addr>;

		constexpr static UByte packet_builder_data_size = 5;


		class PacketBuilderData
		{
			UByte packet_id_ = 0;
			UShort offset_ = 0;
			UShort original_size_ = 0;

		public:

			PacketBuilderData() = default;
			PacketBuilderData(UByte packet_id, UShort offset, UShort original_size);

			void set_packet_id(UByte packet_id);
			void set_offset(UShort offset);
			void set_original_size(UShort size);

			UByte get_packet_id() const;
			UShort get_offset() const;
			UShort get_original_size() const;

			std::array<UByte, packet_builder_data_size> to_bytes() const;
		};


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

			virtual std::vector<UByte> layer_encode(const PacketBuilderData& pb_data, const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, Iter begin, Iter end) const = 0;
			virtual std::vector<UByte> layer_encode(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, Iter begin, Iter end) const = 0;
			virtual std::vector<UByte> layer_encode(const PacketBuilderData& pb_data, Iter begin, Iter end) const = 0;
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

			std::vector<UByte> layer_encode(const PacketBuilderData& pb_data, const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, Iter begin, Iter end) const
			{
				return layer_->layer_encode(pb_data, data, begin, end);
			}

			std::vector<UByte> layer_encode(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, Iter begin, Iter end) const
			{
				return layer_->layer_encode(data, begin, end);
			}

			std::vector<UByte> layer_encode(const PacketBuilderData& pb_data, Iter begin, Iter end) const
			{
				return layer_->layer_encode(pb_data, begin, end);
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

			std::vector<UByte> layer_encode(const PacketBuilderData& pb_data, const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, Iter begin, Iter end) const override
			{
				std::vector<UByte> res = TLSRecordGenerator::generate_object_bytes<TLS13_RecordGenStrategy, TLSAppDataGenerator>(std::move(rec_strategy), pb_data, data, std::move(begin), std::move(end));
				return res;
			}

			std::vector<UByte> layer_encode(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, Iter begin, Iter end) const override
			{
				std::vector<UByte> res = TLSRecordGenerator::generate_object_bytes<TLS13_RecordGenStrategy, TLSAppDataGenerator>(std::move(rec_strategy), data, std::move(begin), std::move(end));
				return res;
			}

			std::vector<UByte> layer_encode(const PacketBuilderData& pb_data, Iter begin, Iter end) const override
			{
				std::vector<UByte> res = TLSRecordGenerator::generate_object_bytes<TLS13_RecordGenStrategy, TLSAppDataGenerator>(std::move(rec_strategy), pb_data, std::move(begin), std::move(end));
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
				std::vector<UByte> data(b1, e1);
				return data;
			}
		};


		template <class Layer, class Iter, class Addr>
		concept is_layer =
			requires (Layer l, Iter begin, Iter end, QVPN::Core::DataStructures::QTunnelProxy<Addr> &data, const PacketBuilderData& pb_data) {

				{ l.get_layer_type() } -> std::same_as<LayerTypes>;
				{ l.get_layer_name() } -> std::same_as <std::string_view>;
				{ l.layer_encode(pb_data, data, begin, end) } -> std::same_as<std::vector<UByte>>;
				{ l.layer_encode(data, begin, end) } -> std::same_as<std::vector<UByte>>;
				{ l.layer_encode(pb_data, begin, end) } -> std::same_as<std::vector<UByte>>;
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
			using DataIterator_t = UByte*;

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

			std::pair<PacketBuilderData, std::vector<UByte>> get_with_pb_data(size_t elem);
			std::tuple<PacketBuilderData, UByte*, UByte*> get_raw_with_pb_data(size_t elem);

			std::pair<UByte*, UByte*> get_raw_packet(size_t elem);
			PacketBuilderData get_packet_builder_data(size_t elem);

			size_t size() const;

			std::pair<DataIterator_t, DataIterator_t> to_bytes();

		};


		class SplittedPacketView
		{
		private:
			using SeparatorType = std::pair<size_t, size_t>;

			UByte packet_id_ = 0;

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
				

				//std::copy(begin, end, std::back_inserter(data_));
				if (data_ == nullptr)
					data_ = begin;

				separators_.emplace_back(std::make_pair<>(data_start, data_end));
				data_size_ += data_end;
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

			std::pair<PacketBuilderData, std::vector<UByte>> get_with_pb_data(size_t elem);
			std::tuple<PacketBuilderData, UByte*, UByte*> get_raw_with_pb_data(size_t elem);

			std::pair<UByte*, UByte*> get_raw_packet(size_t elem);
			PacketBuilderData get_packet_builder_data(size_t elem);

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

			PacketBuilder(const PacketBuilder& pb) noexcept
			{
				if (*this == pb)
					return;
				original_size_ = pb.original_size_;
				data_ = pb.data_;
				is_full_ = pb.is_full_;
			}

			PacketBuilder(PacketBuilder&& pb) noexcept
			{
				if (*this == pb)
					return;
				original_size_ = std::move(pb.original_size_);
				data_ = std::move(pb.data_);
				is_full_ = std::move(pb.is_full_);
			}

			PacketBuilder& operator=(const PacketBuilder& pb) noexcept
			{
				if (*this == pb)
					return *this;
				original_size_ = pb.original_size_;
				data_ = pb.data_;
				is_full_ = pb.is_full_;
				return *this;
			}

			PacketBuilder& operator=(PacketBuilder&& pb) noexcept
			{
				if (*this == pb)
					return *this;
				original_size_ = std::move(pb.original_size_);
				data_ = std::move(pb.data_);
				is_full_ = std::move(pb.is_full_);
				return *this;
			}

			bool operator==(const PacketBuilder& pb) const noexcept
			{
				bool b = original_size_ == pb.original_size_;
				b = is_full_ == pb.is_full_;
				b = data_ == pb.data_;
				return b;
			}

			bool is_full() const;

			template <std::random_access_iterator Iter>
			void add_data(Iter begin, Iter end)
			{
				auto size = std::distance(begin, end);
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


		enum class PacketBuilderSignal
		{
			PACKET_FULL_BUILD = 0,
			PACKET_PART_RECEIVED = 1,
			PACKET_NO_BUILDER_DATA = 2
		};


		class QVPNPacketManager
		{
		public:
			// 5 - packet builder data (package id - 1 byte, data_offset - 2 bytes, original_packet_size - 2 bytes), 5 - size of tls record, 
			// 40 - size of qtunnel data (net proto - 1 byte, transport proto - 1 byte, src_net addr - 16 bytes (max), src_port - 2 bytes, dst_net_addr - 16 bytes (max), dst_port - 2 bytes, 
			// 2 bytes - size of transport proto data
			// 256 bytes - size of max add data size //?
			constexpr static UByte packet_manager_data_size = packet_builder_data_size;
			constexpr static UShort data_meta_qvpn_size = packet_manager_data_size + 5 + 40 + 256;

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
			SplittedPacketView split_packet_view(Iter begin, Iter end) const
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
				else
				{
					spacket.add_data(begin, end);
				}
				return spacket;
			}

			template <std::random_access_iterator Iter>
			SplittedPacket split_packet(Iter begin, Iter end) const
			{
				SplittedPacket spacket{};
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
				else
				{
					spacket.add_data(begin, end);
				}
				return spacket;
			}

			template <std::random_access_iterator Iter>
			PacketBuilderSignal build_packet(Iter begin, Iter end)
			{
				auto size = std::distance(begin, end);
				auto no_pb_header_size = size - QVPNPacketManager::packet_manager_data_size;
				auto offset = begin[1] << 8 | begin[2];
				auto original_size = begin[3] << 8 | begin[4];
				if (no_pb_header_size <= QVPNPacketManager::packet_manager_data_size || offset >= original_size || no_pb_header_size + offset > original_size) // check if corrupted or not our packet
					return PacketBuilderSignal::PACKET_NO_BUILDER_DATA;
				auto p_id = static_cast<UByte>(begin[0]);
				auto it = packets_.find(p_id);

				if (it != packets_.end())
				{
					it->second.add_data(begin + 1, end);
					return PacketBuilderSignal::PACKET_PART_RECEIVED;
				}
				else
				{
					packets_.emplace(std::piecewise_construct, std::forward_as_tuple(p_id), std::forward_as_tuple(begin + 1, end));
					return no_pb_header_size == original_size ? PacketBuilderSignal::PACKET_FULL_BUILD : PacketBuilderSignal::PACKET_PART_RECEIVED;
				}
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

			std::vector<BaseTypes::UByte> layers_encode(const PacketBuilderData& pb_data, const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, Iter begin, Iter end) const
			{
				std::vector<BaseTypes::UByte> res_data(begin, end);
				for (auto& l : layers_)
				{
					if (l.is_active())
						res_data = l.layer_encode(pb_data, data, res_data.data(), res_data.data() + res_data.size());
				}
				return res_data;
			}

			std::vector<BaseTypes::UByte> layers_encode(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, Iter begin, Iter end) const
			{
				std::vector<BaseTypes::UByte> res_data(begin, end);
				for (auto& l : layers_)
				{
					if (l.is_active())
						res_data = l.layer_encode(data, res_data.data(), res_data.data() + res_data.size());
				}
				return res_data;
			}


			std::vector<BaseTypes::UByte> layers_encode(const PacketBuilderData& pb_data, Iter begin, Iter end) const
			{
				std::vector<BaseTypes::UByte> res_data(begin, end);
				for (auto& l : layers_)
				{
					if (l.is_active())
						res_data = l.layer_encode(pb_data, res_data.data(), res_data.data() + res_data.size());
				}
				return res_data;
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

		
		template <class QVPNWorkMode>
		class QVPNConnectionEntity
		{
		public:
			using Ipv4AddressType = IPv4Address;
			using Ipv6AddressType = IPv6Address;
			using AddrType = NetAddr;//std::variant<Ipv4AddressType, Ipv6AddressType>;

		private:
			AddrType addr_;
			BaseTypes::UShort port_;
			TransportProtocol t_proto_;
			QVPNWorkMode mode_;

		public:

			QVPNConnectionEntity() = default;

			QVPNConnectionEntity(const Ipv4AddressType& address, BaseTypes::UShort port, TransportProtocol transport_proto = TRANSPORT_UNDEFINED, QVPNWorkMode mode = static_cast<QVPNWorkMode>(99))
				: addr_(address), port_(port), t_proto_(transport_proto), mode_(mode)
			{

			}

			QVPNConnectionEntity(const Ipv6AddressType& address, BaseTypes::UShort port, TransportProtocol transport_proto = TRANSPORT_UNDEFINED, QVPNWorkMode mode = static_cast<QVPNWorkMode>(99))
				: addr_(address), port_(port), t_proto_(transport_proto), mode_(mode)
			{
			}

			QVPNConnectionEntity(std::string_view data, BaseTypes::UShort port, TransportProtocol transport_proto = TRANSPORT_UNDEFINED, QVPNWorkMode mode = static_cast<QVPNWorkMode>(99))
				: addr_(data), port_(port), t_proto_(transport_proto), mode_(mode)
			{

			}

			QVPNConnectionEntity(const AddrType& address, BaseTypes::UShort port, TransportProtocol transport_proto = TRANSPORT_UNDEFINED, QVPNWorkMode mode = static_cast<QVPNWorkMode>(99))
				: addr_(address), port_(port), t_proto_(transport_proto), mode_(mode)
			{

			}

			void set_transport_proto(TransportProtocol t_proto)
			{
				t_proto_ = t_proto;
			}

			void set_ip_address(const Ipv4AddressType& address)
			{
				addr_ = address;
			}

			void set_ip_address(const Ipv6AddressType& address)
			{
				addr_ = address;
			}

			void set_ip_address(std::string_view addr, QVPN::Core::NetProtocol addr_type)
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

			void set_mode(QVPNWorkMode mode)
			{
				mode_ = mode;
			}

			decltype(auto) get_ip_address() const
			{
				return addr_;
			}

			BaseTypes::UShort get_port() const
			{
				return port_;
			}

			TransportProtocol get_transport_proto() const
			{
				return t_proto_;
			}

			NetProtocol get_net_proto() const
			{
				return addr_.get_addr_family();
			}

			QVPNWorkMode get_work_mode() const
			{
				return mode_;
			}

			std::string to_string() const
			{
				std::stringstream ss{};

				ss << addr_.to_string() << ":" << port_;

				auto res = ss.str();
				return res;
			}
		};


		using QVPNClientConnectionEntity = QVPNConnectionEntity<QVPNClientWorkMode>;
		using QVPNServerConnectionEntity = QVPNConnectionEntity<QVPNServerWorkMode>;


		class QVPNClientConnectionSettings
		{
		public:

			using Ipv4AddressType = QVPNClientConnectionEntity::Ipv4AddressType;
			using Ipv6AddressType = QVPNClientConnectionEntity::Ipv6AddressType;
			using AddrType = QVPNClientConnectionEntity::AddrType;

		private:
			QVPNClientConnectionEntity data_;

		public:

			QVPNClientConnectionSettings() = default;

			QVPNClientConnectionSettings(const Ipv4AddressType& address, BaseTypes::UShort port, TransportProtocol t_proto, QVPNClientWorkMode mode)
				: data_(address, port, t_proto, mode)
			{

			}

			QVPNClientConnectionSettings(const Ipv6AddressType& address, BaseTypes::UShort port, TransportProtocol t_proto, QVPNClientWorkMode mode)
				: data_(address, port, t_proto, mode)
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

			void set_ip_address(std::string_view addr, QVPN::Core::NetProtocol addr_type)
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

			void set_transport_proto(TransportProtocol t_proto)
			{
				data_.set_transport_proto(t_proto);
			}

			decltype(auto) get_ip_address() const
			{
				return data_.get_ip_address();
			}

			BaseTypes::UShort get_port() const
			{
				return data_.get_port();
			}

			TransportProtocol get_transport_proto() const
			{
				return data_.get_transport_proto();
			}

			NetProtocol get_net_proto() const
			{
				return data_.get_net_proto();
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
		class QVPNClientSettings_ : public QVPNClientConnectionSettings, public QVPNLayersSettings<Iter, QVPNClientConnectionSettings::AddrType>, public QVPNClientCryptoSettings, public QVPNClientAuthSettings
		{
		private:

			std::vector<QVPNWhitelist> whitelists_;

		public:

			void parse_settings(std::string_view path)
			{
				std::ifstream f;
				f.open(path.data());

				if (!f.is_open())
					return;

				auto settings = json::parse(f);

				auto addr_type = static_cast<QVPN::Core::NetProtocol>(settings["addr_type"].get<UInt>());
				auto addr = settings["addr"].get<std::string>();
				auto port = static_cast<UShort>(settings["port"].get<UShort>());
				auto proto = static_cast<TransportProtocol>(settings["proto"].get<UByte>());
				auto mode = static_cast<QVPNClientWorkMode>(settings["mode"].get<UByte>());

				set_ip_address(addr);
				set_port(port);
				set_transport_proto(proto);

				auto crypto_method = static_cast<QVPN_Crypto>(settings["crypto_method"].get<UInt>());
				auto key = settings["key"].get<std::string>();

				set_crypto_method(crypto_method);
				set_key(key);

				auto auth_data = settings["auth_data"].get<std::string>();
				set_auth_data(auth_data);

				auto whitelists = settings["whitelists"];

				for (auto& w_list : whitelists)
				{
					whitelists_.emplace_back(std::string_view(w_list));
				}

				f.close();

			}


			QVPNClientSettings_()
				: QVPNLayersSettings<Iter, AddrType>(), QVPNClientConnectionSettings(), QVPNClientCryptoSettings(), QVPNClientAuthSettings()
			{

			}

			QVPNClientSettings_(std::string_view path)
				: QVPNLayersSettings<Iter, AddrType>()
			{
				parse_settings(path);
			}

			QVPNClientSettings_(QVPNLayersSettings<Iter, AddrType> layers, QVPNClientConnectionSettings connection, QVPNClientCryptoSettings crypto, QVPNClientAuthSettings auth)
				: QVPNClientSettings_:: template QVPNLayersSettings<Iter, AddrType>(std::move(layers)), QVPNClientSettings_::QVPNClientConnectionSettings(std::move(connection)), QVPNClientSettings_::QVPNClientCryptoSettings(std::move(crypto)), QVPNClientSettings_::QVPNClientAuthSettings(std::move(auth)) {}

			std::string_view get_whitelist_element(size_t whitelist = 0) const
			{
				return whitelists_[whitelist].get_random_host();
			}

		};


		using QVPNClientSettings = QVPNClientSettings_<UByte*>;

		template <class VPNDriver>
		concept is_vpn_client_driver =
			requires (VPNDriver d, typename VPNDriver::DataIterator begin, typename VPNDriver::DataIterator end, QVPN::Core::DataStructures::QTunnelProxy<typename VPNDriver::AddrType> &data, int reconnect_numbers) {

			typename VPNDriver::AddrType;
			typename VPNDriver::DataIterator;

			{ d.encode_data(data, begin, end) } -> std::same_as<SplittedPacket>;
			{ d.decode_data(begin, end) } -> std::same_as<std::optional<QTunnelData<typename VPNDriver::AddrType>>>;

			{ d.reconnect() } -> std::same_as<bool>;
			{ d.connect() } -> std::same_as<bool>;
			{ d.init() } -> std::same_as<bool>;
			{ d.disconnect() } -> std::same_as<bool>;

			{ d.try_reconnect(reconnect_numbers) } -> std::same_as<bool>;

			{ d.base_send_data(begin, end) } -> std::same_as<bool>;
			{ d.encode_and_send(data, begin, end) } -> std::same_as<void>;
			{ d.get_data() } -> std::ranges::range;

			{ d.get_vpn_port() } -> std::same_as<UShort>;
			{ d.get_vpn_address() } -> std::same_as<typename VPNDriver::AddrType>;

		};


		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class Socket, class NetTools, is_logger Logger, QVPN::Core::QVPNClientWorkMode work_mode>
			requires is_socket<Socket, Addr> && is_net_tools<NetTools>
		class QVPNClientDriver
		{

		};

		// vpn spec
		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class Socket, class NetTools, is_logger Logger>
			requires is_socket<Socket, Addr>&& is_net_tools<NetTools>
		class QVPNClientDriver<Iter, Addr, Socket, NetTools, Logger, QVPN::Core::QVPNClientWorkMode::CLIENT_VPN>
		{
		private:

			QVPNClientSettings_<Iter> settings_;
			Socket socket_;

			QVPNPacketManager packet_manager_;

			using TLS13_RecordView = QVPN::Core::DataStructures::TLS13_RecordView;
			using TLS13_RecordLittleEndian = QVPN::Core::DataStructures::TLS13_RecordLittleEndian;
			using TLS13_RecordGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultRecordGenerationStrategy;

			using TLS13_MessageLittleEndian = QVPN::Core::DataStructures::TLS13_MessageLittleEndian;
			using TLS13_MessageView = QVPN::Core::DataStructures::TLS13_MessageView;

			using TLS13_ClientHello = QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian;
			using TLS13_ClienthHelloGenStrategy = QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy;

			using TLS13_ServerHello = QVPN::Core::DataStructures::TLS13_ServerHelloPacketView;

			using TLS13_AppData = QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian;
			Logger logger_{};


		public:

			using DataIterator = Iter;
			using AddrType = QVPNClientSettings_<Iter>::AddrType;
			using QTunnelProxy = QVPN::Core::DataStructures::QTunnelProxy<QVPNClientDriver::AddrType>;

			QVPNClientDriver(QVPNClientSettings_<Iter> settings)
				: settings_(std::move(settings))
			{
				logger_.set_prefix("[Client Driver]");
				logger_.info("Starting QVPN Client Driver...");
				const auto net_proto = settings_.get_net_proto();
				const auto t_proto = settings_.get_transport_proto();
				socket_ = NetTools::create_socket(net_proto, t_proto);
				logger_.success("QVPN Client Driver successfully started.");
			}

			bool connect()
			{
				logger_.success("QVPN Client successfully started");
				std::stringstream ss{};
				const auto addr = settings_.get_ip_address();
				const auto port = settings_.get_port();
				auto res = socket_.connect(addr, port);
				if (res.success) {
					ss << "Successfully connected to QVPN Server (" << socket_.get_remote_addr().to_string() << ":" << socket_.get_remote_port() << ")";
					logger_.success(ss.str());
				}
				else {
					ss << "Connection to QVPN Server (" << settings_.get_ip_address().to_string() << ":" << settings_.get_port() << ") failed";
					logger_.fail(ss.str());
				}
				return res.success;
			}

			bool try_reconnect(int reconnect_number = 20)
			{
				std::stringstream ss{};
				bool success = false;
				while (!success && reconnect_number > 0)
				{
					ss.str("");
					ss << "Try reconnect to (" << settings_.get_ip_address().to_string() << ":" << settings_.get_port() << "). Remaining " << reconnect_number << " tries...";
					logger_.info(ss.view());
					success = reconnect();
					reconnect_number--;
				}
				return success;
			}

			bool reconnect()
			{
				std::stringstream ss{};
				const auto addr = settings_.get_ip_address();
				const auto port = settings_.get_port();
				auto res = socket_.reconnect(addr, port);
				if (res.success) {
					ss << "Successfully reconnected to QVPN Server (" << socket_.get_remote_addr().to_string() << ":" << socket_.get_remote_port() << ")";
					logger_.success(ss.str());
				}
				else {
					ss << "Reconnection to QVPN Server (" << socket_.get_remote_addr().to_string() << ":" << socket_.get_remote_port() << ") failed. Error " << res.status;
					logger_.fail(ss.str());
				}
				return res.success;
			}

			bool init()
			{
				logger_.info("Starting authorization on QVPN Server.");
				using DataIter = UByte*;
				TLS13_RecordGenStrategy rec_strategy{};
				TLS13_ClienthHelloGenStrategy client_strategy{};
				std::vector<UByte> crypto_data{};

				auto user = settings_.get_auth_data();

				auto m = settings_.get_crypto_method();

				crypto_data.push_back(static_cast<UByte>(m >> 8 & 0xFF));
				crypto_data.push_back(static_cast<UByte>(m & 0xFF));

				auto k = settings_.get_key();
				UByte key_length = k.size();
				crypto_data.push_back(key_length);
				std::copy(k.begin(), k.end(), std::back_inserter(crypto_data));

				UByte user_length = user.size();
				crypto_data.push_back(user_length);
				std::copy(user.begin(), user.end(), std::back_inserter(crypto_data));

				auto wldata = settings_.get_whitelist_element();

				auto tls_data =
					TLS13_RecordLittleEndian::generate_object_bytes<TLS13_RecordGenStrategy, TLS13_MessageLittleEndian, TLS13_ClientHello, TLS13_ClienthHelloGenStrategy>
					(std::move(rec_strategy), std::move(client_strategy), wldata, crypto_data.begin(), crypto_data.end());

				auto res = socket_.send(tls_data.data(), tls_data.data() + tls_data.size());

				logger_.info("Waiting for response from server...");
				auto receive_data = socket_.receive();
				auto& status = receive_data.status;
				auto& server_hello_data = receive_data.data;
				auto size = receive_data.size;
				if (!status.success)
				{
					logger_.fail("Authorization failed.");
					return false;
				}
				
				TLS13_RecordView rec(server_hello_data.data(), server_hello_data.data() + server_hello_data.size());

				if (rec.get_tls_record_type() != QVPN::Core::DataStructures::TLSRecordType::HANDSHAKE)
				{
					logger_.fail("Authorization failed.");
					return false;
				}

				auto [m_b, m_e] = rec.get_tls_record_data();

				TLS13_MessageView mes(m_b, m_e);

				if (mes.get_tls_msg_type() != QVPN::Core::DataStructures::TLSMessageType::SERVER_HELLO)
				{
					logger_.fail("Authorization failed.");
					return false;
				}

				auto [b, e] = mes.get_tls_msg_data();

				TLS13_ServerHello sh(b, e);
				

				if (status.success)
					logger_.success("Authorization successfull.");
				else
				{
					logger_.fail("Authorization failed.");
					return false;
				}

				return res.success;
			}

			bool base_send_data(const UByte* begin, const UByte* end)
			{
				auto res = socket_.send(begin, end);
				if (!res.success)
				{
					std::stringstream ss{};
					ss << "Failed to send " << std::distance(begin, end) << " bytes to (" << socket_.get_remote_addr().to_string() << ":" << socket_.get_remote_port() << ")";
					logger_.fail(ss.view());
					return res.success;
				}
				std::stringstream ss{};
				ss << "Sended " << std::distance(begin, end) << " bytes to (" << socket_.get_remote_addr().to_string() << ":" << socket_.get_remote_port() << ")";
				logger_.info(ss.view());
				return res.success;
			}

			void encode_and_send(QVPN::Core::DataStructures::QTunnelProxy<AddrType>& proxy_data, Iter begin, Iter end)
			{
				auto splitted_packet = encode_data(proxy_data, begin, end);
				for (size_t i = 0; i < splitted_packet.size(); i++)
				{
					auto [b, e] = splitted_packet.get_raw_packet(i);
					auto res = base_send_data(b, e);
					if (!res)
					{
						auto s = try_reconnect(); // TODO: не работает reconnect, error 10014
						if (s)
							init();
						return;
					}
				}
			}

			decltype(auto) get_data()
			{
				std::stringstream ss{};
				auto receive_data = socket_.receive();
				ss << "Recevied from QVPN Server " << receive_data.size << " bytes.";
				logger_.info(ss.view());
				return receive_data.data;
			}

			bool disconnect() const
			{
				logger_.warning("Disconnection from QVPN Server");
				auto r = socket_.shutdown();
				auto r1 = socket_.close_socket();
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

			SplittedPacket encode_data(QVPN::Core::DataStructures::QTunnelProxy<AddrType>& data, Iter begin, Iter end)
			{
				// first must be split, after encode
				SplittedPacketView sp_view = packet_manager_.split_packet_view(begin, end);

				// proxy data encoded only in first splitting
				// first splitting will be always
				SplittedPacket sp{};
				auto [pb_data, b, e] = sp_view.get_raw_with_pb_data(0);
				auto first_encoded_data = settings_.layers_encode(pb_data, data, b, e);
				sp.add_data(first_encoded_data.data(), first_encoded_data.data() + first_encoded_data.size());

				for (auto i = 1; i < sp_view.size(); ++i)
				{
					auto [pb_data_i, bi, ei] = sp_view.get_raw_with_pb_data(i);
					auto encoded_part = settings_.layers_encode(pb_data_i, bi, ei);
					sp.add_data(encoded_part.data(), encoded_part.data() + encoded_part.size());
				}

				return sp;
			}

			std::optional<QTunnelData<Addr>> decode_data(Iter begin, Iter end)
			{
				// first decode, then build

				auto res = settings_.layers_decode(begin, end);
				packet_manager_.build_packet(res.data(), res.data() + res.size());
				if (packet_manager_.have_full_packets())
				{
					auto packet = packet_manager_.get_and_pop_packet();
					QTunnelData<Addr> data(std::move(packet.get_data()));
					return data;
				}
				return std::nullopt;
			}

		};


		// proxy spec
		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class Socket, class NetTools, is_logger Logger>
			requires is_socket<Socket, Addr>&& is_net_tools<NetTools>
		class QVPNClientDriver<Iter, Addr, Socket, NetTools, Logger, QVPN::Core::QVPNClientWorkMode::CLIENT_PROXY_NODE>
		{

		};

		// anti dpi node spec
		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class Socket, class NetTools, is_logger Logger>
			requires is_socket<Socket, Addr>&& is_net_tools<NetTools>
		class QVPNClientDriver<Iter, Addr, Socket, NetTools, Logger, QVPN::Core::QVPNClientWorkMode::CLIENT_ANTI_DPI_NODE>
		{

		};

		// anti dpi spec
		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class Socket, class NetTools, is_logger Logger>
			requires is_socket<Socket, Addr>&& is_net_tools<NetTools>
		class QVPNClientDriver<Iter, Addr, Socket, NetTools, Logger, QVPN::Core::QVPNClientWorkMode::CLIENT_ANTI_DPI>
		{

		};

		// dpi terror spec
		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class Socket, class NetTools, is_logger Logger>
			requires is_socket<Socket, Addr>&& is_net_tools<NetTools>
		class QVPNClientDriver<Iter, Addr, Socket, NetTools, Logger, QVPN::Core::QVPNClientWorkMode::CLIENT_DPI_TERROR>
		{

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
				/*
				AdapterDriver::create_adapter_ipv4();
				AdapterDriver::capture_adapter();
				auto adapter_ = AdapterDriver::get_ipv4_adapter();
				auto addr = adapter_->get_addr();
				*/
				IPv4Address addr("0.0.0.0");
				NetDriver::init_driver(addr);
			}

			void start_vpn_client()
			{
				/*
				auto adapter_ = AdapterDriver::get_ipv4_adapter();
				auto addr = adapter_->get_addr();
				auto id = adapter_->get_id();
				*/
				// TODO: исправить, убрать эти лишнии адреса и id + убрать адаптер, одного windivert достаточно
				auto id = 0;
				IPv4Address addr("0.0.0.0");
				NetDriver::start_capture_outgoing_traffic(addr, id);
				NetDriver::start_capture_incoming_traffic(addr);
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


		class QVPNServerConnectionSettings
		{
		public:
			using Ipv4AddressType = QVPNServerConnectionEntity::Ipv4AddressType;
			using Ipv6AddressType = QVPNServerConnectionEntity::Ipv6AddressType;
			using AddrType = QVPNServerConnectionEntity::AddrType;
			using DataIterator_t = std::vector<QVPNServerConnectionEntity>::const_iterator;

		private:
			std::vector<QVPNServerConnectionEntity> data_;

		public:

			void add_addr(const Ipv4AddressType& addr, UShort port, TransportProtocol t_proto, QVPNServerWorkMode mode);
			void add_addr(const Ipv6AddressType& addr, UShort port, TransportProtocol t_proto, QVPNServerWorkMode mode);
			void add_addr(const NetAddr& addr, UShort port, TransportProtocol t_proto, QVPNServerWorkMode mode);

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
		class QVPNServerSettings_ : public QVPNServerConnectionSettings, public QVPNLayersSettings<Iter, QVPNServerConnectionSettings::AddrType>, public QVPNServerCryptoSettings, public QVPNDatabaseSettings
		{
		private:

		public:

			void parse_settings(std::string_view path)
			{
				using NetProtocol = QVPN::Core::NetProtocol;
				std::ifstream f{};
				f.open(path.data());

				if (!f.is_open())
					return;

				auto settings = json::parse(f);

				auto& addrs = settings["addrs"];

				for (auto& addr_obj : addrs)
				{
					auto addr_type = static_cast<NetProtocol>(addr_obj["addr_type"].get<UInt>());

					auto addr = addr_obj["addr"].get<std::string>();
					auto port = addr_obj["port"].get<UShort>();
					auto proto = static_cast<TransportProtocol>(addr_obj["proto"].get<UByte>());
					auto mode = static_cast<QVPNServerWorkMode>(addr_obj["mode"].get<UByte>());

					NetAddr net_addr(addr);
					add_addr(net_addr, port, proto, mode);
				}

				auto& sup_crypto = settings["supported_crypto"];

				for (auto& crypto_obj : sup_crypto)
				{
					auto crypto = static_cast<QVPN_Crypto>(crypto_obj.get<UShort>());
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


			std::shared_ptr<QVPNServerConnectionSettings> get_connection_data()
			{
				return std::make_shared<QVPNServerConnectionSettings>(dynamic_cast<QVPNServerConnectionSettings*>(this));
			}

			QVPNServerSettings_()
				: QVPNLayersSettings<Iter, AddrType>(), QVPNServerConnectionSettings(), QVPNServerCryptoSettings(), QVPNDatabaseSettings()
			{

			}

			QVPNServerSettings_(std::string_view path)
				: QVPNLayersSettings<Iter, AddrType>()
			{
				parse_settings(path);
			}

			QVPNServerSettings_(QVPNLayersSettings<Iter, AddrType> layers, QVPNServerConnectionSettings connection, QVPNClientCryptoSettings crypto, QVPNClientAuthSettings auth)
				: QVPNServerSettings_:: template QVPNLayersSettings<Iter, AddrType>(std::move(layers)), QVPNServerSettings_::QVPNServerConnectionSettings(std::move(connection)), QVPNServerSettings_::QVPNServerCryptoSettings(std::move(crypto)), QVPNServerSettings_::QVPNDatabaseSettings(std::move(auth)) {}


		};


		using QVPNServerSettings = QVPNServerSettings_<UByte*>;


		enum class TrafficType
		{
			TRAFFIC_INCOMING = 0,
			TRAFFIC_OUTGOING = 1,
			TRAFFIC_ERROR_TYPE = 99
		};

		class UserStatisticData
		{
		private:


			std::string user_;

			QVPNSocketData socket_data_;

			size_t traffic_size_;

			TrafficType traffic_type_;

		public:

			UserStatisticData();
			UserStatisticData(std::string_view user, const QVPNSocketData& socket_data, size_t traffic_size, TrafficType traffic_type);

			void set_data(std::string_view user, const QVPNSocketData& socket_data, size_t traffic_size, TrafficType traffic_type);

			std::string_view get_user() const;

			const QVPNSocketData& get_connection_data() const;

			NetProtocol get_net_proto() const;
			TransportProtocol get_transport_proto() const;

			size_t get_traffic_size() const;

			TrafficType get_traffic_type() const;

		};


		template <class DatabaseAdapterImpl>
		concept is_database_adapter =
			requires (DatabaseAdapterImpl d, std::string_view user, std::shared_ptr<QVPNClientConnectionSettings> conn_data) {

				{ d.check_user(user) } -> std::same_as<bool>;

		};


		template <class StatisticsAdapterImpl>
		concept is_statistic_adapter =
			requires (StatisticsAdapterImpl s, std::string_view user, const UserStatisticData & data) {

				{ s.add_user_stats(data) }-> std::same_as<void>;
				{ s.get_user_stats(user) } -> std::same_as<std::vector<UserStatisticData>>;

		};

		template <class VPNDriverImpl, class DatabaseAdapter, class StatsAdapter>
		concept is_vpn_server_driver =
			requires (VPNDriverImpl d, typename VPNDriverImpl::DataIterator begin, typename VPNDriverImpl::DataIterator end,
		QVPN::Core::DataStructures::QTunnelProxy<typename VPNDriverImpl::AddrType> &data, VPNDriverImpl::SocketType & socket,
			DatabaseAdapter & database, StatsAdapter & stats) {

			typename VPNDriverImpl::DataIterator;
			typename VPNDriverImpl::AddrType;
			typename VPNDriverImpl::SocketType;

			{ d.encode_data(data, begin, end) } -> std::same_as<SplittedPacket>;
			{ d.decode_data(begin, end) } -> std::same_as<std::optional<QTunnelData<typename VPNDriverImpl::AddrType>>>;

			{ d.init(database, stats) } -> std::same_as<void>;

			{ d.base_send_data(socket, begin, end) } -> std::same_as<bool>;
			{ d.encode_and_send(socket, data, begin, end) } -> std::same_as<void>;

		};


		class NoDatabaseAdapter
		{
		public:

			void init(std::shared_ptr<QVPNClientConnectionSettings> conn_data);

			bool check_user(std::string_view data);

		};

		class NoStatisticAdapter
		{
		public:

			void add_user_stats(const UserStatisticData& data);
			std::vector<UserStatisticData> get_user_stats(std::string_view user);

		};


		class PortGenerator
		{
		public:
			static UShort get_random_port();
		};


		template <NetProtocol Net, TransportProtocol Transport, class Socket, class NetTools>
		requires is_net_tools<NetTools>
		class ConnectionInstaller
		{
		public:
			template <is_addr Addr, class Sock>
				requires is_socket<Sock, Addr>
			static NetStatus install_connection(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, Sock& socket)
			{
				return NetStatus{ true, 0 };
			}
		};

		// ipv4 + tcp spec
		template <class Socket, class NetTools>
		class ConnectionInstaller<NetProtocol::IPv4, TransportProtocol::TCP, Socket, NetTools>
		{
			using TCPScheme = QVPN::Core::DataStructures::QTunnelTCPViewScheme;
			using SchemeAdapter = QVPN::Core::DataStructures::QTunnelTransportSchemeAdapter<TransportProtocol::TCP>;

			using TCPFlags = QVPN::Core::DataStructures::TCPFlags;

			using IPv4GenStrategy = QVPN::Core::DataStructures::IPv4DefaultGenStrategy;

			using IPv4PacketObject = QVPN::Core::DataStructures::Ipv4PacketLittleEndian;
			using TCPPacketObject = QVPN::Core::DataStructures::TcpPacketLittleEndian;
			using DataPacketObject = QVPN::Core::DataStructures::DataPacketLittleEndian;

			using FullPacket = QVPN::Core::DataStructures::Ipv4TcpPacket;
		public:

			template <is_addr Addr, class Sock>
			requires is_socket<Sock, Addr>
			static NetStatus install_connection(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, Sock& socket)
			{
				UByte* dummy_data = nullptr;

				auto [b, e] = data.get_proto_data_bytes();
				SchemeAdapter scheme(b, e);

				// syn gen
				auto tcp_syn = generate_transport_header<Addr>(data, scheme.get_seq() - NetTools::hton(static_cast<UShort>(2)), 0, TCPFlags::SYN);
				auto [bt_syn, et_syn] = tcp_syn.to_bytes();
				auto syn_size = std::distance(bt_syn, et_syn);
				auto ipv4_syn = generate_net_header<Addr>(data, syn_size);
				auto [b4_syn, e4_syn] = ipv4_syn.to_bytes();
				FullPacket fp_syn(b4_syn, e4_syn, bt_syn, et_syn, dummy_data, dummy_data);
				fp_syn.recalculate_checksums();
				auto [b1_syn, e1_syn] = fp_syn.bytes();

				auto syn_res = socket.send_to(data.get_dst_addr(), data.get_dst_port(), b1_syn, e1_syn);
				if (!syn_res.success)
					return syn_res;
				// TODO: скорее всего send блокируется системой
				QVPN::Core::ReceiveData rec_data = socket.recv_from(data.get_dst_addr(), data.get_dst_port());
				if (!rec_data.status.success)
					return rec_data.status;

				// syn ack check
				FullPacket fp_syn_ack(rec_data.data.data(), rec_data.data.data() + rec_data.size);
				auto flags = fp_syn_ack.get_flags() & TCPFlags::SYN_ACK;
				auto ack = fp_syn_ack.get_tcp_ack_number();
				if (flags != TCPFlags::SYN_ACK)
					return NetStatus{ false, -1 };

				// ack gen
				auto tcp_ack = generate_transport_header<Addr>(data, scheme.get_seq() - NetTools::hton(static_cast<UShort>(1)), ack + NetTools::hton(static_cast<UInt>(1)), TCPFlags::ACK);
				auto [bt_ack, et_ack] = tcp_ack.to_bytes();
				auto ack_size = std::distance(bt_ack, et_ack);
				auto ipv4_ack = generate_net_header<Addr>(data, ack_size);
				auto [b4_ack, e4_ack] = ipv4_ack.to_bytes();
				FullPacket fp_ack(b4_ack, e4_ack, bt_ack, et_ack, dummy_data, dummy_data);
				fp_ack.recalculate_checksums();
				auto [b1_ack, e1_ack] = fp_ack.bytes();

				auto ack_res = socket.send_to(data.get_dst_addr(), data.get_dst_port(), b1_ack, e1_ack);
				if (!ack_res.success)
					return ack_res;
				return ack_res;

			}

		private:

			template <is_addr Addr>
			static IPv4PacketObject generate_net_header(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, UShort total_length)
			{
				IPv4GenStrategy strategy{};
				return IPv4PacketObject::generate_object(strategy, data.get_src_addr(), data.get_dst_addr(), TransportProtocol::TCP, total_length, true, false, 0);
			}

			template <is_addr Addr>
			static TCPPacketObject generate_transport_header(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& data, UInt seq, UInt ack, TCPFlags flags)
			{
				auto [b, e] = data.get_proto_data_bytes();
				SchemeAdapter scheme(b, e);
				auto [opt_b, opt_e] = scheme.get_options();
				return TCPPacketObject::generate_object(data.get_src_port(), data.get_dst_port(), seq, ack, scheme.get_offset(), static_cast<UByte>(flags), scheme.get_window(), scheme.get_urgent_pointer(), opt_b, opt_e);
			}

		};

		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class NetTools, is_database_adapter Database, is_statistic_adapter Stats, is_logger Logger, QVPN::Core::QVPNServerWorkMode work_mode>
			requires is_net_tools<NetTools>
		class QVPNServerDriver
		{

		};

		// vpn spec
		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class NetTools, is_database_adapter Database, is_statistic_adapter Stats, is_logger Logger>
			requires is_net_tools<NetTools>
		class QVPNServerDriver<Iter, Addr, NetTools, Database, Stats, Logger, QVPN::Core::QVPNServerWorkMode::SERVER_VPN>
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
			using TLS13_ClientHelloView = QVPN::Core::DataStructures::TLS13_ClientHelloPacketView;

			using TLS13_AppData = QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian;

			using IPv4GenStrategy = QVPN::Core::DataStructures::IPv4DefaultGenStrategy;

			IPv4GenStrategy ip4_strategy{};

			QVPNServerSettings_<Iter> settings_;

			using Socket = NetTools::Socket;
			using RawSocket = NetTools::RawSocket;

			std::vector<Socket> vpn_sockets_;
			std::vector<Socket> client_sockets_{};

			std::vector<std::thread> socket_threads_{};
			std::vector<std::thread> response_threads_{};
			std::vector<std::thread> socket_clients_threads_{};

			std::unordered_map<QVPNSocketData, std::pair<Socket, RawSocket>> response_sockets_;

			QVPNPacketManager packet_manager_;

			PacketPreParser pp_{};
			PortGenerator pg_{};

			Logger logger_{};

			using NoNetTcpPacket = QVPN::Core::DataStructures::NoNetPacket<QVPN::Core::DataStructures::TcpPacket_View, QVPN::Core::DataStructures::DataPacket_View>;
			using NoNetUdpPacket = QVPN::Core::DataStructures::NoNetPacket<QVPN::Core::DataStructures::UdpPacket_View, QVPN::Core::DataStructures::DataPacket_View>;
			using NoNetDummyPacket = QVPN::Core::DataStructures::NoNetDummyPacketObject;

			using IPv4PacketObject = QVPN::Core::DataStructures::Ipv4PacketLittleEndian;
			using IPv4PacketView = QVPN::Core::DataStructures::Ipv4PacketView;

			using DummyNetPacketObject = QVPN::Core::DataStructures::DummyNetPacket;

			using IPv6PacketObject = IPv4PacketObject;

			using TCPPacketObject = QVPN::Core::DataStructures::TcpPacketLittleEndian;
			using TCPPacketView = QVPN::Core::DataStructures::TcpPacketView;

			using UDPPacketObject = QVPN::Core::DataStructures::UdpPacketLittleEndian;
			using UDPPacketView = QVPN::Core::DataStructures::UdpPacketView;

			using DummyTransportPacketObject = QVPN::Core::DataStructures::DummyTransportPacket;

			using QTunnelProxyData = QVPN::Core::DataStructures::QTunnelProxy<Addr>;

			using TCPScheme = QVPN::Core::DataStructures::QTunnelTCPViewScheme;
			using UDPScheme = QVPN::Core::DataStructures::QTunnelUDPViewScheme;

			using FullTcpPacket = QVPN::Core::DataStructures::Ipv4TcpPacket;
			using FullUdpPacket = QVPN::Core::DataStructures::Ipv4UdpPacket;
			
			using FullDummyPacketObject = QVPN::Core::DataStructures::DummyFullPacket;

			template <TransportProtocol Proto>
			using SchemeAdapter = QVPN::Core::DataStructures::QTunnelTransportSchemeAdapter<Proto>;

			using NetPacketObjectType = std::variant<IPv4PacketObject, DummyNetPacketObject>;
			using TransportPacketObjectType = std::variant<TCPPacketObject, UDPPacketObject, DummyTransportPacketObject>;
			using NoNetPacketObjectType = std::variant<NoNetTcpPacket, NoNetUdpPacket, NoNetDummyPacket>;
			using FullPacketObjectType = std::variant<FullTcpPacket, FullUdpPacket, FullDummyPacketObject>;

		private:

			void clean_threads_()
			{
				for (auto it = socket_clients_threads_.begin(); it != socket_clients_threads_.end();)
				{
					if (it->joinable())
					{
						it->detach();
						it = socket_clients_threads_.erase(it);
					}
					else
						++it;
				}
			}

			const Socket& get_random_vpn_interface() const
			{
				std::random_device rd;
				std::mt19937 gen(rd());
				std::uniform_int_distribution<UInt> dist(0, vpn_sockets_.size() - 1);
				return vpn_sockets_[dist(gen)];
			}

			// TODO: Проверить добавляются ли response sockets
			// TODO: Возможно нужно сделать либо дублирование сокетов (один raw, другой обычный), либо устанавливать подключение вручную
			decltype(auto) add_to_response_socket_map(Socket& response_socket, RawSocket& raw_socket, QVPNSocketData& remote_key)
			{
				//QVPNSocketData sock_data(remote_key);
				remote_key.local_addr = raw_socket.get_local_addr();
				QVPNSocketSettings settings(false, 0);
				bool legal_addr = false;
				raw_socket.apply_settings(settings);
				while (!legal_addr)
				{
					if (!response_sockets_.contains(remote_key))
					{
						response_sockets_[remote_key] = std::make_pair<>(response_socket, raw_socket);
						legal_addr = true;
						logger_.success("Socket added to response map");
						break;
					}
				}
				return true;
			}


			template <NetProtocol Net, TransportProtocol Transport>
			bool estabilish_connection(const QTunnelProxyData& data, Socket& socket)
			{
				std::stringstream ss{};
				using ConInst = ConnectionInstaller<Net, Transport, Socket, NetTools>;
				auto res = ConInst:: template install_connection<Addr, Socket>(data, socket);
				if (res.success)
				{
					ss << "Connection to (" << socket.get_remote_addr().to_string() << ":" << socket.get_remote_port() << " succesfully estabilished.";
					logger_.success(ss.view());
				}
				else
				{
					ss << "Cannot connect to (" << socket.get_remote_addr().to_string() << ":" << socket.get_remote_port() << ".";
					logger_.fail(ss.view());
				}
				return res.success;
			}

			bool connection_wrapper_transport_ipv4(const QTunnelProxyData& data, Socket& socket)
			{
				auto t_proto = data.get_transport_proto();
				switch (t_proto)
				{
				case TransportProtocol::TCP:
					return estabilish_connection<IPv4, TCP>(data, socket);
					break;
				case TransportProtocol::UDP:
					return estabilish_connection<IPv4, UDP>(data, socket);
					break;
				default:
					break;
				}
				return false;
			}

			bool connection_wrapper_transport_ipv6(const QTunnelProxyData& data, Socket& socket)
			{
				return false;
			}

			bool connection_wrapper_net(const QTunnelProxyData& data, Socket& socket)
			{
				auto net_p = data.get_net_proto();
				switch (net_p)
				{
				case NetProtocol::IPv4:
					return connection_wrapper_transport_ipv4(data, socket);
					break;
				case NetProtocol::IPv6:
					return connection_wrapper_transport_ipv6(data, socket);
					break;
				default:
					return false;
					break;
				}
			}

			void install_connection_by_protocols(const QTunnelProxyData& data, Socket& socket)
			{
				bool con = false;
				while (!con)
				{
					con = connection_wrapper_net(data, socket);
				}
			}

			std::optional<RawSocket> connect_to_server_impl_(Socket& response_socket, QVPNSocketData& key, const QTunnelProxyData& proxy_data)
			{
				std::stringstream ss{};
				auto socket = NetTools::create_raw_socket(key.remote_addr.get_addr_family(), key.transport_proto);

				auto s_filter = NetTools::create_socket_filter(key);

				socket.filter(s_filter);
				if (!socket.is_valid())
				{
					ss << "Failed to create socket to " << key.remote_addr.to_string() << ":" << key.remote_port << ".";
					logger_.fail(ss.str());
					return std::nullopt;
				}

				// TODO: разобраться с socket key, local addr приходит оригинальный, а отправлять и приходить будет на другой
				auto bind_res = socket.bind(NetAddr{}, key.local_port); // NetAddr{} - IN6ADDR_ANY

				if (!bind_res.success)
				{
					logger_.fail("Failed bind socket to port {}. Error #{}", key.local_port, bind_res.status);
					return std::nullopt;
				}
				logger_.success("Socket successfully binded to port {}", key.local_port);

				auto res = socket.connect(key.remote_addr, key.remote_port);
				if (!res.success)
				{
					ss << "Failed to connect to " << key.remote_addr.to_string() << ":" << key.remote_port << ". Error #" << res.status;
					logger_.fail(ss.str());
					return std::nullopt;
				}

				add_to_response_socket_map(response_socket, socket, key);

				ss << "Socket from (" << key.local_addr.to_string() << ":" << key.local_port << ") to (" << key.remote_addr.to_string() << ":" << key.remote_port << ") created and connected.";
				logger_.success(ss.str());

				//install_connection_by_protocols(proxy_data, socket); // dont need to install con?
				return socket;
			}

			void connect_to_server_(Socket& response_socket, QVPNSocketData& key, std::unordered_map<QVPNSocketData, RawSocket>& sock_map, const QTunnelProxyData& proxy_data)
			{
				auto sock = connect_to_server_impl_(response_socket, key, proxy_data);
				if (sock.has_value())
				{
					sock_map[key] = *sock;
				}
			}

			void connect_if_not_to_server(Socket& response_socket, QVPNSocketData& key, std::unordered_map<QVPNSocketData, RawSocket>& sock_map, const QTunnelProxyData& proxy_data)
			{
				auto it = sock_map.find(key);
				if (it == sock_map.end())
				{
					connect_to_server_(response_socket, key, sock_map, proxy_data);
				}
			}

			NetPacketObjectType generate_net_header(const QTunnelProxyData& data, UShort total_len, bool dont_fragment = true, bool more_fragment = false, UShort offset = 0)
			{
				auto net_proto = data.get_net_proto();

				switch (net_proto)
				{
				case NetProtocol::IPv4:
				{
					IPv4PacketObject obj = IPv4PacketObject::generate_object(ip4_strategy, data.get_src_addr(), data.get_dst_addr(), data.get_transport_proto(), total_len, dont_fragment, more_fragment, offset);
					return obj;
					break;
				}
				/*case NetProtocol::IPv6:
				{
					IPv6PacketObject obj = IPv6PacketObject::generate_object(ip4_strategy, data.get_src_addr(), data.get_dst_addr(), data.get_transport_proto(), total_len, dont_fragment, more_fragment, offset);
					return obj;
					break;
				}*/
				default:
				{
					DummyNetPacketObject obj = DummyNetPacketObject();
					return obj;
					break;
				}
				}
			}

			TransportPacketObjectType generate_transport_header(const QTunnelProxyData& data)
			{
				auto t_proto = data.get_transport_proto();
				auto [b, e] = data.get_proto_data_bytes();


				switch (t_proto)
				{
				case TransportProtocol::TCP:
				{
					SchemeAdapter<TCP> scheme(b, e);
					auto [opt_b, opt_e] = scheme.get_options();
					TCPPacketObject obj = TCPPacketObject::generate_object(data.get_src_port(), data.get_dst_port(), scheme.get_seq(), scheme.get_ack(), scheme.get_offset(), scheme.get_flags(), scheme.get_window(), scheme.get_urgent_pointer(), opt_b, opt_e);
					return obj;
					break;
				}
				case TransportProtocol::UDP:
				{
					SchemeAdapter<UDP> scheme(b, e);
					UDPPacketObject obj = UDPPacketObject::generate_object(data.get_src_port(), data.get_dst_port(), scheme.get_length());
					return obj;
					break;
				}
				default:
				{
					DummyTransportPacketObject obj{};
					return obj;
					break;
				}
				}
			}

			FullPacketObjectType generate_full_packet(const QTunnelProxyData& data, NetPacketObjectType& net, TransportPacketObjectType& transport, UByte* begin, UByte* end)
			{
				auto net_proto = data.get_net_proto();
				auto t_proto = data.get_transport_proto();

				switch (t_proto)
				{
				case TransportProtocol::TCP:
					return std::visit([&](auto& n, auto& t)
						{
							auto net_view = n.to_view();
							auto [n_b, n_e] = net_view.to_bytes();
							auto t_view = t.to_view();
							auto [t_b, t_e] = t_view.to_bytes();
							return FullTcpPacket(n_b, n_e, t_b, t_e, begin, end);
						}, net, transport);
					break;
				case TransportProtocol::UDP:
					return std::visit([&](auto& n, auto& t)
						{
							auto net_view = n.to_view();
							auto [n_b, n_e] = net_view.to_bytes();
							auto t_view = t.to_view();
							auto [t_b, t_e] = t_view.to_bytes();
							return FullUdpPacket(n_b, n_e, t_b, t_e, begin, end);
						}, net, transport);
					break;
				default:
				{
					return FullDummyPacketObject(begin, end);
					break;
				}
				}
			}

			NoNetPacketObjectType generate_packet_with_transport_layer(const QTunnelProxyData& data, TransportPacketObjectType& transport, UByte* begin, UByte* end)
			{
				auto t_proto = data.get_transport_proto();

				switch (t_proto)
				{
				case TCP:
					return std::visit([&](auto& t)
						{
							auto view = t.to_view();
							auto [b, e] = view.to_bytes();
							return NoNetTcpPacket(b, e, begin, end);
						},
						transport);
					break;
				case UDP:
					return std::visit([&](auto& t)
						{
							auto view = t.to_view();
							auto [b, e] = view.to_bytes();
							return NoNetUdpPacket(b, e, begin, end);
						},
						transport);
					break;
				default:
					return NoNetDummyPacket(begin, end);
					break;
				}
			}


			FullPacketObjectType generate_sender_packet(const QTunnelProxyData& data, UByte* begin, UByte* end)
			{
				auto packet_data_size = static_cast<UShort>(std::distance(begin, end));
				auto t_header = generate_transport_header(data);
				auto t_size = std::visit([](auto& t) { return t.get_transport_length(); }, t_header);

				auto n_header = generate_net_header(data, t_size + packet_data_size);
				auto packet = generate_full_packet(data, n_header, t_header, begin, end);
				auto full_size = std::visit([](auto& p) 
					{ 
						p.recalculate_checksums(); 
						return p.get_full_packet_length(); 
					}, 
					packet);
				return packet;
			}

			NoNetPacketObjectType generate_sender_no_net_packet(const QTunnelProxyData& data, UByte* begin, UByte* end)
			{
				auto t_header = generate_transport_header(data);
				auto t_size = std::visit([](auto& t) { return t.get_transport_length(); }, t_header);
				auto full_size = t_size + std::distance(begin, end);
				const auto src = data.get_src_addr();
				const auto dst = data.get_dst_addr();
				auto packet = generate_packet_with_transport_layer(data, t_header, begin, end);

				std::visit([&](auto& p) { p.recalculate_checksums(src, dst, full_size); }, packet);
				return packet;
			}
			 
			// TODO: РАЗОБРАТЬСЯ С ГЕНЕРАЦИЕЙ TCP заголовка

			bool vpn_request_loop_iteration(std::shared_ptr<Socket> client_socket, std::unordered_map<QVPNSocketData, RawSocket>& sock_map, Stats& stats, std::string_view user)
			{
				std::stringstream ss{};

				//auto receive_data = client_socket->receive(); 
				auto receive_data = (*client_socket).template safe_recv<TLS13_Record>();

				const auto& status = receive_data.get_status();
				//auto& data = receive_data.data;
				//auto size = receive_data.size;

				if (!status.success)
				{
					auto err_data = std::format("Failed to receive bytes from {}:{}. Error {}", (*client_socket).get_remote_addr().to_string(), (*client_socket).get_remote_port(), status.status);
					logger_.fail(err_data);
					return true;
				}

				auto [bb, be] = receive_data.to_bytes();
				auto size = std::distance(bb, be);

				ss.str("");
				ss << "Received " << size << " bytes from (" << client_socket->get_remote_addr().to_string() << ":" << client_socket->get_remote_port() << ")";
				logger_.info(ss.view());

				auto num = receive_data.get_objects_num();

				auto num_data = std::format("Received {} object(s) from safe recv", num);
				logger_.success(num_data);

				for (size_t i = 0; i < num; i++)
				{
					auto [data_b, data_e] = receive_data.get_object_bytes(i);
					auto decoded_data = decode_data(data_b, data_e);

					if (!decoded_data.has_value())
					{
						ss.str("");
						ss << "Part of splitted or corrupted packet received.";
						logger_.info(ss.view());
						return true;
					}
					QTunnelProxyData original_proxy_data = decoded_data->create(*decoded_data);
					// inverted proxy data
					QTunnelProxyData proxy_data = decoded_data->create_and_inverse_addrs(*decoded_data);

					QVPNSocketData key{ decoded_data->get_net_proto(), decoded_data->get_transport_proto(), decoded_data->get_src_addr(), decoded_data->get_src_port(), decoded_data->get_dst_addr(), decoded_data->get_dst_port() };
					connect_if_not_to_server(*client_socket, key, sock_map, original_proxy_data);
					auto [b, e] = decoded_data->get_raw_data();
					auto inf = std::format("Received data size = {}", std::distance(b, e));
					logger_.info(inf);

					if (!sock_map.contains(key))
					{
						ss.str("");
						ss << "Error while creating socket to destination.";
						logger_.fail(ss.view());
						return false; // no socket error
					}

					auto& server_socket = sock_map[key];

					//auto packet = generate_sender_packet(original_proxy_data, b, e);
					auto packet = generate_sender_no_net_packet(original_proxy_data, b, e);

					auto [res_b, res_e] = std::visit([](auto& p)
						{
							return p.bytes();
						}, packet);

					//auto send_status = server_socket.send_to(key.remote_addr, key.remote_port, res_b, res_e);

					auto send_status = server_socket.send(res_b, res_e);

					if (!send_status.success)
					{
						ss.str("");
						ss << "Error while sending packet to (" << server_socket.get_remote_addr().to_string() << ":" << server_socket.get_remote_port() << "). Error " << send_status.status;
						logger_.fail(ss.view());
						return true;
					}

					auto send_size = std::distance(res_b, res_e);

					ss.str("");
					ss << "Sended (raw) " << send_size << " bytes to " << server_socket.get_remote_addr().to_string() << ":" << server_socket.get_remote_port() << " from " << server_socket.get_local_addr().to_string() << ":" << server_socket.get_local_port();
					logger_.info(ss.view());

					// statistics
					////
					NetProtocol net_proto = proxy_data.get_net_proto();
					TransportProtocol transport_proto = proxy_data.get_transport_proto();
					size_t data_size = std::distance(b, e);
					TrafficType traffic_type = TrafficType::TRAFFIC_OUTGOING;

					auto src = proxy_data.get_src_addr();
					auto src_port = proxy_data.get_src_port();

					auto dst = proxy_data.get_dst_addr();
					auto dst_port = proxy_data.get_dst_port();

					QVPNSocketData socket_data{ net_proto, transport_proto, src, src_port, dst, dst_port };

					UserStatisticData stats_data(user, socket_data, data_size, traffic_type);
					//stats.add_user_stats(stats_data);
				}


				////
				return true;
			}

			void process_socket_(std::shared_ptr<Socket> client_socket, Stats& stats, std::string_view user)
			{
				std::stringstream ss{};
				ss << "QTunnel from (" << client_socket->get_remote_addr().to_string() << ":" << client_socket->get_remote_port() << ") initialized";
				logger_.success(ss.view());

				std::unordered_map<QVPNSocketData, RawSocket> socket_map{};
				bool status = true;
				while (status)
				{
					status = vpn_request_loop_iteration(client_socket, socket_map, stats, user);
				}

				ss.str("");
				ss << "QTunnel from (" << client_socket->get_remote_addr().to_string() << ":" << client_socket->get_remote_port() << ") closed";
				logger_.warning(ss.view());

				client_socket->shutdown();
				client_socket->close_socket();
				client_socket->disconnect();
			}

			void listen_and_connect_socket_(Socket& socket, Database& database, Stats& stats)
			{
				using NoNetTcpPacket = QVPN::Core::DataStructures::NoNetPacket<QVPN::Core::DataStructures::TcpPacket_View, QVPN::Core::DataStructures::DataPacket_View>;
				using NoNetUdpPacket = QVPN::Core::DataStructures::NoNetPacket<QVPN::Core::DataStructures::UdpPacket_View, QVPN::Core::DataStructures::DataPacket_View>;
				using TCPPacketView = QVPN::Core::DataStructures::TcpPacket_View;
				using UDPPacketView = QVPN::Core::DataStructures::UdpPacket_View;

				std::stringstream ss{};
				ss << "QVPN Server started on " << socket.get_local_addr().to_string() << ":" << socket.get_local_port();
				logger_.success(ss.view());
				ss.str("");

				// TODO: сделать логер отдельными функциями

				while (true)
				{
					auto res = socket.listen();
					if (res.success)
					{
						TLS13_RecordGenStrategy rec_strategy{};
						TLS13_DefaultServerHelloGenStrategy strategy{};

						auto client_socket = socket.template accept<Addr>();

						std::stringstream ss_ac{};
						ss_ac << "Accepting connnection from (" << client_socket.get_remote_addr().to_string() << ":" << client_socket.get_remote_port() << ")";
						logger_.warning(ss_ac.view());

						auto receive_data = client_socket.receive();
						auto& status = receive_data.status;
						auto& data = receive_data.data;
						auto len = receive_data.size;

						if (!status.success)
						{
							logger_auth_fail(client_socket);
							client_socket.shutdown();
							client_socket.disconnect();
							client_socket.close_socket();
							continue;
						}

						std::stringstream ss1{};

						ss1 << "Start authorization from " << client_socket.get_remote_addr().to_string() << ":" << client_socket.get_remote_port();
						logger_.info(ss1.view());
						auto rec = TLS13_RecordView(data.data(), data.data() + len);

						if (rec.get_tls_record_type() != QVPN::Core::DataStructures::TLSRecordType::HANDSHAKE)
						{
							logger_auth_fail(client_socket);
							client_socket.shutdown();
							client_socket.disconnect();
							client_socket.close_socket();
							continue;
						}

						auto [mb, me] = rec.get_tls_record_data();
						auto mes = TLS13_MessageView(mb, me);

						if (mes.get_tls_msg_type() != QVPN::Core::DataStructures::TLSMessageType::CLIENT_HELLO)
						{
							logger_auth_fail(client_socket);
							client_socket.shutdown();
							client_socket.disconnect();
							client_socket.close_socket();
							continue;
						}

						auto [h_b, h_e] = mes.get_tls_msg_data();

						TLS13_ClientHelloView client_hello(h_b, h_e);
						auto crypto_data = client_hello.get_tls_session();

						// crypto method
						auto [d_b, d_e] = crypto_data.get_tls_id();
						QVPN::Core::QVPN_Crypto crypto_method = static_cast<QVPN_Crypto>((*(d_b) << 8) | *(d_b + 1));
						int offset = 2;
						// crypto key
						UByte key_size = *(d_b + offset);
						offset++;
						std::string_view key(reinterpret_cast<char*>(d_b + 3), reinterpret_cast<char*>(d_b + key_size + offset));
						offset += key_size;

						// user
						UByte user_size = *(d_b + offset);
						offset++;
						std::string_view user(reinterpret_cast<char*>(d_b + offset), reinterpret_cast<char*>(d_b + user_size + offset));
						offset += user_size;

						if (!database.check_user(user)) //TODO: изменить поведение на отправку HTTP
						{
							logger_auth_fail(client_socket);
							client_socket.shutdown();
							client_socket.disconnect();
							client_socket.close_socket();
							continue;
						}

						auto tls_data = TLS13_Record::generate_object_bytes<TLS13_RecordGenStrategy, TLS13_Message, TLS13_ServerHello>(std::move(rec_strategy), std::move(strategy));

						auto res = client_socket.send(tls_data.data(), tls_data.data() + tls_data.size());

						if (res.success)
						{
							logger_auth_success(client_socket);
							std::shared_ptr<Socket> c_sock = std::make_shared<Socket>(std::move(client_socket));
							//auto t = std::thread([this, c_sock, &stats, &user]() { process_socket_(c_sock, stats, user); });
							socket_clients_threads_.emplace_back(std::thread([this, c_sock, &stats, &user]() { process_socket_(c_sock, stats, user); }));
						}
						else
						{
							logger_auth_fail(client_socket);
							client_socket.shutdown();
							client_socket.disconnect();
							client_socket.close_socket();
						}

					}
				}
				clean_threads_();
			}

			template <std::random_access_iterator Iterator>
			void vpn_response_loop_iteration(RawSocket& raw_socket, Socket& socket, const QVPNSocketData& key, Iterator begin, Iterator end)
			{
				auto str = std::format("Received (raw) {} bytes from {}:{}", std::distance(begin, end), raw_socket.get_remote_addr().to_string(), raw_socket.get_remote_port());
				logger_.success(str);
				auto response = pp_.pre_parse(begin, end);

				auto proto_data = std::visit([](auto& p) { return p.collect_proto_data(); }, response);


				QTunnelProxyData new_proxy_data = std::visit([&proto_data, &key](auto& p)
					{
						auto net = p.get_protocol_version();
						auto transport = p.get_transport_protocol();
						auto src = p.get_src_addr();
						auto src_port = p.get_src_port();
						auto& dst = key.remote_addr; 
						auto dst_port = key.remote_port;
						return QTunnelProxyData(net, transport, src, src_port, dst, dst_port, std::move(proto_data));
					}
				, response);

				auto [data_b, data_e] = std::visit([](auto& p) { return p.get_data(); }, response);

				encode_and_send(socket, new_proxy_data, data_b, data_e);
			}

			void listen_response_sockets_()
			{
				while (true)
				{
					for (auto& [key, socks] : response_sockets_)
					{
						auto [resp_sock, sock] = socks;
						auto rec_data = sock.recv_from(key.local_addr, key.local_port);
						if (rec_data.status.success)
							vpn_response_loop_iteration<>(sock, resp_sock, key, rec_data.data.data(), rec_data.data.data() + rec_data.size);
						else
						{
							std::stringstream ss{};

							if (!rec_data.status.success)
							{	
								ss.str("");
								ss << "Cannot receive (raw) packet from (" << sock.get_remote_addr().to_string() << ":" << sock.get_remote_port() << "). Error " << rec_data.status.status;
								logger_.fail(ss.view());
							}
						}
					}
				}

			}

			void logger_auth_fail(Socket& socket)
			{
				std::stringstream ss{};
				ss << "Authorization failed from (" << socket.get_remote_addr().to_string() << ":" << socket.get_remote_port() << ")";
				logger_.fail(ss.view());

				ss.str("");

				ss << "Connection from (" << socket.get_remote_addr().to_string() << ":" << socket.get_remote_port() << ") closed";
				logger_.info(ss.view());
			}

			void logger_auth_success(Socket& socket)
			{
				std::stringstream ss{};
				ss << "Authorization successfull from (" << socket.get_remote_addr().to_string() << ":" << socket.get_remote_port() << ")";
				logger_.success(ss.view());
			}

		public:

			using AddrType = Addr;
			using SocketType = Socket;
			using DataIterator = Iter;

			QVPNServerDriver(QVPNServerSettings_<Iter> settings)
				: settings_(std::move(settings))
			{
				logger_.info("Starting QVPN Server Driver...");
				auto [b, e] = settings_.get_addrs();
				std::stringstream ss{};
				for (auto& i = b; b < e; ++i)
				{
					auto sock = NetTools::create_socket(i->get_net_proto(), i->get_transport_proto());
					if (!sock.is_valid())
					{
						auto err = std::format("Cannot create socket");
						logger_.fail(err);
						continue;
					}
					
					auto b_res = sock.bind(i->get_ip_address(), i->get_port());
					if (!b_res.success)
					{
						auto err_str = std::format("Failed to bind socket to ({}:{})", i->get_ip_address().to_string(), i->get_port());
						perror(err_str.c_str());
						continue;
					}

					ss << "Init socket on " << sock.get_local_addr().to_string() << ":" << sock.get_local_port();
					logger_.success(ss.str());
					ss.clear();

					vpn_sockets_.emplace_back(std::move(sock));
				}
				if (vpn_sockets_.size() > 0)
					logger_.success("QVPN Server Driver successfully started.");
				else
					logger_.fail("Failed to start QVPN Server Driver. No sockets provided.");
			}

			template <is_database_adapter DB>
			void init(DB& database, Stats& stats)
			{
				for (auto& s : vpn_sockets_)
				{
					auto t = std::thread([this, &s, &database, &stats]() { listen_and_connect_socket_(s, database, stats); });
					socket_threads_.emplace_back(std::move(t));
				}
				auto r_t = std::thread([this]() { listen_response_sockets_(); });
				response_threads_.emplace_back(std::move(r_t));
			}

			bool base_send_data(Socket& socket, const UByte* begin, const UByte* end)
			{
				std::stringstream ss{};
				auto res = socket.send(begin, end);
				if (!res.success)
					return false;
				ss << "Sended to " << socket.get_remote_addr().to_string() << ":" << socket.get_remote_port() << " " << std::distance(begin, end) << " bytes from " << socket.get_local_addr().to_string() << ":" << socket.get_local_port();
				logger_.info(ss.str());
				return res.success;
			}

			void encode_and_send(Socket& socket, const QVPN::Core::DataStructures::QTunnelProxy<Addr>& proxy_data, Iter begin, Iter end)
			{
				auto splitted_packet = encode_data(proxy_data, begin, end);
				for (size_t i = 0; i < splitted_packet.size(); i++)
				{
					auto [b, e] = splitted_packet.get_raw_packet(i);
					auto res = base_send_data(socket, b, e);
					if (!res) // TODO: переделать на возврат
						return;
				}
			}

			SplittedPacket encode_data(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& proxy_data, Iter begin, Iter end)
			{
				// first must be split, after encode
				SplittedPacketView sp_view = packet_manager_.split_packet_view(begin, end);

				// proxy data encoded only in first splitting
				// first splitting will be always
				SplittedPacket sp{};
				auto [pb_data, b, e] = sp_view.get_raw_with_pb_data(0);
				auto first_encoded_data = settings_.layers_encode(pb_data, proxy_data, b, e);
				sp.add_data(first_encoded_data.data(), first_encoded_data.data() + first_encoded_data.size());

				for (auto i = 1; i < sp_view.size(); ++i)
				{
					auto [pb_data_i, bi, ei] = sp_view.get_raw_with_pb_data(i);
					auto encoded_part = settings_.layers_encode(pb_data_i, bi, ei);
					sp.add_data(encoded_part.data(), encoded_part.data() + encoded_part.size());
				}

				return sp;
			}


			std::optional<QTunnelData<Addr>> decode_data(Iter begin, Iter end)
			{
				// first decode, then build
				auto res = settings_.layers_decode(begin, end);
				auto signal = packet_manager_.build_packet(res.data(), res.data() + res.size());
				if (packet_manager_.have_full_packets())
				{
					auto packet = packet_manager_.get_and_pop_packet();
					QTunnelData<Addr> data(std::move(packet.get_data()));
					return data;
				}
				return std::nullopt;
			}

		};


		// proxy spec
		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class NetTools, is_database_adapter Database, is_statistic_adapter Stats, is_logger Logger>
			requires is_net_tools<NetTools>
		class QVPNServerDriver<Iter, Addr, NetTools, Database, Stats, Logger, QVPN::Core::QVPNServerWorkMode::SERVER_PROXY_NODE>
		{

		};

		// anti dpi node spec
		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class NetTools, is_database_adapter Database, is_statistic_adapter Stats, is_logger Logger>
			requires is_net_tools<NetTools>
		class QVPNServerDriver<Iter, Addr, NetTools, Database, Stats, Logger, QVPN::Core::QVPNServerWorkMode::SERVER_ANTI_DPI_NODE>
		{

		};

		// dpi terror spec
		template <std::random_access_iterator Iter, QVPN::Core::is_addr Addr, class NetTools, is_database_adapter Database, is_statistic_adapter Stats, is_logger Logger>
			requires is_net_tools<NetTools>
		class QVPNServerDriver<Iter, Addr, NetTools, Database, Stats, Logger, QVPN::Core::QVPNServerWorkMode::SERVER_DPI_TERROR>
		{

		};

		template <std::random_access_iterator Iter, class VPNServerDriver, is_database_adapter Database, is_statistic_adapter Stats>
			requires is_vpn_server_driver<VPNServerDriver, Database, Stats>
		class VPNServer_ : public VPNServerDriver
		{
		private:


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

