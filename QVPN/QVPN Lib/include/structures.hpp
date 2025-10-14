#pragma once
#include <string_view>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <lib.hpp>


namespace QVPN {
	namespace Core
	{
		namespace DataStructures {


			using Byte = char;
			using UByte = unsigned char;
			using UShort = unsigned short;
			using UInt = unsigned int;
			using ULong = unsigned long long;
			using ubyte_const_iter = std::vector<unsigned char>::const_iterator;

			enum AdapterFlags : ULong {
				DdnsEnabled = 0x1,
				RegisterAdapterSuffix = 0x2,
				DhcpvEnabled = 0x4,
				ReceiveOnly = 0x8,
				NoMulticast = 0x10,
				Ipv6OtherStatefulConfig = 0x20,
				NetbiosOverTcpipEnabled = 0x40,
				Ipv4Enabled = 0x80,
				Ipv6Enabled = 0x100,
				Ipv6ManagedAddressConfigurationSupported = 0x200
			};

			template <class AdapterHandle>
			class Adapter final {
			private:
				std::string adapter_name;
				std::string adapter_desc;
				std::string friendly_name;
				std::vector<Byte> PhysAdress;
				QVPN::Core::IPv4Address address;
				ULong Flags = 0;
				ULong Mtu = 0;
				AdapterHandle handle;

			public:

				Adapter()
				{
					PhysAdress.reserve(10);
					handle = nullptr;
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname)
				{
					PhysAdress.reserve(10);
				}

				Adapter(std::string_view a_name, std::string_view a_desc, const QVPN::Core::IPv4Address& addr)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_name), address(addr)
				{

				}

				Adapter(std::string_view a_name, std::string_view a_desc, const QVPN::Core::IPv4Address& addr, AdapterHandle hnd)
					: Adapter(a_name, a_desc, addr)
				{
					handle = hnd;
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, AdapterHandle a_handle)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), handle(a_handle)
				{
					PhysAdress.reserve(10);
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, ULong flags, ULong mtu)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), Flags(flags), Mtu(mtu)
				{
					PhysAdress.reserve(10);
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, AdapterHandle a_handle, ULong flags, ULong mtu)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), Flags(flags), Mtu(mtu), handle(a_handle)
				{
					PhysAdress.reserve(10);
				}

				Adapter(const Byte* begin, const Byte* end)
					: QVPN::Core::DataStructures::Adapter::Adapter()
				{
					PhysAdress.insert(PhysAdress.cend(), begin, end);
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, const Byte* begin, const Byte* end)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname)
				{
					PhysAdress.reserve(10);
					PhysAdress.insert(PhysAdress.cend(), begin, end);
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, ULong flags, ULong mtu, const Byte* begin, const Byte* end)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), Flags(flags), Mtu(mtu)
				{
					PhysAdress.reserve(10);
					PhysAdress.insert(PhysAdress.cend(), begin, end);
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, AdapterHandle a_handle, const Byte* begin, const Byte* end)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), handle(a_handle)
				{
					PhysAdress.reserve(10);
					PhysAdress.insert(PhysAdress.cend(), begin, end);
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, ULong flags, AdapterHandle a_handle, ULong mtu, const Byte* begin, const Byte* end)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), Flags(flags), Mtu(mtu), handle(a_handle)
				{
					PhysAdress.reserve(10);
					PhysAdress.insert(PhysAdress.cend(), begin, end);
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, ULong flags, ULong mtu, std::vector<Byte>::const_iterator begin, std::vector<Byte>::const_iterator end)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), Flags(flags), Mtu(mtu)
				{
					PhysAdress.reserve(10);
					PhysAdress.insert(PhysAdress.cend(), begin, end);
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, AdapterHandle a_handler, ULong flags, ULong mtu, const Byte* begin, const Byte* end)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), Flags(flags), Mtu(mtu), handle(a_handler)
				{
					PhysAdress.reserve(10);
					PhysAdress.insert(PhysAdress.cend(), begin, end);
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, AdapterHandle a_handler, ULong flags, ULong mtu, std::vector<Byte>::const_iterator begin, std::vector<Byte>::const_iterator end)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), Flags(flags), Mtu(mtu), handle(a_handler)
				{
					PhysAdress.reserve(10);
					PhysAdress.insert(PhysAdress.cend(), begin, end);
				}


				void set_handle(const AdapterHandle a_handle)
				{
					handle = a_handle;
				}

				void set_data(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, ULong flags, ULong mtu)
				{
					adapter_name = a_name;
					adapter_desc = a_desc;
					friendly_name = a_fname;
					Flags = flags;
					Mtu = mtu;
				}

				void set_name(std::string_view a_name)
				{
					adapter_name = a_name;
				}

				void set_desc(std::string_view a_desc)
				{
					adapter_desc = a_desc;
				}

				void set_friendly_name(std::string_view a_fname)
				{
					friendly_name = a_fname;
				}

				void set_phys_addr(std::vector<Byte>::const_iterator begin, std::vector<Byte>::const_iterator end)
				{
					PhysAdress.clear();
					PhysAdress.insert(PhysAdress.end(), begin, end);
				}

				void set_phys_addr(const Byte* begin, const Byte* end)
				{
					PhysAdress.clear();
					PhysAdress.insert(PhysAdress.end(), begin, end);
				}

				void set_phys_addr(std::unique_ptr<Byte> begin, std::unique_ptr<Byte> end)
				{
					PhysAdress.clear();
					PhysAdress.insert(PhysAdress.end(), begin.get(), end.get());
				}

				void set_flags(ULong flags)
				{
					Flags = flags;
				}

				void set_mtu(ULong mtu)
				{
					Mtu = mtu;
				}


				std::string_view get_name() const
				{
					return adapter_name;
				}

				std::string_view get_desc() const
				{
					return adapter_desc;
				}

				std::string_view get_friendly_name() const
				{
					return friendly_name;
				}

				std::pair<std::vector<Byte>::const_iterator, std::vector<Byte>::const_iterator> get_phys_addr() const
				{
					return std::make_pair<>(PhysAdress.cbegin(), PhysAdress.cend());
				}

				ULong get_flags() const
				{
					return Flags;
				}

				ULong get_mtu() const
				{
					return Mtu;
				}

				ULong get_flag(AdapterFlags flag) const
				{
					return Flags & flag;
				}

				const AdapterHandle get_handle() const
				{
					return const_cast<AdapterHandle>(handle);
				}

				const QVPN::Core::IPv4Address& get_addr() const
				{
					return address;
				}

				~Adapter()
				{

				}


			};


			template<class EndianessPacketLike, class AdapterHandle>
			concept is_adapter_criteria =
				requires (EndianessPacketLike t) {
					{ true };
					{ t.check_criteria(std::declval<const Adapter<AdapterHandle>&>()) } -> std::same_as<bool>;
			};

			template <class AdapterHandle>
			class AdapterList final : public std::vector<Adapter<AdapterHandle>> {

			public:

				template<class U, class AdapterHandle> requires is_adapter_criteria<U, AdapterHandle>
				std::unique_ptr<Adapter<AdapterHandle>> get_default_adapter()
				{
					for (const auto& it : *this)
					{
						if (U::check_criteria(it))
						{
							return std::make_unique<Adapter<AdapterHandle>>(it);
						}
					}
					return nullptr;
				}

				~AdapterList() {}
			};


			template <class EndianessPacketLike>
			concept EndianessPacket =
				requires (EndianessPacketLike t) {
					{ true };
					{ t.get_version() } -> std::same_as<UByte>;
					{ t.get_header_length() } -> std::same_as<UByte>;
					{ t.get_dscp() } -> std::same_as<UByte>;
					{ t.get_ecn() } -> std::same_as<UByte>;
					{ t.get_total_length() } -> std::same_as<UShort>;
					{ t.get_id() } -> std::same_as<UShort>;
					{ t.get_flags() } -> std::same_as<UByte>;
					{ t.get_offset() } -> std::same_as<UShort>;
					{ t.get_ttl() } -> std::same_as<UByte>;
					{ t.get_checksum() } -> std::same_as<UShort>;
					{ t.get_source() } -> std::same_as<UInt>;
					{ t.get_dest() } -> std::same_as<UInt>;
					{ t.get_additional_header() } -> std::same_as<std::pair<ubyte_const_iter, ubyte_const_iter>>;
					{ t.get_data() } -> std::same_as<std::pair<ubyte_const_iter, ubyte_const_iter>>;
					{ t.to_friendly_view() } -> std::same_as<std::string>;
			};


			class Ipv4PacketLittleEndian {

			private:
				UByte header_[20];
				std::vector<UByte> additional_header_;
				std::vector<UByte> data_;

			public:

				Ipv4PacketLittleEndian(unsigned char* begin, int size);
				Ipv4PacketLittleEndian(UByte* begin, UByte* end);
				Ipv4PacketLittleEndian(ubyte_const_iter begin, ubyte_const_iter end);

				void parse_packet(UByte* begin, UByte* end);

				UByte get_version() const;
				UByte get_header_length() const;

				UByte get_dscp() const;
				UByte get_ecn() const;

				UShort get_total_length() const;

				UShort get_id() const;

				UByte  get_flags() const;
				UShort get_offset() const;

				UByte get_ttl() const;
				UByte get_protocol() const;

				UShort get_checksum() const;

				UInt get_source() const;
				UInt get_dest() const;

				std::pair<ubyte_const_iter, ubyte_const_iter> get_additional_header() const;

				std::pair<ubyte_const_iter, ubyte_const_iter> get_data() const;

				std::string to_friendly_view() const;
			};


			template <EndianessPacket EndianessPacketLike>
			class Ipv4Packet_ final : public EndianessPacketLike {

			public:

				Ipv4Packet_(unsigned char* begin, int size)
					: EndianessPacketLike(begin, size) {}

				Ipv4Packet_(UByte* begin, UByte* end)
					: EndianessPacketLike(begin, end) {}

				Ipv4Packet_(ubyte_const_iter begin, ubyte_const_iter end)
					: EndianessPacketLike(begin, end) {}

			};
			


			using Ipv4Packet = Ipv4Packet_<Ipv4PacketLittleEndian>;
}
	}
}

