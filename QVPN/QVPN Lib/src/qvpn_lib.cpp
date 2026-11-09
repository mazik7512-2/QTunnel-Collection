#include "qvpn_lib.hpp"
#include <sstream>
#include <fstream>
#include <random>
#include <qvpn_tools.hpp>


using UByte = QVPN::Core::BaseTypes::UByte;
using UShort = QVPN::Core::BaseTypes::UShort;

QVPN::Core::IPv4Address::IPv4Address()
{
	ip_ = { 0, 0, 0, 0 };
}

QVPN::Core::IPv4Address::IPv4Address(AddrBytes_t data)
{
	ip_[0] = data[0];
	ip_[1] = data[1];
	ip_[2] = data[2];
	ip_[3] = data[3];
}

QVPN::Core::IPv4Address::IPv4Address(std::string_view data)
{
	auto vec = Tools::parse_net_addr(data);
	std::copy(vec.begin(), vec.end(), ip_.begin());
}

QVPN::Core::IPv4Address::IPv4Address(std::initializer_list<UByte> list)
{
	std::copy(list.begin(), list.end(), ip_.begin());
}

QVPN::Core::IPv4Address::IPv4Address(AddrInt_t data)
{
	UByte first = data >> 24 & 0xFF;
	UByte second = data >> 16 & 0xFF;
	UByte third = data >> 8 & 0xFF;
	UByte four = data & 0xFF;
	ip_ = { first, second, third, four };
}

QVPN::Core::IPv4Address::IPv4Address(UByte first, UByte second, UByte third, UByte four)
	: ip_{ first, second, third, four }
{}

QVPN::Core::IPv4Address::IPv4Address(const IPv4Address& other)
{
	std::copy(other.ip_.begin(), other.ip_.end(), ip_.begin());
}

QVPN::Core::IPv4Address::IPv4Address(IPv4Address&& other)
{
	ip_ = std::exchange(other.ip_, {});
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(const IPv4Address& other)
{
	if (this == &other)
		return *this;
	std::copy(other.ip_.begin(), other.ip_.end(), ip_.begin());
	return *this;
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(IPv4Address&& other)
{
	if (this == &other)
		return *this;
	ip_ = std::exchange(other.ip_, {});
	return *this;
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(const AddrBytes_t& other)
{
	std::copy(other.begin(), other.end(), ip_.begin());
	return *this;
}

QVPN::Core::IPv4Address& QVPN::Core::IPv4Address::operator=(AddrBytes_t&& other)
{
	ip_ = std::exchange(other, {});
	return *this;
}

QVPN::Core::IPv4Address::UByte QVPN::Core::IPv4Address::operator[](int elem) const
{
	return ip_[elem];
}

bool QVPN::Core::IPv4Address::operator==(const IPv4Address& other) const
{
	return to_uint() == other.to_uint();
}

QVPN::Core::NetProtocol QVPN::Core::IPv4Address::get_addr_family() const
{
	return NetProtocol::IPv4;
}

size_t QVPN::Core::IPv4Address::get_addr_size() const
{
	return 4;
}

std::array<QVPN::Core::IPv4Address::UByte, 4> QVPN::Core::IPv4Address::to_bytes() const
{
	return ip_;
}

std::string QVPN::Core::IPv4Address::to_string() const
{
	std::stringstream ip;
	ip << (int)ip_[0] << "." << (int)ip_[1] << "." << (int)ip_[2] << "." << (int)ip_[3];
	return ip.str();

}

QVPN::Core::BaseTypes::UInt QVPN::Core::IPv4Address::to_uint() const
{
	return (ip_[0] << 24 | ip_[1] << 16 | ip_[2] << 8 | ip_[3]);
}

QVPN::Core::IPv4Address::~IPv4Address()
{}


// ipv6

QVPN::Core::IPv6Address::IPv6Address()
{
	ip_ = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
}

QVPN::Core::IPv6Address::IPv6Address(AddrBytes_t data)
{
	std::copy(data.begin(), data.end(), ip_.begin());
}

QVPN::Core::IPv6Address::IPv6Address(std::initializer_list<UByte> list)
{
	std::copy(list.begin(), list.end(), ip_.begin());
}

QVPN::Core::IPv6Address::IPv6Address(UByte data[16])
{
	std::copy(data, data + 16, ip_.begin());
}

QVPN::Core::IPv6Address::IPv6Address(std::string_view data)
{
	auto vec = Tools::parse_net_addr(data);
	std::copy(vec.begin(), vec.end(), ip_.begin());
}

QVPN::Core::NetProtocol QVPN::Core::IPv6Address::get_addr_family() const
{
	return NetProtocol::IPv6;
}

size_t QVPN::Core::IPv6Address::get_addr_size() const
{
	return 6;
}

QVPN::Core::IPv6Address::AddrBytes_t QVPN::Core::IPv6Address::to_bytes() const
{
	return ip_;
}

std::string QVPN::Core::IPv6Address::to_string() const
{
	std::stringstream ip;
	for (size_t i = 0; i < ip_.size(); i++)
	{
		ip << static_cast<int>(ip_[i]) << ".";
	}
	auto temp = ip.str();
	auto str = temp.substr(0, temp.size() - 2);
	str.append("\0");
	return str;
}

QVPN::Core::IPv6Address::AddrInt_t QVPN::Core::IPv6Address::to_uint() const
{
	return ip_;
}

QVPN::Core::QVPNWhitelistElement::QVPNWhitelistElement()
	: host_(""), priority_(QVPNWhitelistElement::default_priority)
{}

QVPN::Core::QVPNWhitelistElement::QVPNWhitelistElement(std::string_view host, int priority)
	: host_(host), priority_(priority)
{}

void QVPN::Core::QVPNWhitelistElement::set_host(std::string_view host)
{
	host_ = host;
}

void QVPN::Core::QVPNWhitelistElement::set_priority(int priority)
{
	priority_ = priority;
}

std::string_view QVPN::Core::QVPNWhitelistElement::get_host() const
{
	return host_;
}

int QVPN::Core::QVPNWhitelistElement::get_priority() const
{
	return priority_;
}

QVPN::Core::QVPNWhitelistDefaultStrategy::QVPNWhitelistDefaultStrategy()
	: map_{}
{}

QVPN::Core::QVPNWhitelistElementView QVPN::Core::QVPNWhitelistDefaultStrategy::get_host_by_params(const StrategyFilter& param)
{
	return map_[param];
}

QVPN::Core::QVPNWhitelistElementView::QVPNWhitelistElementView(const QVPNWhitelistElement& elem)
	: host_(elem.get_host()), priority_(elem.get_priority())
{}

std::string_view QVPN::Core::QVPNWhitelistElementView::get_host() const
{
	return host_;
}

int QVPN::Core::QVPNWhitelistElementView::get_priority() const
{
	return priority_;
}

QVPN::Core::QVPNWhitelist::QVPNWhitelist()
	: whitelist_{}
{}

QVPN::Core::QVPNWhitelist::QVPNWhitelist(std::string_view path)
	: QVPNWhitelist()
{
	parse_whitelist(path);
}

void QVPN::Core::QVPNWhitelist::parse_whitelist(std::string_view path)
{
	std::ifstream wlist{};
	//auto full_path = std::filesystem::current_path() / path.data();
	wlist.open(path.data());
	std::string line;

	if (!wlist.is_open())
		return;

	std::string host;
	int priority;
	while (wlist >> host >> priority)
		whitelist_.emplace_back(host, priority);

	wlist.close();
}

std::string_view QVPN::Core::QVPNWhitelist::get_random_host() const
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<int> dist(0, whitelist_.size() - 1);

	return whitelist_[dist(gen)].get_host();
}

std::string_view QVPN::Core::QVPNWhitelist::get_host(size_t i) const
{
	return whitelist_[i].get_host();
}

size_t QVPN::Core::QVPNWhitelist::get_size() const
{
	return whitelist_.size();
}

// IP Address

QVPN::Core::NetAddr::NetAddr()
{
	ip_ = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
}

QVPN::Core::NetAddr::NetAddr(AddrBytes_t data)
{
	std::copy(data.cbegin(), data.cend(), std::back_inserter(ip_));
}

QVPN::Core::NetAddr::NetAddr(std::initializer_list<UByte> list)
{
	std::copy(list.begin(), list.end(), std::back_inserter(ip_));
}

QVPN::Core::NetAddr::NetAddr(AddrInt_t data)
{
	ip_.push_back(data >> 24 & 0xFF);
	ip_.push_back(data >> 16 & 0xFF);
	ip_.push_back(data >> 8 & 0xFF);
	ip_.push_back(data & 0xFF);
}

QVPN::Core::NetAddr::NetAddr(const IPv4Address& data)
{
	auto bytes = data.to_bytes();
	std::copy(bytes.cbegin(), bytes.cend(), std::back_inserter(ip_));
}

QVPN::Core::NetAddr::NetAddr(const IPv6Address& data)
{
	auto bytes = data.to_bytes();
	std::copy(bytes.cbegin(), bytes.cend(), std::back_inserter(ip_));
}

QVPN::Core::NetAddr::NetAddr(std::string_view data)
{
	ip_ = Tools::parse_net_addr(data);
}

size_t QVPN::Core::NetAddr::get_addr_size() const
{
	return ip_.size();
}

QVPN::Core::NetProtocol QVPN::Core::NetAddr::get_addr_family() const
{
	if (ip_.size() == 4)
		return NetProtocol::IPv4;
	else if (ip_.size() == 16)
		return NetProtocol::IPv6;
	return NetProtocol::NET_UNDEFINED;
}

QVPN::Core::IPv4Address QVPN::Core::NetAddr::to_ipv4() const
{
	std::array<UByte, 4> data{ ip_[0], ip_[1], ip_[2], ip_[3] };
	return IPv4Address(data);
}

QVPN::Core::IPv6Address QVPN::Core::NetAddr::to_ipv6() const
{
	std::array<UByte, 16> data{};
	std::copy(ip_.cbegin(), ip_.cbegin() + 16, data.begin());
	return IPv6Address(data);
}

QVPN::Core::BaseTypes::UByte QVPN::Core::NetAddr::operator[](int elem) const
{
	return ip_[elem];
}

QVPN::Core::NetAddr::AddrBytes_t QVPN::Core::NetAddr::to_bytes() const
{
	return ip_;
}

std::string QVPN::Core::NetAddr::to_string() const
{
	std::stringstream ip;
	for (size_t i = 0; i < ip_.size(); i++)
	{
		ip << static_cast<int>(ip_[i]) << ".";
	}
	auto temp = ip.str();
	auto str = temp.substr(0, temp.size() - 1);
	str.append("\0");
	return str;
}

QVPN::Core::NetAddr::AddrInt_t QVPN::Core::NetAddr::to_uint() const
{
	if (get_addr_family() == NetProtocol::IPv4)
		return ip_[0] << 24 | ip_[1] << 16 | ip_[2] << 8 | ip_[3];
	return 0;
}

bool QVPN::Core::NetAddr::operator==(const NetAddr& other) const
{
	// TODO: доделать сравнение на тип + INADDR_ANY
	bool res = true;
	auto min_size = std::min(other.get_addr_size(), get_addr_size());
	for (size_t i = 0; i < min_size; i++)
	{
		if (ip_[i] != other.ip_[i])
		{
			res = false;
			break;
		}
	}
	return res;
}

// QVPN Socket Data

std::string QVPN::Core::QVPNSocketData::to_string() const
{
	std::stringstream ss{};

	ss << "(" << static_cast<BaseTypes::UInt>(net_proto) << "," << static_cast<BaseTypes::UInt>(transport_proto) << ") " << local_addr.to_string() << ":" << local_port << "-" << remote_addr.to_string() << ":" << remote_port;

	auto str = ss.str();
	return str;
}

QVPN::Core::QVPNSocketSettings::QVPNSocketSettings(bool ip_data, int receive_timeout_ms, bool tcp_no_delay)
{
	ip_header_ = ip_data;
	recv_timeout_ = receive_timeout_ms;
	tcp_no_delay_ = tcp_no_delay;
}

bool QVPN::Core::QVPNSocketSettings::ip_header() const
{
	return ip_header_;
}

int QVPN::Core::QVPNSocketSettings::receive_timeout_ms() const
{
	return recv_timeout_;
}

bool QVPN::Core::QVPNSocketSettings::tcp_no_delay() const
{
	return tcp_no_delay_;
}


// QVPN Lib 


consteval std::string_view QVPN::Core::QVPNLib::get_short_library_name() const
{
	return short_lib_name_;
}

consteval std::string_view QVPN::Core::QVPNLib::get_library_name() const
{
	return lib_name_;
}

consteval QVPN::Core::QVPNLib::UInt QVPN::Core::QVPNLib::get_major_version() const
{
	return major_ver_;
}

consteval QVPN::Core::QVPNLib::UInt QVPN::Core::QVPNLib::get_minor_version() const
{
	return minor_ver_;
}

consteval QVPN::Core::QVPNLib::UInt QVPN::Core::QVPNLib::get_patch_version() const
{
	return patch_ver_;
}

constexpr std::string QVPN::Core::QVPNLib::get_library_version() const
{
	std::string lib_ver(u_number_to_string(major_ver_));
	lib_ver += ".";
	lib_ver += u_number_to_string(minor_ver_);
	lib_ver += ".";
	lib_ver += u_number_to_string(patch_ver_);
	return lib_ver;
}

constexpr std::string QVPN::Core::QVPNLib::get_full_library_name() const
{
	std::string full_lib_name(lib_name_);
	full_lib_name += " v";
	full_lib_name += u_number_to_string(major_ver_);
	full_lib_name += ".";
	full_lib_name += u_number_to_string(minor_ver_);
	full_lib_name += ".";
	full_lib_name += u_number_to_string(patch_ver_);
	return full_lib_name;
}

consteval bool QVPN::Core::QVPNLib::is_compatible(UInt major, UInt minor, UInt patch) const
{
	if (last_compatible_major_ver_ > major)
		return false;
	if (last_compatible_minor_ver_ > minor)
		return false;
	if (last_compatible_patch_ver_ > patch)
		return false;
	return true;
}

std::string_view QVPN::Core::QVPNModeVerbose::get_client_mode_verbose(QVPNClientWorkMode mode)
{
	return client_verboses_[mode];
}

std::string_view QVPN::Core::QVPNModeVerbose::get_server_mode_verbose(QVPNServerWorkMode mode)
{
	return server_verboses_[mode];
}

QVPN::Core::QVPNClientWorkMode QVPN::Core::QVPNModeVerbose::get_client_mode_by_verbose(std::string_view mode)
{
	return client_modes_[mode];
}

QVPN::Core::QVPNServerWorkMode QVPN::Core::QVPNModeVerbose::get_server_mode_by_verbose(std::string_view mode)
{
	return server_modes_[mode];
}

std::string QVPN::Core::QVPNServerSocketData::to_string() const
{
	std::stringstream ss{};

	ss << "(" << static_cast<BaseTypes::UInt>(net_proto) << "," << static_cast<BaseTypes::UInt>(transport_proto) << ") (Client data:" << client_local_addr.to_string() << ":" << local_port << "<=>" << server_local_addr.to_string() << ":" << local_port << ")-" << remote_addr.to_string() << ":" << remote_port;

	auto str = ss.str();
	return str;
}

std::string QVPN::Core::QVPNServerSocketData::to_string_no_server_local_addr() const
{
	std::stringstream ss{};

	ss << "(" << static_cast<BaseTypes::UInt>(net_proto) << "," << static_cast<BaseTypes::UInt>(transport_proto) << ") (Client data:" << client_local_addr.to_string() << ":" << local_port << ")-" << remote_addr.to_string() << ":" << remote_port;

	auto str = ss.str();
	return str;
}

std::string_view QVPN::Core::QVPNVerboser::net_verbose(NetProtocol net)
{
	return net_verbose_[net];
}

void QVPN::Core::QVPNVerboser::register_net_verbose(NetProtocol net, std::string_view verbose)
{
	net_verbose_[net] = verbose;
}

std::string_view QVPN::Core::QVPNVerboser::transport_verbose(TransportProtocol transport)
{
	return transport_verbose_[transport];
}

void QVPN::Core::QVPNVerboser::register_transport_verbose(TransportProtocol transport, std::string_view verbose)
{
	transport_verbose_[transport] = verbose;
}

std::string QVPN::Core::QVPNVerboser::tcp_flags(TcpFlagsObject flags)
{
	std::string flags_data{"["};
	for (size_t i = 0; i < tcp_flags_.size() ; ++i)
	{
		auto flag = flags[i];
		if (flag)
		{
			flags_data.append(tcp_flags_[i]);
			flags_data.append(" ");
		}
	}
	if (flags_data.size() >= 2)
	{
		flags_data.pop_back();
		flags_data.append("]");
	}
	return flags_data;
}

std::string QVPN::Core::QVPNVerboser::ipv4_flags(UByte flags)
{
	std::string flags_data{ "[" };

	for (size_t i = 0; i < ipv4_flags_.size(); i++)
	{
		auto flag = flags >> i & 0x01;
		if (flag)
		{
			flags_data.append(ipv4_flags_[i]);
			flags_data.append(" ");
		}
	}
	if (flags_data.size() >= 2)
	{
		flags_data.pop_back();
		flags_data.append("]");
	}
	return flags_data;
}

std::string_view QVPN::Core::QVPNVerboser::tcp_option(UByte option)
{
	return tcp_options_[option];
}

void QVPN::Core::QVPNVerboser::register_tcp_option(TCPOptions option, std::string_view verbose)
{
	tcp_options_[option] = verbose;
}

void QVPN::Core::QVPNVerboser::register_addr_verbose(const NetAddr& addr, std::string_view verbose, std::string_view cmd_color)
{
	VerbosedNetAddr v_addr(addr, verbose, cmd_color);
	verb_addrs_[addr] = v_addr;
}

std::string QVPN::Core::QVPNVerboser::addr_verbose(const NetAddr& addr)
{
	std::stringstream ss{};

	if (!verb_addrs_.contains(addr))
	{
		ss << addr.to_string();
		return ss.str();
	}
		
	auto& v_addr = verb_addrs_[addr];
	ss << v_addr.get_color() << v_addr.to_string() << " [" << CmdColorizer::BOLD << v_addr.get_verbose() << "]" << CmdColorizer::ENDC << CmdColorizer::DEFAULT;
	return ss.str();
	
}

std::string_view QVPN::Core::QVPNVerboser::client_mode_verbose(QVPNClientWorkMode mode)
{
	return client_work_modes_[mode];
}

std::string_view QVPN::Core::QVPNVerboser::server_mode_verbose(QVPNServerWorkMode mode)
{
	return server_work_modes_[mode];
}

std::string QVPN::Core::QVPNVerboser::work_mode_verbose(BaseTypes::UInt mode)
{
	std::stringstream ss{};

	auto cw_mode = static_cast<QVPNClientWorkMode>(mode);
	auto sw_mode = static_cast<QVPNServerWorkMode>(mode);

	ss << client_mode_verbose(cw_mode) << "/" << server_mode_verbose(sw_mode);

	return ss.str();
}

std::string_view QVPN::Core::QVPNVerboser::crypto_mode_verbose(QVPN_Crypto crypto)
{
	return crypto_modes_[crypto];
}


QVPN::Core::TcpFlagsObject::TcpFlagsObject(TCPFlags flags)
	: flags_(flags)
{}

QVPN::Core::TcpFlagsObject::TcpFlagsObject(UShort flags)
	: flags_(flags)
{}

QVPN::Core::TcpFlagsObject::TcpFlagsObject(UByte ns, UByte cwr, UByte ecn, UByte urg, UByte ack, UByte psh, UByte rst, UByte syn, UByte fin)
	: flags_(0)
{
	flags_ = ns << 8 | cwr << 7 | ecn << 6 | urg << 5 | ack << 4 | psh << 3 | rst << 2 | syn << 1 | fin;
}

UByte QVPN::Core::TcpFlagsObject::get_ns() const
{
	return flags_ >> 8 & 0x1;
}

UByte QVPN::Core::TcpFlagsObject::get_cwr() const
{
	return flags_ >> 7 & 0x1;
}

UByte QVPN::Core::TcpFlagsObject::get_ecn() const
{
	return flags_ >> 6 & 0x1;
}

UByte QVPN::Core::TcpFlagsObject::get_urg() const
{
	return flags_ >> 5 & 0x1;
}

UByte QVPN::Core::TcpFlagsObject::get_ack() const
{
	return flags_ >> 4 & 0x1;
}

UByte QVPN::Core::TcpFlagsObject::get_psh() const
{
	return flags_ >> 3 & 0x1;
}

UByte QVPN::Core::TcpFlagsObject::get_rst() const
{
	return flags_ >> 2 & 0x1;
}

UByte QVPN::Core::TcpFlagsObject::get_syn() const
{
	return flags_ >> 1 & 0x1;
}

UByte QVPN::Core::TcpFlagsObject::get_fin() const
{
	return flags_ & 0x1;
}

UByte QVPN::Core::TcpFlagsObject::get_without_ns() const
{
	return flags_ & 0xFF;
}

QVPN::Core::TcpFlagsObject::operator UShort() const
{
	return flags_;
}

UByte QVPN::Core::TcpFlagsObject::operator[](size_t i) const
{
	return static_cast<UByte>(flags_ >> i & 0x1);
}


// Objects Buffer


QVPN::Core::ObjectsBuffer::ObjectsBuffer(UByte* begin, UByte* end)
	: data_(begin, end)
{
	add_object_separators(0, std::distance(begin, end));
}

QVPN::Core::ObjectsBuffer::ObjectsBuffer(const ObjectsBuffer & other)
	: ObjectsSeparator(other)
{
	data_ = other.data_;
}

QVPN::Core::ObjectsBuffer::ObjectsBuffer(ObjectsBuffer && other) noexcept
	: ObjectsSeparator(std::move(other))
{
	data_ = std::move(other.data_);
}

QVPN::Core::ObjectsBuffer& QVPN::Core::ObjectsBuffer::operator=(const ObjectsBuffer & other)
{
	ObjectsSeparator::operator=(other);
	data_ = other.data_;
	return *this;
}

QVPN::Core::ObjectsBuffer& QVPN::Core::ObjectsBuffer::operator=(ObjectsBuffer&& other) noexcept
{
	ObjectsSeparator::operator=(std::move(other));
	data_ = std::move(other.data_);
	return *this;
}

size_t QVPN::Core::ObjectsBuffer::get_objects_num() const
{
	return ObjectsSeparator::get_objects_num();
}

void QVPN::Core::ObjectsBuffer::add_object(UByte* begin, UByte* end)
{
	auto start = data_.size();
	data_.insert(data_.end(), begin, end);
	add_object_separators(start, std::distance(begin, end));

}

void QVPN::Core::ObjectsBuffer::add_data_to_object(size_t i, UByte * begin, UByte * end)
{
	const auto& [b, e] = get_object_separators(i);
	data_.insert(data_.begin() + e, begin, end);
	add_data_to_object_separators(i, std::distance(begin, end));
}

void QVPN::Core::ObjectsBuffer::add_data_to_last_object(UByte * begin, UByte * end)
{
	data_.insert(data_.end(), begin, end);
	add_data_to_last_object_separators(std::distance(begin, end));
}

void QVPN::Core::ObjectsBuffer::split_last_object(size_t size)
{
	split_last_object_separators(size);
}

size_t QVPN::Core::ObjectsBuffer::get_object_offset(size_t i) const
{
	return ObjectsSeparator::get_object_offset(i);
}

size_t QVPN::Core::ObjectsBuffer::get_full_size() const
{
	return data_.size();
}

std::pair<UByte*, UByte*> QVPN::Core::ObjectsBuffer::get_object(size_t i)
{
	auto [b, e] = get_object_separators(i);
	return std::pair<UByte*, UByte*>(data_.data() + b, data_.data() + e);
}

std::pair<const UByte*, const UByte*> QVPN::Core::ObjectsBuffer::get_object(size_t i) const
{
	const auto& [b, e] = get_object_separators(i);
	return std::pair<const UByte*, const UByte*>(data_.data() + b, data_.data() + e);
}

std::vector<UByte> QVPN::Core::ObjectsBuffer::get_object_data(size_t i) const
{
	auto [b, e] = get_object_separators(i);
	return std::vector<UByte>(data_.data() + b, data_.data() + e);
}

std::pair<UByte*, UByte*> QVPN::Core::ObjectsBuffer::get_objects_by_size(size_t size)
{
	auto [b, e] = get_objects_separators_by_size(size);
	return std::pair<UByte*, UByte*>(data_.data() + b, data_.data() + e);
}

std::pair<const UByte*, const UByte*> QVPN::Core::ObjectsBuffer::get_objects_by_size(size_t size) const
{
	auto [b, e] = get_objects_separators_by_size(size);
	return std::pair<const UByte*, const UByte*>(data_.data() + b, data_.data() + e);
}

std::pair<UByte*, UByte*> QVPN::Core::ObjectsBuffer::get_objects_by_num(size_t size)
{
	auto [b, e] = get_objects_separators_by_num(size);
	return std::pair<UByte*, UByte*>(data_.data() + b, data_.data() + e);
}

std::pair<const UByte*, const UByte*> QVPN::Core::ObjectsBuffer::get_objects_by_num(size_t size) const
{
	auto [b, e] = get_objects_separators_by_num(size);
	return std::pair<const UByte*, const UByte*>(data_.data() + b, data_.data() + e);
}

std::vector<UByte> QVPN::Core::ObjectsBuffer::get_objects_data_by_size(size_t size) const
{
	auto [b, e] = get_objects_separators_by_size(size);
	return std::vector<UByte>(data_.data() + b, data_.data() + e);
}

std::pair<UByte*, UByte*> QVPN::Core::ObjectsBuffer::get_last_object()
{
	auto [b, e] = get_last_object_separators();
	return std::pair<UByte*, UByte*>(data_.data()  + b, data_.data() + e);
}

std::pair<const UByte*, const UByte*> QVPN::Core::ObjectsBuffer::get_last_object() const
{
	auto [b, e] = get_last_object_separators();
	return std::pair<const UByte*, const UByte*>(data_.data() + b, data_.data() + e);
}

std::vector<UByte> QVPN::Core::ObjectsBuffer::get_last_object_data() const
{
	auto [b, e] = get_last_object_separators();
	return std::vector<UByte>(data_.begin() + b, data_.begin() + e);
}

void QVPN::Core::ObjectsBuffer::weak_pop_last()
{
	pop_last_separators();
}

void QVPN::Core::ObjectsBuffer::weak_pop_first()
{
	pop_first_separators();
}

void QVPN::Core::ObjectsBuffer::pop_last()
{
	auto [b, e] = get_last_object_separators();
	pop_last_separators();
	data_.erase(data_.begin() + b, data_.begin() + e);
}

void QVPN::Core::ObjectsBuffer::pop_first()
{
	auto [b, e] = get_first_object_separators();
	pop_first_separators();
	data_.erase(data_.begin() + b, data_.begin() + e);
}

void QVPN::Core::ObjectsBuffer::pop(size_t i)
{
	auto [b, e] = get_object_separators(i);
	pop_object_separators(i);
	data_.erase(data_.begin() + b, data_.begin() + e);
}

void QVPN::Core::ObjectsBuffer::pop_by_size(size_t size)
{
	auto [b, e] = get_objects_separators_by_size(size);
	pop_separators_by_size(size);
	data_.erase(data_.begin() + b, data_.begin() + e);
}

void QVPN::Core::ObjectsBuffer::pop_objects(size_t size)
{
	auto [b, e] = get_objects_separators_by_num(size);
	pop_objects_separators(size);
	data_.erase(data_.begin() + b, data_.begin() + e);
}

void QVPN::Core::ObjectsBuffer::weak_pop_by_size(size_t size)
{
	pop_separators_by_size(size);
}

void QVPN::Core::ObjectsBuffer::weak_pop_objects(size_t size)
{
	pop_objects_separators(size);
}

void QVPN::Core::ObjectsBuffer::clear_weak_pop()
{
	auto [bf, ef] = get_first_object_separators();
	auto [be, ee] = get_last_object_separators();

	data_.erase(data_.begin(), data_.begin() + bf); // clear from front weak_pop
	data_.erase(data_.begin() + ee, data_.end()); // clear from back weak_pop
}

std::pair<UByte*, UByte*> QVPN::Core::ObjectsBuffer::to_bytes()
{
	return std::pair<UByte*, UByte*>(data_.data(), data_.data() + data_.size());
}

std::pair<const UByte*, const UByte*> QVPN::Core::ObjectsBuffer::to_bytes() const
{
	return std::pair<const UByte*, const UByte*>(data_.data(), data_.data() + data_.size());
}


// Objects buffer view


QVPN::Core::ObjectsBufferView::ObjectsBufferView(UByte* begin, UByte* end)
	: data_(begin), data_size_(std::distance(begin, end))
{
	add_object_separators(0, data_size_);
}

QVPN::Core::ObjectsBufferView::ObjectsBufferView(const ObjectsBufferView& other)
	: ObjectsSeparator(other)
{
	data_ = other.data_;
	data_size_ = other.data_size_;
}

QVPN::Core::ObjectsBufferView::ObjectsBufferView(ObjectsBufferView&& other) noexcept
	: ObjectsSeparator(std::move(other))
{
	data_ = std::move(other.data_);
	data_size_ = std::move(other.data_size_);
}

QVPN::Core::ObjectsBufferView& QVPN::Core::ObjectsBufferView::operator=(const ObjectsBufferView& other)
{
	ObjectsSeparator::operator=(other);
	data_ = other.data_;
	data_size_ = other.data_size_;
	return *this;
}

QVPN::Core::ObjectsBufferView& QVPN::Core::ObjectsBufferView::operator=(ObjectsBufferView&& other) noexcept
{
	ObjectsSeparator::operator=(std::move(other));
	data_ = std::move(other.data_);
	data_size_ = std::move(other.data_size_);
	return *this;
}

size_t QVPN::Core::ObjectsBufferView::get_objects_num() const
{
	return ObjectsSeparator::get_objects_num();
}

void QVPN::Core::ObjectsBufferView::add_object(UByte* begin, UByte* end)
{
	if (data_ == nullptr)
		data_ = begin;

	add_object_separators(data_size_, std::distance(begin, end));
	data_size_ += std::distance(begin, end);
}

void QVPN::Core::ObjectsBufferView::add_data_to_object(size_t i, UByte * begin, UByte * end)
{
	auto size = std::distance(begin, end);
	add_data_to_object_separators(i, size);
}

void QVPN::Core::ObjectsBufferView::add_data_to_last_object(UByte * begin, UByte * end)
{
	auto size = std::distance(begin, end);
	add_data_to_last_object_separators(size);
}

void QVPN::Core::ObjectsBufferView::split_last_object(size_t size)
{
	split_last_object_separators(size);
}

size_t QVPN::Core::ObjectsBufferView::get_object_offset(size_t i) const
{
	return ObjectsSeparator::get_object_offset(i);
}

size_t QVPN::Core::ObjectsBufferView::get_full_size() const
{
	return data_size_;
}

std::pair<UByte*, UByte*> QVPN::Core::ObjectsBufferView::get_object(size_t i)
{
	auto [b, e] = get_object_separators(i);
	return std::pair<UByte*, UByte*>(data_ + b, data_ + e);
}

std::pair<const UByte*, const UByte*> QVPN::Core::ObjectsBufferView::get_object(size_t i) const
{
	auto [b, e] = get_object_separators(i);;
	return std::pair<const UByte*, const UByte*>(data_ + b, data_ + e);
}

std::vector<UByte> QVPN::Core::ObjectsBufferView::get_object_data(size_t i) const
{
	auto [b, e] = get_object_separators(i);;
	return std::vector<UByte>(data_ + b, data_ + e);
}

std::pair<UByte*, UByte*> QVPN::Core::ObjectsBufferView::get_objects_by_size(size_t size)
{
	auto [b, e] = get_objects_separators_by_size(size);
	return std::pair<UByte*, UByte*>(data_ + b, data_ + e);
}

std::pair<const UByte*, const UByte*> QVPN::Core::ObjectsBufferView::get_objects_by_size(size_t size) const
{
	auto [b, e] = get_objects_separators_by_size(size);
	return std::pair<const UByte*, const UByte*>(data_ + b, data_ + e);
}

std::pair<UByte*, UByte*> QVPN::Core::ObjectsBufferView::get_objects_by_num(size_t size)
{
	auto [b, e] = get_objects_separators_by_num(size);
	return std::pair<UByte*, UByte*>(data_ + b, data_ + e);
}

std::pair<const UByte*, const UByte*> QVPN::Core::ObjectsBufferView::get_objects_by_num(size_t size) const
{
	auto [b, e] = get_objects_separators_by_num(size);
	return std::pair<const UByte*, const UByte*>(data_ + b, data_ + e);
}

std::vector<UByte> QVPN::Core::ObjectsBufferView::get_objects_data_by_size(size_t size) const
{
	auto [b, e] = get_objects_separators_by_size(size);
	return std::vector<UByte>(data_ + b, data_ + e);
}

std::pair<UByte*, UByte*> QVPN::Core::ObjectsBufferView::get_last_object()
{
	auto [b, e] = get_last_object_separators();
	return std::pair<UByte*, UByte*>(data_ + b, data_ + e);
}

std::pair<const UByte*, const UByte*> QVPN::Core::ObjectsBufferView::get_last_object() const
{
	auto [b, e] = get_last_object_separators();
	return std::pair<const UByte*, const UByte*>(data_ + b, data_ + e);
}

std::vector<UByte> QVPN::Core::ObjectsBufferView::get_last_object_data() const
{
	auto [b, e] = get_last_object_separators();
	return std::vector<UByte>(data_ + b, data_ + e);
}

void QVPN::Core::ObjectsBufferView::weak_pop_last()
{
	pop_last_separators();
}

void QVPN::Core::ObjectsBufferView::weak_pop_first()
{
	pop_first_separators();
}

void QVPN::Core::ObjectsBufferView::pop_last()
{
	weak_pop_last();
}

void QVPN::Core::ObjectsBufferView::pop_first()
{
	weak_pop_first();
}

void QVPN::Core::ObjectsBufferView::weak_pop_by_size(size_t size)
{
	pop_separators_by_size(size);
}

void QVPN::Core::ObjectsBufferView::weak_pop_objects(size_t size)
{
	pop_objects_separators(size);
}

void QVPN::Core::ObjectsBufferView::pop(size_t i)
{
	pop_object_separators(i);
}

void QVPN::Core::ObjectsBufferView::pop_by_size(size_t size)
{
	weak_pop_by_size(size);
}

void QVPN::Core::ObjectsBufferView::pop_objects(size_t size)
{
	weak_pop_objects(size);
}

void QVPN::Core::ObjectsBufferView::clear_weak_pop()
{

}

std::pair<UByte*, UByte*> QVPN::Core::ObjectsBufferView::to_bytes()
{
	return std::pair<UByte*, UByte*>(data_, data_ + data_size_);
}

std::pair<const UByte*, const UByte*> QVPN::Core::ObjectsBufferView::to_bytes() const
{
	return std::pair<const UByte*, const UByte*>(data_, data_ + data_size_);
}

QVPN::Core::ReceiveDataEx::ReceiveDataEx()
	: ObjectsSeparator{}
{

}

QVPN::Core::ReceiveDataEx::ReceiveDataEx(size_t max_packets, size_t packet_size)
	: ObjectsSeparator{}
{
	data_.reserve(max_packets * packet_size);
	data_.resize(max_packets * packet_size);
}

QVPN::Core::ReceiveDataEx::ReceiveDataEx(size_t buffer_size)
	: ObjectsSeparator{}
{
	data_.reserve(buffer_size);
	data_.resize(buffer_size);
}

void QVPN::Core::ReceiveDataEx::add_data(UByte * begin, UByte * end)
{
	auto size = std::distance(begin, end);
	data_.insert(data_.begin() + real_size_, begin, end);
	add_object_separators(real_size_, size);
	real_size_ += size;
}

void QVPN::Core::ReceiveDataEx::add_raw_object(size_t offset, size_t size)
{
	ObjectsSeparator::add_object_separators(offset, size);
}

void QVPN::Core::ReceiveDataEx::split_last_object(size_t size)
{
	ObjectsSeparator::split_last_object_separators(size);
}

UByte* QVPN::Core::ReceiveDataEx::get_raw_buffer_pointer()
{
	return data_.data();
}

void QVPN::Core::ReceiveDataEx::set_status(NetStatus status)
{
	status_ = status;
}

void QVPN::Core::ReceiveDataEx::add_status(NetStatus status)
{
	status_.success |= status.success;
	status_.status = status.status;
}

const QVPN::Core::NetStatus& QVPN::Core::ReceiveDataEx::get_status() const
{
	return status_;
}

std::pair<UByte*, UByte*> QVPN::Core::ReceiveDataEx::get_object(size_t i)
{
	auto [b, e] = get_object_separators(i);
	return std::pair<UByte*, UByte*>(data_.data() + b, data_.data() + e);
}

std::pair<const UByte*, const UByte*> QVPN::Core::ReceiveDataEx::get_object(size_t i) const
{
	auto [b, e] = get_object_separators(i);
	return std::pair<const UByte*, const UByte*>(data_.data() + b, data_.data() + e);
}

size_t QVPN::Core::ReceiveDataEx::get_objects_num() const
{
	return ObjectsSeparator::get_objects_num();
}

std::pair<UByte*, UByte*> QVPN::Core::ReceiveDataEx::to_bytes()
{
	return std::pair<UByte*, UByte*>(data_.data(), data_.data() + data_.size());
}

std::pair<const UByte*, const UByte*> QVPN::Core::ReceiveDataEx::to_bytes() const
{
	return std::pair<const UByte*, const UByte*>(data_.data(), data_.data() + data_.size());
}

QVPN::Core::ObjectsSeparator::ObjectsSeparator(const ObjectsSeparator& other)
{
	separators_ = other.separators_;
}

QVPN::Core::ObjectsSeparator::ObjectsSeparator(ObjectsSeparator&& other) noexcept
{
	separators_ = std::move(other.separators_);
}

QVPN::Core::ObjectsSeparator& QVPN::Core::ObjectsSeparator::operator=(const ObjectsSeparator & other)
{
	separators_ = other.separators_;
	return *this;
}

QVPN::Core::ObjectsSeparator& QVPN::Core::ObjectsSeparator::operator=(ObjectsSeparator&& other) noexcept
{
	separators_ = std::move(other.separators_);
	return *this;
}

size_t QVPN::Core::ObjectsSeparator::find_last_sep_by_size(size_t size) const
{
	size_t last_sep_iter = 0;
	size_t last_size = 0;
	for (size_t i = 0; i < separators_.size(); i++)
	{
		if (last_size <= size)
		{
			last_size = separators_[i].second;
			last_sep_iter = i;
		}
		else
			break;
	}
	return last_sep_iter;
}

void QVPN::Core::ObjectsSeparator::add_object_separators(size_t offset, size_t size)
{
	separators_.emplace_back(offset, offset + size);
}

void QVPN::Core::ObjectsSeparator::add_data_to_object_separators(size_t i, size_t size)
{
	auto& [bi, ei] = separators_[i];
	ei += size;
}

void QVPN::Core::ObjectsSeparator::add_data_to_last_object_separators(size_t size)
{
	auto& [bl, el] = separators_.back();
	el += size;
}

void QVPN::Core::ObjectsSeparator::split_last_object_separators(size_t size)
{
	auto& [b, e] = separators_.back();
	auto old_end = e;
	e = b + size;
	separators_.emplace_back(e, old_end);
}

size_t QVPN::Core::ObjectsSeparator::get_objects_num() const
{
	return separators_.size();
}

size_t QVPN::Core::ObjectsSeparator::get_object_offset(size_t i) const
{
	auto& [b, e] = separators_[i];
	return b;
}

std::pair<size_t, size_t> QVPN::Core::ObjectsSeparator::get_objects_separators_by_num(size_t size) const
{
	auto& [fb, fe] = separators_.front();
	auto& [sb, se] = separators_[size - 1];
	return std::pair<size_t, size_t>(fb, se);
}

std::pair<size_t, size_t> QVPN::Core::ObjectsSeparator::get_object_separators(size_t i)
{
	return separators_[i];
}

std::pair<size_t, size_t> QVPN::Core::ObjectsSeparator::get_objects_separators_by_size(size_t size)
{
	auto it = find_last_sep_by_size(size);
	return separators_[it];
}

std::pair<size_t, size_t> QVPN::Core::ObjectsSeparator::get_object_separators(size_t i) const
{
	return separators_[i];
}

std::pair<size_t, size_t> QVPN::Core::ObjectsSeparator::get_objects_separators_by_size(size_t size) const
{
	auto it = find_last_sep_by_size(size);
	return separators_[it];
}

std::pair<size_t, size_t> QVPN::Core::ObjectsSeparator::get_last_object_separators()
{
	return separators_.back();;
}

std::pair<size_t, size_t> QVPN::Core::ObjectsSeparator::get_last_object_separators() const
{
	return separators_.back();
}

std::pair<size_t, size_t> QVPN::Core::ObjectsSeparator::get_first_object_separators()
{
	return separators_.front();
}

std::pair<size_t, size_t> QVPN::Core::ObjectsSeparator::get_first_object_separators() const
{
	return separators_.front();
}

void QVPN::Core::ObjectsSeparator::pop_last_separators()
{
	separators_.pop_back();
}

void QVPN::Core::ObjectsSeparator::pop_first_separators()
{
	separators_.erase(separators_.begin());
}

void QVPN::Core::ObjectsSeparator::pop_object_separators(size_t i)
{
	separators_.erase(separators_.begin() + i);
}

void QVPN::Core::ObjectsSeparator::pop_objects_separators(size_t size)
{
	separators_.erase(separators_.begin(), separators_.begin() + size);
}

void QVPN::Core::ObjectsSeparator::pop_separators_by_size(size_t size)
{
	auto last_iter = find_last_sep_by_size(size);
	auto b = separators_[0].first;
	auto e = separators_[last_iter].second;
	separators_.erase(separators_.begin(), separators_.begin() + last_iter + 1);
}
