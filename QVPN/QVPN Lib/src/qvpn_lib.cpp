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
	for (size_t i = 0; i < ip_.size(); i++)
	{
		if (ip_[i] != other.ip_[i])
			return false;
	}
	return true;
}

// QVPN Socket Data

std::string QVPN::Core::QVPNSocketData::to_string() const
{
	std::stringstream ss{};

	ss << "(" << static_cast<BaseTypes::UInt>(net_proto) << "," << static_cast<BaseTypes::UInt>(transport_proto) << ") " << local_addr.to_string() << ":" << local_port << "-" << remote_addr.to_string() << ":" << remote_port;

	auto str = ss.str();
	return str;
}

QVPN::Core::QVPNSocketSettings::QVPNSocketSettings(bool ip_data, int receive_timeout_ms)
{
	ip_header_ = ip_data;
	recv_timeout_ = receive_timeout_ms;
}

bool QVPN::Core::QVPNSocketSettings::ip_header() const
{
	return ip_header_;
}

int QVPN::Core::QVPNSocketSettings::receive_timeout_ms() const
{
	return recv_timeout_;
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
	flags_data.pop_back();
	flags_data.append("]");
	return flags_data;
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
	return flags_ & 0x100;
}

UByte QVPN::Core::TcpFlagsObject::get_cwr() const
{
	return flags_ & 0x80;
}

UByte QVPN::Core::TcpFlagsObject::get_ecn() const
{
	return flags_ & 0x40;
}

UByte QVPN::Core::TcpFlagsObject::get_urg() const
{
	return flags_ & 0x20;
}

UByte QVPN::Core::TcpFlagsObject::get_ack() const
{
	return flags_ & 0x10;
}

UByte QVPN::Core::TcpFlagsObject::get_psh() const
{
	return flags_ & 0x8;
}

UByte QVPN::Core::TcpFlagsObject::get_rst() const
{
	return flags_ & 0x4;
}

UByte QVPN::Core::TcpFlagsObject::get_syn() const
{
	return flags_ & 0x2;
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
