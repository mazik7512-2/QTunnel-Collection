#include <qvpn_net_tools.hpp>
#include <endian.h>



using QVPNNetTools = QVPN::NetTools::QVPNNetTools;
using UByte = QVPN::Core::BaseTypes::UByte;
using UShort = QVPN::Core::BaseTypes::UShort;
using UInt = QVPN::Core::BaseTypes::UInt;
using ULong = QVPN::Core::BaseTypes::ULong;
using QVPNSocketSettings = QVPN::Core::QVPNSocketSettings;
using NetProtocol = QVPN::Core::NetProtocol;
using TransportProtocol = QVPN::Core::TransportProtocol;


QVPN::NetTools::QVPNNetTools::Socket QVPN::NetTools::QVPNNetTools::create_socket(QVPN::Core::NetProtocol net_proto, QVPN::Core::TransportProtocol t_proto)
{
	QVPNMetaSocketData meta{};
	return QVPN::NetTools::QVPNNetTools::Socket(meta.get_socket_family(net_proto), meta.get_socket_type(t_proto), meta.get_socket_proto(t_proto));
}

QVPN::NetTools::QVPNNetTools::RawSocket QVPN::NetTools::QVPNNetTools::create_raw_socket(QVPN::Core::NetProtocol net_proto, QVPN::Core::TransportProtocol t_proto)
{
	QVPNMetaSocketData meta{};
	QVPNSocketSettings sock_s(false);
	auto sock = QVPN::NetTools::QVPNNetTools::RawSocket(meta.get_socket_family(net_proto), meta.get_raw_socket_type(t_proto), meta.get_raw_socket_proto(t_proto));
	sock.apply_settings(sock_s);
	return sock;
}

QVPN::NetTools::QVPNNetTools::Socket QVPN::NetTools::QVPNNetTools::create_socket_by_connection(NetProtocol net_proto, TransportProtocol t_proto, const QVPNSocketData& connection_data, UInt local_isn, UInt remote_isn)
{
	auto sock = create_socket(net_proto, t_proto);
	sock.append_socket_to_connection(connection_data, local_isn, remote_isn);
	return sock;
}

QVPN::NetTools::QVPNNetTools::SocketFilter QVPN::NetTools::QVPNNetTools::create_socket_filter(const QVPN::Core::QVPNSocketData& s_data)
{
	return SocketFilter(s_data);
}

QVPN::NetTools::QVPNNetTools::SocketFilter QVPN::NetTools::QVPNNetTools::create_socket_filter(const QVPN::Core::QVPNServerSocketData& s_data)
{
	return SocketFilter(s_data);
}

UShort QVPN::NetTools::QVPNNetTools::hton(UShort num)
{
	return htons(num);
}

UShort QVPN::NetTools::QVPNNetTools::ntoh(UShort num)
{
	return ntohs(num);
}

UInt QVPN::NetTools::QVPNNetTools::hton(UInt num)
{
	return htonl(num);
}

UInt QVPN::NetTools::QVPNNetTools::ntoh(UInt num)
{
	return ntohl(num);
}

ULong QVPN::NetTools::QVPNNetTools::hton(ULong num)
{
	return htobe64(num);
}

ULong QVPN::NetTools::QVPNNetTools::ntoh(ULong num)
{
	return be64toh(num);
}

// QVPN Socket

QVPN::NetTools::QVPN_Socket::QVPN_Socket()
	: socket_(NULL)
{}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(int sock_family, int sock_type, int sock_proto)
{
	socket_ = socket(sock_family, sock_type, sock_proto);
	switch (sock_proto)
	{
	case IPPROTO_TCP:
		socket_data_.transport_proto = QVPN::Core::TCP;
		break;
	case IPPROTO_UDP:
		socket_data_.transport_proto = QVPN::Core::UDP;
		break;
	default:
		socket_data_.transport_proto = QVPN::Core::TRANSPORT_UNDEFINED;
		break;
	}

	switch (sock_family)
	{
	case AF_INET:
		socket_data_.net_proto = NetProtocol::IPv4;
		break;
	case AF_INET6:
		socket_data_.net_proto = NetProtocol::IPv6;
		break;
	default:
		socket_data_.net_proto = NetProtocol::NET_UNDEFINED;
		break;
	}

	socket_data_.remote_port = 0;
	socket_data_.local_port = 0;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(const QVPN_Socket& other) noexcept
{
	socket_ = other.socket_;
	socket_data_ = other.socket_data_;
}

QVPN::NetTools::QVPN_Socket& QVPN::NetTools::QVPN_Socket::operator=(const QVPN_Socket& other) noexcept
{
	socket_ = other.socket_;
	socket_data_ = other.socket_data_;
	return *this;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(QVPN_Socket&& other) noexcept
{
	socket_ = std::move(other.socket_);
	socket_data_ = std::move(other.socket_data_);
}

QVPN::NetTools::QVPN_Socket& QVPN::NetTools::QVPN_Socket::operator=(QVPN_Socket&& other) noexcept
{
	socket_ = std::move(other.socket_);
	socket_data_ = std::move(other.socket_data_);
	return *this;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::IPv4Address remote_addr, UShort remote_port, QVPN::Core::IPv4Address local_addr, UShort local_port, TransportProtocol transport_proto)
{
	socket_ = socket;
	socket_data_.net_proto = NetProtocol::IPv4;
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	socket_data_.transport_proto = transport_proto;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::IPv6Address remote_addr, UShort remote_port, QVPN::Core::IPv6Address local_addr, UShort local_port, TransportProtocol transport_proto)
{
	socket_ = socket;
	socket_data_.net_proto = NetProtocol::IPv6;
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	socket_data_.transport_proto = transport_proto;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::NetAddr remote_addr, UShort remote_port, QVPN::Core::NetAddr local_addr, UShort local_port, TransportProtocol transport_proto)
{
	socket_ = socket;
	socket_data_.net_proto = remote_addr.get_addr_family();
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	socket_data_.transport_proto = transport_proto;
}

bool QVPN::NetTools::QVPN_Socket::is_valid() const
{
	if (socket_ < 0)
		return false;
	return true;
}

const QVPN::Core::QVPNSocketData& QVPN::NetTools::QVPN_Socket::get_socket_data() const
{
	return socket_data_;
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::listen(int con_limit)
{
	int err = 0;
	auto res = ::listen(socket_, con_limit);
	bool s = (res == 0) ? true : false;
	if (res == -1)
		err = errno;
	return QVPN::Core::NetStatus{ s , res };
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::send(const UByte* begin, const UByte* end, int flags)
{
	QVPN::Core::NetStatus status{};
	status.success = true;
	auto res = ::send(socket_, reinterpret_cast<const char*>(begin), std::distance(begin, end), flags);
	if (res == -1)
	{
		status.success = false;
		status.status = errno;
	}
	return status;
}

QVPN::NetTools::QVPN_Socket::ReceiveData QVPN::NetTools::QVPN_Socket::receive(int flags)
{
	QVPN::Core::NetStatus status{};
	std::array<UByte, QVPN_Socket::buffer_size> buff{};
	auto res = recv(socket_, reinterpret_cast<char*>(buff.data()), QVPN_Socket::buffer_size, flags);
	status.success = (res > 0) ? true : false;
	if (!status.success)
		status.status = errno;
	return ReceiveData{ status, res, std::move(buff) };
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::disconnect() const
{
	return QVPN::Core::NetStatus{ true, 0 };
}

bool QVPN::NetTools::QVPN_Socket::check_connected() const
{
	sockaddr_in peerAddr;
	socklen_t addrLen = sizeof(peerAddr);
	if (getpeername(socket_, (sockaddr*)&peerAddr, &addrLen) == 0) {
		return true;
	}
	return false;
}

void QVPN::NetTools::QVPN_Socket::disconnect_if_connected() const
{
	if (check_connected())
		return;
	disconnect();
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::shutdown()
{
	auto res = ::shutdown(socket_, SHUT_WR);
	bool s = (res == 0) ? true : false;
	return QVPN::Core::NetStatus{ s, res };
}

void QVPN::NetTools::QVPN_Socket::close_socket() const
{
	close(socket_);
}

QVPN::Core::SocketRepairStatus QVPN::NetTools::QVPN_Socket::append_socket_to_connection(const QVPNSocketData& connection_data, UInt local_isn, UInt remote_isn)
{
	using QVPN::Core::SocketRepairStatus;

	switch (socket_data_.transport_proto)
	{
	case TransportProtocol::TCP:
		return NetTools::details::SocketAppendToConnection<TransportProtocol::TCP>{}(socket_, connection_data, local_isn, remote_isn);
	case TransportProtocol::UDP:
		return NetTools::details::SocketAppendToConnection<TransportProtocol::UDP>{}(socket_, connection_data);
	default:
		return SocketRepairStatus{ false, -1, "Not supported for this protocol"};
	}
}


// QVPN Meta Socket Data


QVPN::NetTools::QVPNMetaSocketData::SockParam QVPN::NetTools::QVPNMetaSocketData::get_socket_family(QVPN::Core::NetProtocol net_proto)
{
	return families_[net_proto];
}

QVPN::NetTools::QVPNMetaSocketData::SockParam QVPN::NetTools::QVPNMetaSocketData::get_socket_type(QVPN::Core::TransportProtocol t_proto)
{
	return types_[t_proto];
}

QVPN::NetTools::QVPNMetaSocketData::SockParam QVPN::NetTools::QVPNMetaSocketData::get_socket_proto(QVPN::Core::TransportProtocol t_proto)
{
	return protos_[t_proto];
}

QVPN::NetTools::QVPNMetaSocketData::SockParam QVPN::NetTools::QVPNMetaSocketData::get_raw_socket_type(QVPN::Core::TransportProtocol t_proto)
{
	return raw_types_[t_proto];
}

QVPN::NetTools::QVPNMetaSocketData::SockParam QVPN::NetTools::QVPNMetaSocketData::get_raw_socket_proto(QVPN::Core::TransportProtocol t_proto)
{
	return raw_protos_[t_proto];
}


// QVPN Raw Socket


QVPN::NetTools::QVPN_RawSocket::QVPN_RawSocket()
	: socket_(NULL)
{}

QVPN::NetTools::QVPN_RawSocket::QVPN_RawSocket(int sock_family, int sock_type, int sock_proto)
{
	QVPNMetaSocketData meta{};
	socket_ = socket(sock_family, sock_type, sock_proto);
	switch (sock_proto)
	{
	case IPPROTO_TCP:
		socket_data_.transport_proto = QVPN::Core::TCP;
		break;
	case IPPROTO_UDP:
		socket_data_.transport_proto = QVPN::Core::UDP;
		break;
	default:
		socket_data_.transport_proto = QVPN::Core::TRANSPORT_UNDEFINED;
		break;
	}
	
	switch (sock_family)
	{
	case AF_INET:
		socket_data_.net_proto = NetProtocol::IPv4;
		break;
	case AF_INET6:
		socket_data_.net_proto = NetProtocol::IPv6;
		break;
	default:
		socket_data_.net_proto = NetProtocol::NET_UNDEFINED;
		break;
	}

	socket_data_.remote_port = 0;
	socket_data_.local_port = 0;
}

QVPN::NetTools::QVPN_RawSocket::QVPN_RawSocket(const QVPN_RawSocket& other) noexcept
{
	socket_ = other.socket_;
	socket_data_ = other.socket_data_;
}

QVPN::NetTools::QVPN_RawSocket& QVPN::NetTools::QVPN_RawSocket::operator=(const QVPN_RawSocket& other) noexcept
{
	socket_ = other.socket_;
	socket_data_ = other.socket_data_;
	return *this;
}

QVPN::NetTools::QVPN_RawSocket::QVPN_RawSocket(QVPN_RawSocket&& other) noexcept
{
	socket_ = std::move(other.socket_);
	socket_data_ = std::move(other.socket_data_);
}

QVPN::NetTools::QVPN_RawSocket& QVPN::NetTools::QVPN_RawSocket::operator=(QVPN_RawSocket&& other) noexcept
{
	socket_ = std::move(other.socket_);
	socket_data_ = std::move(other.socket_data_);
	return *this;
}

QVPN::NetTools::QVPN_RawSocket::QVPN_RawSocket(SOCKET socket, QVPN::Core::IPv4Address remote_addr, UShort remote_port, QVPN::Core::IPv4Address local_addr, UShort local_port, TransportProtocol transport_proto)
{
	socket_ = socket;
	socket_data_.net_proto = NetProtocol::IPv4;
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	socket_data_.transport_proto = transport_proto;
}

QVPN::NetTools::QVPN_RawSocket::QVPN_RawSocket(SOCKET socket, QVPN::Core::IPv6Address remote_addr, UShort remote_port, QVPN::Core::IPv6Address local_addr, UShort local_port, TransportProtocol transport_proto)
{
	socket_ = socket;
	socket_data_.net_proto = NetProtocol::IPv6;
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	socket_data_.transport_proto = transport_proto;
}

QVPN::NetTools::QVPN_RawSocket::QVPN_RawSocket(SOCKET socket, QVPN::Core::NetAddr remote_addr, UShort remote_port, QVPN::Core::NetAddr local_addr, UShort local_port, TransportProtocol transport_proto)
{
	socket_ = socket;
	socket_data_.net_proto = remote_addr.get_addr_family();
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	socket_data_.transport_proto = transport_proto;
}

bool QVPN::NetTools::QVPN_RawSocket::is_valid() const
{
	if (socket_ < 0)
		return false;
	return true;
}

const QVPN::Core::QVPNSocketData& QVPN::NetTools::QVPN_RawSocket::get_socket_data() const
{
	return socket_data_;
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_RawSocket::listen(int con_limit)
{
	int err = 0;
	auto res = ::listen(socket_, con_limit);
	bool s = (res == 0) ? true : false;
	if (res == -1)
		err = errno;
	return QVPN::Core::NetStatus{ s , res };
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_RawSocket::send(const UByte* begin, const UByte* end, int flags)
{
	QVPN::Core::NetStatus status{};
	status.success = true;
	auto res = ::send(socket_, reinterpret_cast<const char*>(begin), std::distance(begin, end), flags);
	if (res == -1)
	{
		status.success = false;
		status.status = errno;
	}
	return status;
}

QVPN::Core::ReceiveData QVPN::NetTools::QVPN_RawSocket::receive(int flags)
{
	QVPN::Core::NetStatus status{};
	std::array<UByte, QVPN_Socket::buffer_size> buff{};
	auto res = recv(socket_, reinterpret_cast<char*>(buff.data()), QVPN_Socket::buffer_size, flags);
	status.success = (res > 0) ? true : false;
	if (!status.success)
		status.status = errno;
	return ReceiveData{ status, res, std::move(buff) };
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_RawSocket::disconnect() const
{
	return QVPN::Core::NetStatus{ true, 0 };
}

bool QVPN::NetTools::QVPN_RawSocket::check_connected() const
{
	sockaddr_in peerAddr;
	socklen_t addrLen = sizeof(peerAddr);
	if (getpeername(socket_, (sockaddr*)&peerAddr, &addrLen) == 0) {
		return true;
	}
	return false;
}

void QVPN::NetTools::QVPN_RawSocket::disconnect_if_connected() const
{
	if (check_connected())
		return;
	disconnect();
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_RawSocket::shutdown()
{
	auto res = ::shutdown(socket_, SHUT_WR);
	bool s = (res == 0) ? true : false;
	return QVPN::Core::NetStatus{ s, res };
}

void QVPN::NetTools::QVPN_RawSocket::close_socket() const
{
	close(socket_);
}

void QVPN::NetTools::QVPN_RawSocket::filter(QVPN_SocketFilter& filter)
{
	auto prog_fd = details::socket_filter_wrapper(filter);

	if (setsockopt(socket_, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0)
	{
		perror("Error attach filter to socket");
	}
}

