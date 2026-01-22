#include <qvpn_net_tools.hpp>


using QVPNNetTools = QVPN::NetTools::QVPNNetTools;
using UByte = QVPN::Core::BaseTypes::UByte;
using UShort = QVPN::Core::BaseTypes::UShort;
using QVPNSocketSettings = QVPN::Core::QVPNSocketSettings;


QVPN::NetTools::QVPN_Socket QVPN::NetTools::QVPNNetTools::create_socket(QVPN::Core::NetProtocol net_proto, QVPN::Core::TransportProtocol t_proto)
{
	QVPNMetaSocketData meta{};
	return QVPN::NetTools::QVPN_Socket(meta.get_socket_family(net_proto), meta.get_socket_type(t_proto), meta.get_socket_proto(t_proto));
}

QVPN::NetTools::QVPN_Socket QVPN::NetTools::QVPNNetTools::create_raw_socket(QVPN::Core::NetProtocol net_proto, QVPN::Core::TransportProtocol t_proto)
{
	QVPNMetaSocketData meta{};
	QVPNSocketSettings sock_s(false);
	auto sock = QVPN::NetTools::QVPN_Socket(meta.get_socket_family(net_proto), meta.get_socket_type(t_proto), meta.get_socket_proto(t_proto));
	sock.apply_settings(sock_s);
	return sock;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket()
	: s_mod_(UNDEFINED), socket_(NULL)
{
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(int sock_family, int sock_type, int sock_proto)
{
	int result = WSAStartup(MAKEWORD(2, 2), &wsa_data_);
	if (result == 0)
	{
		socket_ = socket(sock_family, sock_type, sock_proto);
		s_type_ = sock_type;
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
		socket_data_.remote_port = 0;
		socket_data_.local_port = 0;
		s_mod_ = UNDEFINED;
	}
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(const QVPN_Socket& other) noexcept
{
	socket_ = other.socket_;
	wsa_data_ = other.wsa_data_;
	socket_data_ = other.socket_data_;
	s_mod_ = other.s_mod_;
}

QVPN::NetTools::QVPN_Socket& QVPN::NetTools::QVPN_Socket::operator=(const QVPN_Socket& other) noexcept
{
	socket_ = other.socket_;
	wsa_data_ = other.wsa_data_;
	socket_data_ = other.socket_data_;
	s_mod_ = other.s_mod_;
	return *this;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(QVPN_Socket&& other) noexcept
{
	socket_ = std::move(other.socket_);
	wsa_data_ = std::move(other.wsa_data_);
	socket_data_ = std::move(other.socket_data_);
	s_mod_ = std::move(other.s_mod_);
}

QVPN::NetTools::QVPN_Socket& QVPN::NetTools::QVPN_Socket::operator=(QVPN_Socket&& other) noexcept
{
	socket_ = std::move(other.socket_);
	wsa_data_ = std::move(other.wsa_data_);
	socket_data_ = std::move(other.socket_data_);
	s_mod_ = std::move(other.s_mod_);
	return *this;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::IPv4Address remote_addr, UShort remote_port, QVPN::Core::IPv4Address local_addr, UShort local_port, SocketMod s_mod, TransportProtocol transport_proto)
{
	socket_ = socket;
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	s_mod_ = s_mod;
	socket_data_.transport_proto = transport_proto;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::IPv6Address remote_addr, UShort remote_port, QVPN::Core::IPv6Address local_addr, UShort local_port, SocketMod s_mod, TransportProtocol transport_proto)
{
	socket_ = socket;
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	s_mod_ = s_mod;
	socket_data_.transport_proto = transport_proto;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::NetAddr remote_addr, UShort remote_port, QVPN::Core::NetAddr local_addr, UShort local_port, SocketMod s_mod, TransportProtocol transport_proto)
{
	socket_ = socket;
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	s_mod_ = s_mod;
	socket_data_.transport_proto = transport_proto;
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::listen(int con_limit)
{
	int err = 0;
	auto res = ::listen(socket_, con_limit);
	bool s = (res == 0) ? true : false;
	if (!s)
		err = WSAGetLastError();
	return QVPN::Core::NetStatus{ s , res };
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::send(const UByte* begin, const UByte* end, int flags)
{
	QVPN::Core::NetStatus status{};
	status.success = true;
	auto res = ::send(socket_, reinterpret_cast<const char*>(begin), std::distance(begin, end), flags);
	if (res == SOCKET_ERROR)
	{
		status.success = false;
		status.status = WSAGetLastError();
	}
	return status;
}

QVPN::NetTools::QVPN_Socket::ReceiveData QVPN::NetTools::QVPN_Socket::receive(int flags)
{
	QVPN::Core::NetStatus status{};
	std::array<UByte, QVPN_Socket::buffer_size> buff{};
	auto res = recv(socket_, reinterpret_cast<char *>(buff.data()), QVPN_Socket::buffer_size, flags);
	status.success = (res > 0) ? true : false;
	if (!status.success)
		status.status = WSAGetLastError();
	return ReceiveData{ status, res, std::move(buff) };
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::disconnect() const
{
	WSACleanup();
	return QVPN::Core::NetStatus{ true, 0 };
}

bool QVPN::NetTools::QVPN_Socket::check_connected() const
{
	sockaddr_in peerAddr;
	int addrLen = sizeof(peerAddr);
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
	auto res = ::shutdown(socket_, SD_BOTH);
	bool s = (res == 0) ? true : false;
	return QVPN::Core::NetStatus{ s, res };
}

void QVPN::NetTools::QVPN_Socket::close_socket() const
{
	closesocket(socket_);
}

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
