#pragma once

#include <qvpn_lib.hpp>
#include <windivert_ext.hpp>
#include <wintun_ext.hpp>
#include <qvpn_net_tools.hpp>
#include <qvpn_driver.hpp>

namespace QVPN
{

	namespace details
	{
		using QVPNSocket = QVPN::NetTools::QVPN_Socket;
		using QVPNNetTools = QVPN::NetTools::QVPNNetTools;

		template <QVPN::Core::is_database_adapter Database, QVPN::Core::is_statistic_adapter Stats>
		using QVPNServerDriver = QVPN::Core::QVPNServerDriver<QVPN::Core::BaseTypes::UByte*, QVPN::Core::NetAddr, QVPNSocket, QVPNNetTools, Database, Stats>;
	}

	using QVPNClientSettings = QVPN::Core::QVPNClientSettings;
	using QVPNClient = QVPN::Core::VPNClient<QVPN::WinTunExt::WinTunDriver, QVPN::WinDivertExt::WinDivertClientNetDriver>;
	using QVPNLayersStrategy = QVPN::Core::DefaultLayersStrategy<QVPN::Core::BaseTypes::UByte*, QVPN::Core::NetAddr>;

	using QVPNServerSettings = QVPN::Core::QVPNServerSettings;

	using NoDatabaseAdapter = QVPN::Core::NoDatabaseAdapter;
	using NoStatsAdapter = QVPN::Core::NoStatisticAdapter;

	template <QVPN::Core::is_database_adapter Database, QVPN::Core::is_statistic_adapter Stats>
	using QVPNServer = QVPN::Core::VPNServer_<QVPN::Core::BaseTypes::UByte*, details::QVPNServerDriver<Database, Stats>, Database, Stats>;

	template <QVPN::Core::is_database_adapter Database>
	using NoStatsQVPNServer = QVPN::Core::VPNServer_<QVPN::Core::BaseTypes::UByte*, details::QVPNServerDriver<Database, NoStatsAdapter>, Database, NoStatsAdapter>;
	
	using NoDbNoStatsQVPNServer = QVPNServer<NoDatabaseAdapter, NoStatsAdapter>;
}