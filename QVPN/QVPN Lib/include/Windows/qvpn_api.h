#pragma once

#include <qvpn_lib.hpp>
#include <windivert_ext.hpp>
#include <wintun_ext.hpp>

namespace QVPN
{
	using VPNClient = QVPN::Core::VPNClient_<QVPN::WinTunExt::WinTunDriver, QVPN::WinDivertExt::WinDivertClientNetDriver>;
	
}