#pragma once

#include <lib.hpp>
#include <windivert_ext.hpp>
#include <wintun_ext.hpp>

namespace QVPN
{
	using VPNDriver = QVPN::Core::VPNDriver_<QVPN::WinTunExt::WinTunDriver, QVPN::WinDivertExt::WinDivertNetDriver>;
	
}