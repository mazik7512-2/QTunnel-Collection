#include <windivert_ext.hpp>
#include <sstream>



QVPN::WinDivertExt::WinDivertTrafficFilterType::WinDivertTrafficFilterType(Convertable_from filter)
{
    filter_ = filter;
}


QVPN::WinDivertExt::WinDivertTrafficFilterType::operator Convertable_to() const
{
    return filter_;
}

/*
Filter_t QVPN::WinDivertExt::operator&&(const Filter_t f1, const Filter_t f2)
{
    return Filter_t(" and ");
}
*/

QVPN::WinDivertExt::WinDivertTrafficFilterType QVPN::WinDivertExt::WinDivertTrafficFilterType::operator&&(const WinDivertTrafficFilterType t)
{
    std::stringstream f;
    f << filter_ << " and " << t.filter_;
    return WinDivertTrafficFilterType(f.str());
}