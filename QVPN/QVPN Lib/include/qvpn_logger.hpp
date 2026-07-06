#include <qvpn_tools.hpp>

namespace QVPN {

	namespace Core {

		namespace Tools {

#ifdef _WIN32

			static QVPNLogger<QVPNPlatform::WINDOWS> gLogger{};

#elif __linux__ // also defined in android

#ifdef __ANDROID__ // android branch

			static QVPNLogger<QVPNPlatform::ANDROID> gLogger{};
			
#else // Linux branch

			static QVPNLogger<QVPNPlatform::LINUX> gLogger{};

#endif


#endif

		}
	}

}

