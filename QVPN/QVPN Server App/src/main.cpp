#include <database.hpp>
#include <argparse/argparse.hpp>
#include <qvpn_api.hpp>

using QVPNServerSettings = QVPN::QVPNServerSettings;
using QVPNServer = QVPN::QVPNServer<ServerDatabaseAdapter, ServerStatsAdatper>;
using QVPNLayers = QVPN::QVPNLayersStrategy;

int main()
{
	//SQLiteDatabase database();

	return 0;
}