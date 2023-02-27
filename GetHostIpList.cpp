
#pragma warning( push )
#pragma warning( disable : 4365 ) // conversion from '' to ''
#pragma warning( disable : 4668 ) // is not defined as a preprocessor macro
#pragma warning( disable : 4710 ) // function not inlined
#pragma warning( disable : 4711 ) // selected for automatic inline expansion
#pragma warning( disable : 4820 ) // bytes padding added after data member
#pragma warning( disable : 5039 ) // pointer or reference to potentially throwing function passed to 'extern "C"' function under - EHc.Undefined behavior may occur if this function throws an exception.
#pragma warning( disable : 5264 ) // 'const' variable is not used

#include <iostream>
#include <vector>
#include <string>

#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma warning( pop )

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")


std::string GetWsaErrorString(int errorCode)
{
	std::string retv(std::to_string(errorCode) + ": ");
	std::vector<char> buf(1024, 0);
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, static_cast<DWORD>(errorCode), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf.data(), static_cast<DWORD>(buf.size() - 1), nullptr);
	for (auto& item : buf) {
		if (item == '\r' || item == '\n') {
			item = 0;
		}
	}
	retv.append(buf.data());
	return retv;
}

typedef struct IpItem
{
	IpItem(std::wstring ip, std::wstring adapter, ADDRESS_FAMILY family) :
		Ip(ip),
		Adapter(adapter),
		Family(family) {
	}

	auto GetFamilyString() {
		switch (Family) {
		case AF_UNSPEC: return "Unspecified";
		case AF_UNIX: return "local to host (pipes, portals)";
		case AF_INET: return "IPv4";
		case AF_IMPLINK: return "ARPANET imp addresses";
		case AF_PUP: return "pup protocols: e.g. BSP";
		case AF_CHAOS: return "MIT CHAOS protocols";
		case AF_IPX: return "IPX protocols: IPX, SPX, etc.";
		case AF_ISO: return "ISO protocols";
		case AF_ECMA: return "European computer manufacturers";
		case AF_DATAKIT: return "datakit protocols";
		case AF_CCITT: return "CCITT protocols, X.25 etc";
		case AF_SNA: return "IBM SNA";
		case AF_DECnet: return "DECnet";
		case AF_DLI: return "Direct data link interface";
		case AF_LAT: return "LAT";
		case AF_HYLINK: return "NSC Hyperchannel";
		case AF_APPLETALK: return "AppleTalk";
		case AF_NETBIOS: return "NetBios-style addresses";
		case AF_VOICEVIEW: return "VoiceView";
		case AF_FIREFOX: return "Protocols from Firefox";
		case AF_UNKNOWN1: return "Somebody is using this!";
		case AF_BAN: return "Banyan";
		case AF_ATM: return "Native ATM Services";
		case AF_INET6: return "IPv6";
		case AF_CLUSTER: return "Microsoft Wolfpack";
		case AF_12844: return "IEEE 1284.4 WG AF";
		case AF_IRDA: return "IrDA";
		case AF_NETDES: return "Network Designers OSI & gateway";
		default: return "";
		}
	}

	std::wstring Ip;
	std::wstring Adapter;
	ADDRESS_FAMILY Family;
	uint8_t x[6] = {};

}IpItem;

std::vector<IpItem> GetLocalIpList()
{
	std::vector<IpItem> ipList;
	std::vector<BYTE> adapterInfo;

	try {
		DWORD size = 0;
		if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) {
			auto lastErr = WSAGetLastError();
			auto err = "Failed get_ipaddress - GetAdaptersAddresses get size" + GetWsaErrorString(lastErr);
			throw std::exception(err.c_str());
		}

		adapterInfo.resize(size);

		if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, (PIP_ADAPTER_ADDRESSES)adapterInfo.data(), &size) != ERROR_SUCCESS) {
			auto lastErr = WSAGetLastError();
			auto err = "Failed get_ipaddress - GetAdaptersAddresses get size" + GetWsaErrorString(lastErr);
			throw std::exception("Failed get_ipaddress - GetAdaptersAddresses get value");
		}

		for (auto a1 = (PIP_ADAPTER_ADDRESSES)adapterInfo.data(); a1 != NULL; a1 = a1->Next) {
			std::wstring adapter(a1->FriendlyName);
			for (auto a2 = a1->FirstUnicastAddress; a2 != NULL; a2 = a2->Next) {
				std::vector<wchar_t> buf(BUFSIZ + 1, 0);
				if (GetNameInfoW(a2->Address.lpSockaddr, a2->Address.iSockaddrLength,
					buf.data(), static_cast<DWORD>(buf.size() - 1), NULL, 0, NI_NUMERICHOST) == 0) {
					ipList.emplace_back(buf.data(), adapter, a2->Address.lpSockaddr->sa_family);
				}
			}
		}

		return ipList;

	}
	catch (const std::exception&) {
		throw;
	}
	catch (...) {
		try {
			std::rethrow_exception(std::current_exception());
		}
		catch (...) {
			throw;
		}
	}

}

int main(int argc, char* argv[])
{

	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv[0]);

	try
	{

		WSAData d;
		if (WSAStartup(MAKEWORD(2, 2), &d) != 0) {
			return -1;
		}

		auto addresList = GetLocalIpList();

		size_t ipLen = 0;
		size_t adapterLen = 0;
		size_t familyLen = 0;

		for (auto& item : addresList) {
			ipLen = std::max<decltype(ipLen)>(ipLen, static_cast<decltype(ipLen)>(item.Ip.length()));
			adapterLen = std::max<decltype(adapterLen)>(adapterLen, static_cast<decltype(adapterLen)>(item.Adapter.length()));
			familyLen = std::max<decltype(familyLen)>(familyLen, static_cast<decltype(familyLen)>(lstrlenA(item.GetFamilyString())));
		}

		wprintf(L"\n--- START ---\n");

		for (auto& item : addresList) {
			wprintf(L"IP [%s] %s %S %s %s %s;\n",
				item.Ip.c_str(),
				std::wstring(ipLen - static_cast<decltype(ipLen)>(item.Ip.length()), ' ').c_str(),
				item.GetFamilyString(),
				std::wstring(familyLen - static_cast<decltype(familyLen)>(lstrlenA(item.GetFamilyString())), ' ').c_str(),
				item.Adapter.c_str(),
				std::wstring(adapterLen - static_cast<decltype(adapterLen)>(item.Adapter.length()), ' ').c_str()
			);
		}

		wprintf(L"--- END ---\n");

	}
	catch (const std::exception& ex) {
		printf("FATAL: %s", ex.what());
	}
	catch (...) {
		try {
			std::rethrow_exception(std::current_exception());
		}
		catch (const std::exception& ex) {
			printf("FATAL: %s", ex.what());
		}
	}

	WSACleanup();

	return 0;
}