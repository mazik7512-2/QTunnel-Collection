#pragma once
#if defined(_MSC_VER)
	#define QVPN_ALIGN(n) __declspec(align(n))
	#define QVPN_PACKED_BEGIN __pragma(pack(push, 1))
	#define QVPN_PACKED_END __pragma(pack(pop))
#elif defined(__GNUC__) || defined(__clang__)
	#define QVPN_ALIGN(n) __attribute__((aligned(n)))
	#define QVPN_PACKED_BEGIN 
	#define QVPN_PACKED_END __attribute__((packed))
#else
	#define QVPN_ALIGN(n) alignas(n)
	#define QVPN_PACKED_BEGIN
	#define QVPN_PACKED_END
#endif

/////////////////////////////////////////////

// using:
/*
QVPN_PACKED_BEGIN
struct PackedStruct {
	char a;
	int b;
}
QVPN_PACKED_END;
*/
