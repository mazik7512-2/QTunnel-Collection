#pragma once
//
// Although AF_UNSPEC is defined for backwards compatibility, using
// AF_UNSPEC for the "af" parameter when creating a socket is STRONGLY
// DISCOURAGED.  The interpretation of the "protocol" parameter
// depends on the actual address family chosen.  As environments grow
// to include more and more address families that use overlapping
// protocol values there is more and more chance of choosing an
// undesired address family when AF_UNSPEC is used.
//
#define AF_UNSPEC       0               // unspecified
#define AF_UNIX         1               // local to host (pipes, portals)
#define AF_INET         2               // internetwork: UDP, TCP, etc.
#define AF_IMPLINK      3               // arpanet imp addresses
#define AF_PUP          4               // pup protocols: e.g. BSP
#define AF_CHAOS        5               // mit CHAOS protocols
#define AF_NS           6               // XEROX NS protocols
#define AF_IPX          AF_NS           // IPX protocols: IPX, SPX, etc.
#define AF_ISO          7               // ISO protocols
#define AF_OSI          AF_ISO          // OSI is ISO
#define AF_ECMA         8               // european computer manufacturers
#define AF_DATAKIT      9               // datakit protocols
#define AF_CCITT        10              // CCITT protocols, X.25 etc
#define AF_SNA          11              // IBM SNA
#define AF_DECnet       12              // DECnet
#define AF_DLI          13              // Direct data link interface
#define AF_LAT          14              // LAT
#define AF_HYLINK       15              // NSC Hyperchannel
#define AF_APPLETALK    16              // AppleTalk
#define AF_NETBIOS      17              // NetBios-style addresses
#define AF_VOICEVIEW    18              // VoiceView
#define AF_FIREFOX      19              // Protocols from Firefox
#define AF_UNKNOWN1     20              // Somebody is using this!
#define AF_BAN          21              // Banyan
#define AF_ATM          22              // Native ATM Services
#define AF_INET6        23              // Internetwork Version 6
#define AF_CLUSTER      24              // Microsoft Wolfpack
#define AF_12844        25              // IEEE 1284.4 WG AF
#define AF_IRDA         26              // IrDA
#define AF_NETDES       28              // Network Designers OSI & gateway

#if(_WIN32_WINNT < 0x0501)
#define AF_MAX          29
#else //(_WIN32_WINNT < 0x0501)

#define AF_TCNPROCESS   29
#define AF_TCNMESSAGE   30
#define AF_ICLFXBM      31

#if(_WIN32_WINNT < 0x0600)
#define AF_MAX          32
#else //(_WIN32_WINNT < 0x0600)
#define AF_BTH          32              // Bluetooth RFCOMM/L2CAP protocols
#if(_WIN32_WINNT < 0x0601)
#define AF_MAX          33
#else //(_WIN32_WINNT < 0x0601)
#define AF_LINK         33
#if(_WIN32_WINNT < 0x0604)
#define AF_MAX          34
#else //(_WIN32_WINNT < 0x0604)
#define AF_HYPERV       34
#define AF_MAX          35
#endif //(_WIN32_WINNT < 0x0604)
#endif //(_WIN32_WINNT < 0x0601)
#endif //(_WIN32_WINNT < 0x0600)

#endif //(_WIN32_WINNT < 0x0501)

//
// Socket types.
//

#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3
#define SOCK_RDM        4
#define SOCK_SEQPACKET  5

//
// Define a level for socket I/O controls in the same numbering space as
// IPPROTO_TCP, IPPROTO_IP, etc.
//

#define SOL_SOCKET 0xffff
#define SOL_IP     (SOL_SOCKET-4)
#define SOL_IPV6   (SOL_SOCKET-5)

//
// Define socket-level options.
//

#define SO_DEBUG        0x0001      // turn on debugging info recording
#define SO_ACCEPTCONN   0x0002      // socket has had listen()
#define SO_REUSEADDR    0x0004      // allow local address reuse
#define SO_KEEPALIVE    0x0008      // keep connections alive
#define SO_DONTROUTE    0x0010      // just use interface addresses
#define SO_BROADCAST    0x0020      // permit sending of broadcast msgs
#define SO_USELOOPBACK  0x0040      // bypass hardware when possible
#define SO_LINGER       0x0080      // linger on close if data present
#define SO_OOBINLINE    0x0100      // leave received OOB data in line

#define SO_DONTLINGER   (int)(~SO_LINGER)
#define SO_EXCLUSIVEADDRUSE \
    ((int)(~SO_REUSEADDR))          // disallow local address reuse

#define SO_SNDBUF       0x1001      // send buffer size
#define SO_RCVBUF       0x1002      // receive buffer size
#define SO_SNDLOWAT     0x1003      // send low-water mark
#define SO_RCVLOWAT     0x1004      // receive low-water mark
#define SO_SNDTIMEO     0x1005      // send timeout
#define SO_RCVTIMEO     0x1006      // receive timeout
#define SO_ERROR        0x1007      // get error status and clear
#define SO_TYPE         0x1008      // get socket type
#define SO_BSP_STATE    0x1009      // get socket 5-tuple state

#define SO_GROUP_ID     0x2001      // ID of a socket group
#define SO_GROUP_PRIORITY 0x2002    // the relative priority within a group
#define SO_MAX_MSG_SIZE 0x2003      // maximum message size

#define SO_CONDITIONAL_ACCEPT 0x3002 // enable true conditional accept:
                                    // connection is not ack-ed to the
                                    // other side until conditional
                                    // function returns CF_ACCEPT
#define SO_PAUSE_ACCEPT 0x3003      // pause accepting new connections
#define SO_COMPARTMENT_ID 0x3004    // get/set the compartment for a socket
#if (_WIN32_WINNT >= 0x0600)
#define SO_RANDOMIZE_PORT 0x3005    // randomize assignment of wildcard ports
#define SO_PORT_SCALABILITY 0x3006  // enable port scalability
#define SO_REUSE_UNICASTPORT 0x3007 // defer ephemeral port allocation for
                                    // outbound connections
#define SO_REUSE_MULTICASTPORT 0x3008 // enable port reuse and disable unicast
                                      //reception.
#define SO_ORIGINAL_DST 0x300F      // Query the original destination address
                                    // of a redirected connection.
#define IP6T_SO_ORIGINAL_DST SO_ORIGINAL_DST
#endif //(_WIN32_WINNT >= 0x0600)

#if (NTDDI_VERSION >= NTDDI_WIN11_GE)
#define SO_RECEIVED_HOPLIMIT 0x3010
#define SO_RECEIVED_PROCESSOR 0x3011 // Receive the processor number packets
                                     // have been processed by
#endif // NTDDI_VERSION >= NTDDI_WIN11_GE