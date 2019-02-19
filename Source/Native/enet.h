/*
 *  ENet reliable UDP networking library 
 *  Copyright (c) 2018 Lee Salzman, Vladyslav Hrytsenko, Dominik Madarász, Stanislav Denisov
 *  Copyright (c) 2019 Nicolas Lebedenco
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#ifndef ENET_INCLUDE_H
#define ENET_INCLUDE_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef ENET_LZ4
    #include "lz4/lz4.h"
#endif

#define ENET_VERSION_MAJOR 3
#define ENET_VERSION_MINOR 0
#define ENET_VERSION_PATCH 0
#define ENET_VERSION_CREATE(major, minor, patch) (((major) << 16) | ((minor) << 8) | (patch))
#define ENET_VERSION_GET_MAJOR(version) (((version) >> 16) & 0xFF)
#define ENET_VERSION_GET_MINOR(version) (((version) >> 8) & 0xFF)
#define ENET_VERSION_GET_PATCH(version) ((version) & 0xFF)
#define ENET_VERSION ENET_VERSION_CREATE(ENET_VERSION_MAJOR, ENET_VERSION_MINOR, ENET_VERSION_PATCH)

#define ENET_TIME_OVERFLOW 86400000
#define ENET_TIME_LESS(a, b) ((a) - (b) >= ENET_TIME_OVERFLOW)
#define ENET_TIME_GREATER(a, b) ((b) - (a) >= ENET_TIME_OVERFLOW)
#define ENET_TIME_LESS_EQUAL(a, b) (!ENET_TIME_GREATER(a, b))
#define ENET_TIME_GREATER_EQUAL(a, b) (!ENET_TIME_LESS(a, b))
#define ENET_TIME_DIFFERENCE(a, b) ((a) - (b) >= ENET_TIME_OVERFLOW ? (b) - (a) : (a) - (b))

#define ENET_SRTT_INITIAL 1.0
#define ENET_SRTT_PARA_G  0.125

#ifdef _WIN32
    #if defined(_MSC_VER) && defined(ENET_IMPLEMENTATION)
        // #pragma warning(disable: 4267) /* size_t to int conversion */
        // #pragma warning(disable: 4244) /* 64bit to 32bit int */
        // #pragma warning(disable: 4018) /* signed/unsigned mismatch */
        // #pragma warning(disable: 4146) /* unary minus operator applied to unsigned type */
    #endif

    #ifndef ENET_NO_PRAGMA_LINK
        #pragma comment(lib, "ws2_32.lib")
        #pragma comment(lib, "winmm.lib")
    #endif

    #if _MSC_VER >= 1910
        /* It looks like there were changes as of Visual Studio 2017 and there are no 32/64 bit
           versions of _InterlockedExchange[operation], only InterlockedExchange[operation]
           (without leading underscore), so we have to distinguish between compiler versions */
        #define _InterlockedExchange            InterlockedExchange
        #define _InterlockedExchange64          InterlockedExchange64

        #define _InterlockedExchangeAdd         InterlockedExchangeAdd
        #define _InterlockedExchangeAdd64       InterlockedExchangeAdd64

        #define _InterlockedCompareExchange     InterlockedCompareExchange
        #define _InterlockedCompareExchange64   InterlockedCompareExchange64
    #endif

    #ifdef __GNUC__
        #if (_WIN32_WINNT < 0x0501)
            #undef _WIN32_WINNT
            #define _WIN32_WINNT 0x0501
        #endif
    #endif

    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <mmsystem.h>
    #include <intrin.h>

    #if defined(_WIN32) && defined(_MSC_VER)
        #if _MSC_VER < 1900
            typedef struct timespec 
            {
                long tv_sec;
                long tv_nsec;
            };
        #endif
        #define CLOCK_MONOTONIC 0
    #endif

    typedef SOCKET ENetSocket;

    #define ENET_SOCKET_NULL INVALID_SOCKET

    typedef struct 
    {
        size_t dataLength;
        void*  data;
    } ENetBuffer;

    #define ENET_CALLBACK __cdecl

    #ifdef ENET_DLL
        #ifdef ENET_IMPLEMENTATION
            #define ENET_API __declspec(dllexport)
        #else
            #define ENET_API __declspec(dllimport)
        #endif
    #else
        #define ENET_API extern
    #endif

    typedef fd_set ENetSocketSet;

    #define ENET_SOCKETSET_EMPTY(sockset)          FD_ZERO(&(sockset))
    #define ENET_SOCKETSET_ADD(sockset, socket)    FD_SET(socket, &(sockset))
    #define ENET_SOCKETSET_REMOVE(sockset, socket) FD_CLR(socket, &(sockset))
    #define ENET_SOCKETSET_CHECK(sockset, socket)  FD_ISSET(socket, &(sockset))
#else
    #include <sys/types.h>
    #include <sys/ioctl.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <poll.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <string.h>
    #include <errno.h>
    #include <fcntl.h>

    #ifdef __APPLE__
        #include <mach/clock.h>
        #include <mach/mach.h>
        #include <Availability.h>
    #endif

    #ifndef MSG_NOSIGNAL
        #define MSG_NOSIGNAL 0
    #endif

    #ifdef MSG_MAXIOVLEN
        #define ENET_BUFFER_MAXIMUM MSG_MAXIOVLEN
    #endif

    typedef int ENetSocket;

    #define ENET_SOCKET_NULL -1

    typedef struct 
    {
        void* data;
        size_t dataLength;
    } ENetBuffer;

    #define ENET_CALLBACK
    #define ENET_API extern

    typedef fd_set ENetSocketSet;

    #define ENET_SOCKETSET_EMPTY(sockset)          FD_ZERO(&(sockset))
    #define ENET_SOCKETSET_ADD(sockset, socket)    FD_SET(socket, &(sockset))
    #define ENET_SOCKETSET_REMOVE(sockset, socket) FD_CLR(socket, &(sockset))
    #define ENET_SOCKETSET_CHECK(sockset, socket)  FD_ISSET(socket, &(sockset))
#endif

#define ENET_MAX(x, y) ((x) > (y) ? (x) : (y))
#define ENET_MIN(x, y) ((x) < (y) ? (x) : (y))
#define ENET_IPV6           1
#define ENET_HOST_ANY       in6addr_any
#define ENET_HOST_LOCALHOST in6addr_loopback
#define ENET_HOST_BROADCAST 0xFFFFFFFFU
#define ENET_PORT_ANY       0
#define ENET_SCOPE_ID_NONE  0

#define ENET_HOST_TO_NET_16(value) (htons(value))
#define ENET_HOST_TO_NET_32(value) (htonl(value))
#define ENET_NET_TO_HOST_16(value) (ntohs(value))
#define ENET_NET_TO_HOST_32(value) (ntohl(value))

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t         enet_uint8;
typedef uint16_t        enet_uint16;
typedef uint32_t        enet_uint32;
typedef uint64_t        enet_uint64;

typedef enet_uint32     ENetVersion;

typedef struct _ENetCallbacks 
{
    void* (ENET_CALLBACK* malloc) (size_t size);
    void  (ENET_CALLBACK* free) (void* memory);
    void  (ENET_CALLBACK* out_of_memory) (size_t size);
} ENetCallbacks;

void* enet_malloc(size_t size);
void  enet_free(void* memory);

typedef struct _ENetListNode 
{
    struct _ENetListNode* next;
    struct _ENetListNode* previous;
} ENetListNode;

typedef ENetListNode* ENetListIterator;

typedef struct _ENetList 
{
    ENetListNode sentinel;
} ENetList;

ENET_API ENetListIterator enet_list_insert(ENetListIterator position, void* data);
ENET_API ENetListIterator enet_list_move(ENetListIterator position, void* dataFirst, void* dataLast);

ENET_API void*  enet_list_remove(ENetListIterator position);
ENET_API void   enet_list_clear(ENetList* list);
ENET_API size_t enet_list_size(ENetList* list);

#define enet_list_begin(list) ((list)->sentinel.next)
#define enet_list_end(list) (&(list)->sentinel)
#define enet_list_empty(list) (enet_list_begin(list) == enet_list_end(list))
#define enet_list_next(iterator) ((iterator)->next)
#define enet_list_previous(iterator) ((iterator)->previous)
#define enet_list_front(list) ((void*) (list)->sentinel.next)
#define enet_list_back(list) ((void*) (list)->sentinel.previous)



/**************************************************************************
 * Protocol
 **************************************************************************/

#define ENET_PROTOCOL_MINIMUM_MTU                               ((enet_uint16)   576)
#define ENET_PROTOCOL_MAXIMUM_MTU                               ((enet_uint16)  4096)
#define ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS                   ((enet_uint16)    32)
#define ENET_PROTOCOL_MINIMUM_WINDOW_SIZE                       ((enet_uint32)  4096)
#define ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE                       ((enet_uint32) 65536)
#define ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT                     ((enet_uint16)     1)
#define ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT                     ((enet_uint16)   256)       // Cannot be greater than 256 since the protocol command header can only contain channel ids of 8 bits.
#define ENET_PROTOCOL_MAXIMUM_PEER_COUNT                        ((enet_uint16)  4096)
#define ENET_PROTOCOL_MAXIMUM_PEER_ID                           ((enet_uint16) (ENET_PROTOCOL_MAXIMUM_PEER_COUNT - 1))
#define ENET_PROTOCOL_NULL_PEER                                 ((enet_uint16) 65535)
#define ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT                    ((enet_uint16) 65000)


#ifndef ENET_BUFFER_MAXIMUM
#define ENET_BUFFER_MAXIMUM                                     (1 + 2 * ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS)
#endif

#ifdef _MSC_VER
    #pragma pack(push, 1)
    #define ENET_PACKED
#elif defined(__GNUC__) || defined(__clang__)
    #define ENET_PACKED __attribute__ ((packed))
#else
    #define ENET_PACKED
#endif

/***
 *  PROTOCOL HEADER (one per packet)
 *
 *  Size: 3, 7 or 11 depending on flags TIME and CRC.
 *
 *  ------------------------------------------------------------------------------------
 * |                  0                    |  1  |  2  | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
 *  ------------------------------------------------------------------------------------
 * | 7 ... 5 |   4  |   3  |  2  | 1 ... 0 | 15 ... 0  |   31 ... 0    |    31 ... 0    |
 * |---------|------|------|-----|---------|-----------|---------------|----------------|
 * |  RSVD   | COMP | TIME | CRC | SESSION |  PEER ID  |   SEND TIME   |      CRC32     |
 *  ------------------------------------------------------------------------------------
 *
 * TL;DR: CRC should always be one.
 *
 * As pointed out by Evan Jones at http://www.evanjones.ca/tcp-and-ethernet-checksums-fail.html
 *
 * TCP [and UDP] checksum is two bytes long, and can detect any burst error of 15 bits, and most burst errors of 16 bits (excluding switching 0x0000 and 0xffff).
 * This means that to keep the same checksum, a packet must be corrupted in at least two locations, at least 2 bytes apart. If the chance is purely random,
 * we should expect approximately 1 in 65536 (approximately 0.001%) of corrupt packets to not be detected. This seems small, but on one Gigabit Ethernet
 * connection, that could be as many as 15 packets per second. For details about how to compute TCP/IP checksums and its error properties, see
 * RFC 768 <http://www.faqs.org/rfcs/rfc768.html> and RFC 1071 <https://tools.ietf.org/html/rfc1071>.
 * Also bear in mind that TCP [and UDP] checksum is optional and can either be disabled or not supported at all by a certain platform.
 *
 * The Ethernet CRC is substantially stronger, partly because it is twice as long (4 bytes), and partly because CRCs have "good" mathematical properties(...)
 * [802.3 CRC] can detect up to 3 bit errors in a 1500 byte frame (see http://users.ece.cmu.edu/~koopman/networks/dsn02/dsn02_koopman.pdf).
 * It appears that most switches discard packets with invalid CRCs when they are received, and recalculate the CRC when a packet goes back out. This means
 * the CRC really only protects against corruption on the wire, and not inside a switch or any other type of intermediary network node. Why not just re-send
 * the existing CRC then ? Modern switch chips have features that modify packets, such as VLANs or explicit congestion notification. Hence, it is simpler to
 * always recompute the CRC. For a detailed description, see Denton Gentry's description of how the Ethernet CRC doesn't protect very much
 * <https://codingrelic.geekhold.com/2009/11/ethernet-integrity-or-lack-thereof.html>.
 *
 * There is also one small complication that does not change this cause of failure but does change how you might detect it. Some switches support cut-through
 * switching, where packets begin being forwarded as soon as the destination address is read, without waiting for the entire packet. In this case, it is already
 * sending the packet before it can validate it, so it absolutely cannot recalculate the CRC. These switches typically support something called "CRC stomping"
 * to ensure the outgoing CRC is invalid, so the ultimate receiver will eventually discard it. This gets more complicated when a destination port is being used
 * when a new packet arrives. In this case, cut-through switches must buffer packets, and then act like a store-and-forward switch. Hence, cut-through switching
 * does not prevent switches from corrupting packets and appending a valid Ethernet CRC. See Cisco's white paper on cut-through switching
 * <https://www.cisco.com/c/en/us/products/collateral/switches/nexus-5020-switch/white_paper_c11-465436.html> and Cut-through, corruption and CRC-stomping
 * <http://thenetworksherpa.com/cut-through-corruption-and-crc-stomping/> for more details.
 *
 * The conclusion is that when transmitting or storing data, you should always include strong CRCs that protect the data all the way from the sender to the final
 * receiver.
 */
typedef struct _ENetProtocolHeader 
{
    enet_uint8  flags;
    enet_uint16 peerId;
    enet_uint32 sentTime;
} ENET_PACKED ENetProtocolHeader;

#define ENET_PROTOCOL_HEADER_FLAG_RSVD_1                        ((enet_uint8) 0x80)
#define ENET_PROTOCOL_HEADER_FLAG_RSVD_2                        ((enet_uint8) 0x40)
#define ENET_PROTOCOL_HEADER_FLAG_RSVD_3                        ((enet_uint8) 0x20)
#define ENET_PROTOCOL_HEADER_FLAG_COMP                          ((enet_uint8) 0x10)
#define ENET_PROTOCOL_HEADER_FLAG_TIME                          ((enet_uint8) 0x08)
#define ENET_PROTOCOL_HEADER_FLAG_CRC                           ((enet_uint8) 0x04)
#define ENET_PROTOCOL_HEADER_SESSION                            ((enet_uint8) 0x03)

/***
 *  PROTOCOL COMMAND HEADER
 *
 *  Size: 4 bytes
 *  A packet may aggregate one or more commands. Each command starts with an ENetProtocolCommandHeader.
 *
 *   -------------------------------------------------------
 *  |              0                |     1     |  2  |  3  |
 *   -------------------------------------------------------
 *  |  7  |  6  | 5 ... 4 | 3 ... 0 |  7 ... 0  |  15 ... 0 |
 *  |-----|-----|---------|---------|-----------|-----------|
 *  | ACK | USQ |  RSVD   | OPCODE  |  CHANNEL  |  SEQNUM   |
 *   -------------------------------------------------------
 *
 */
typedef struct _ENetProtocolCommandHeader 
{
    enet_uint8  command;
    enet_uint8  channelId;
    enet_uint16 reliableSequenceNumber;
} ENET_PACKED ENetProtocolCommandHeader;

#define ENET_PROTOCOL_COMMAND_FLAG_ACK                          ((enet_uint8) 0x80)
#define ENET_PROTOCOL_COMMAND_FLAG_USQ                          ((enet_uint8) 0x40)
#define ENET_PROTOCOL_COMMAND_FLAG_RSVD_1                       ((enet_uint8) 0x20)
#define ENET_PROTOCOL_COMMAND_FLAG_RSVD_2                       ((enet_uint8) 0x10)

#define ENET_PROTOCOL_COMMAND_MASK                              ((enet_uint8) 0x0F)

#define ENET_PROTOCOL_COMMAND_NONE                              ((enet_uint8) 0x00)
#define ENET_PROTOCOL_COMMAND_ACKNOWLEDGE                       ((enet_uint8) 0x01)
#define ENET_PROTOCOL_COMMAND_CONNECT                           ((enet_uint8) 0x02)
#define ENET_PROTOCOL_COMMAND_ACCEPT                            ((enet_uint8) 0x03)
#define ENET_PROTOCOL_COMMAND_DISCONNECT                        ((enet_uint8) 0x04)
#define ENET_PROTOCOL_COMMAND_PING                              ((enet_uint8) 0x05)
#define ENET_PROTOCOL_COMMAND_SEND_RELIABLE_PACKET              ((enet_uint8) 0x06)
#define ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_PACKET            ((enet_uint8) 0x07)
#define ENET_PROTOCOL_COMMAND_SEND_OUTOFBAND_PACKET             ((enet_uint8) 0x08)
                                                                    
#define ENET_PROTOCOL_COMMAND_SEND_RELIABLE_FRAGMENT            ((enet_uint8) 0x09)
#define ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT          ((enet_uint8) 0x0A)
#define ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT                   ((enet_uint8) 0x0B)
#define ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE                ((enet_uint8) 0x0C)
#define ENET_PROTOCOL_COMMAND_RSVD_1                            ((enet_uint8) 0x0D)
#define ENET_PROTOCOL_COMMAND_RSVD_2                            ((enet_uint8) 0x0E)
#define ENET_PROTOCOL_COMMAND_RSVD_3                            ((enet_uint8) 0x0F)

#define ENET_PROTOCOL_COMMAND_COUNT                             16


typedef struct _ENetProtocolAcknowledge 
{
    ENetProtocolCommandHeader       header;
    enet_uint16                     receivedReliableSequenceNumber;
    enet_uint16                     receivedSentTime;
} ENET_PACKED ENetProtocolAcknowledge;

typedef struct _ENetProtocolConnect 
{
    ENetProtocolCommandHeader       header;
    enet_uint16                     outgoingPeerId;
    enet_uint8                      incomingSessionId;
    enet_uint8                      outgoingSessionId;
    enet_uint16                     mtu;
    enet_uint16                     channelCount;
    enet_uint32                     windowSize;
    enet_uint32                     incomingBandwidth;
    enet_uint32                     outgoingBandwidth;
    enet_uint32                     packetThrottleInterval;
    enet_uint32                     packetThrottleAcceleration;
    enet_uint32                     packetThrottleDeceleration;
    enet_uint32                     connectId;
    enet_uint32                     status;
} ENET_PACKED ENetProtocolConnect;

typedef struct _ENetProtocolAccept
{
    ENetProtocolCommandHeader       header;
    enet_uint16                     outgoingPeerId;
    enet_uint8                      incomingSessionId;
    enet_uint8                      outgoingSessionId;
    enet_uint16                     mtu;
    enet_uint16                     channelCount;
    enet_uint32                     windowSize;
    enet_uint32                     incomingBandwidth;
    enet_uint32                     outgoingBandwidth;
    enet_uint32                     packetThrottleInterval;
    enet_uint32                     packetThrottleAcceleration;
    enet_uint32                     packetThrottleDeceleration;
    enet_uint32                     connectId;
} ENET_PACKED ENetProtocolAccept;

typedef struct _ENetProtocolBandwidthLimit 
{
    ENetProtocolCommandHeader       header;
    enet_uint32                     incomingBandwidth;
    enet_uint32                     outgoingBandwidth;
} ENET_PACKED ENetProtocolBandwidthLimit;

typedef struct _ENetProtocolThrottleConfigure 
{
    ENetProtocolCommandHeader       header;
    enet_uint32                     packetThrottleInterval;
    enet_uint32                     packetThrottleAcceleration;
    enet_uint32                     packetThrottleDeceleration;
} ENET_PACKED ENetProtocolThrottleConfigure;

typedef struct _ENetProtocolDisconnect 
{
    ENetProtocolCommandHeader       header;
    enet_uint32                     status;
} ENET_PACKED ENetProtocolDisconnect;

typedef struct _ENetProtocolPing 
{
    ENetProtocolCommandHeader       header;
} ENET_PACKED ENetProtocolPing;

typedef struct _ENetProtocolSendReliable 
{
    ENetProtocolCommandHeader       header;
    enet_uint16                     dataLength;
} ENET_PACKED ENetProtocolSendReliable;

typedef struct _ENetProtocolSendUnreliable 
{
    ENetProtocolCommandHeader       header;
    enet_uint16                     unreliableSequenceNumber;
    enet_uint16                     dataLength;
} ENET_PACKED ENetProtocolSendUnreliable;

typedef struct _ENetProtocolSendUnsequenced 
{
    ENetProtocolCommandHeader       header;
    enet_uint16                     unsequencedGroup;
    enet_uint16                     dataLength;
} ENET_PACKED ENetProtocolSendUnsequenced;

typedef struct _ENetProtocolSendFragment 
{
    ENetProtocolCommandHeader       header;
    enet_uint16                     startSequenceNumber;
    enet_uint16                     dataLength;
    enet_uint16                     fragmentCount;
    enet_uint16                     fragmentNumber;
    enet_uint32                     totalLength;
    enet_uint32                     fragmentOffset;
} ENET_PACKED ENetProtocolSendFragment;

typedef union _ENetProtocol 
{
    ENetProtocolCommandHeader       header;
    ENetProtocolAcknowledge         acknowledge;
    ENetProtocolConnect             connect;
    ENetProtocolAccept              accept;
    ENetProtocolDisconnect          disconnect;
    ENetProtocolPing                ping;
    ENetProtocolSendReliable        sendReliable;
    ENetProtocolSendUnreliable      sendUnreliable;
    ENetProtocolSendUnsequenced     sendUnsequenced;
    ENetProtocolSendFragment        sendFragment;
    ENetProtocolBandwidthLimit      bandwidthLimit;
    ENetProtocolThrottleConfigure   throttleConfigure;
} ENET_PACKED ENetProtocol;

#ifdef _MSC_VER
    #pragma pack(pop)
#endif



/**************************************************************************
 * General ENet structs/enums
 **************************************************************************/

#define ENET_ERROR_NONE                                   0
#define ENET_ERROR                                       -1
#define ENET_ERROR_INVALID_OPERATION                     -2
#define ENET_ERROR_INVALID_ARGUMENTS                     -3
#define ENET_ERROR_OUT_OF_MEMORY                         -4

#define ENET_ERROR_RECEIVING_INCOMING_PACKETS           -10
#define ENET_ERROR_DISPATCHING_INCOMING_PACKETS         -11
#define ENET_ERROR_SENDING_OUTGOING_COMMANDS            -12
#define ENET_ERROR_SOCKET_WAIT_FAILED                   -13

typedef enum _ENetSocketType 
{
    ENET_SOCKET_TYPE_NONE = 0,
    ENET_SOCKET_TYPE_STREAM,
    ENET_SOCKET_TYPE_DATAGRAM
} ENetSocketType;

typedef enum _ENetSocketWait 
{
    ENET_SOCKET_WAIT_NONE      = 0,
    ENET_SOCKET_WAIT_SEND      = (1 << 0),
    ENET_SOCKET_WAIT_RECEIVE   = (1 << 1),
    ENET_SOCKET_WAIT_INTERRUPT = (1 << 2)
} ENetSocketWait;

typedef enum _ENetSocketOption 
{
    ENET_SOCKOPT_NONE = 0,
    ENET_SOCKOPT_NONBLOCK,
    ENET_SOCKOPT_BROADCAST,
    ENET_SOCKOPT_RCVBUF,
    ENET_SOCKOPT_SNDBUF,
    ENET_SOCKOPT_REUSEADDR,
    ENET_SOCKOPT_RCVTIMEO,
    ENET_SOCKOPT_SNDTIMEO,
    ENET_SOCKOPT_ERROR,
    ENET_SOCKOPT_NODELAY,
    ENET_SOCKOPT_IPV6_V6ONLY
} ENetSocketOption;

typedef enum _ENetSocketShutdown 
{
    ENET_SOCKET_SHUTDOWN_READ = 0,
    ENET_SOCKET_SHUTDOWN_WRITE,
    ENET_SOCKET_SHUTDOWN_READ_WRITE
} ENetSocketShutdown;

typedef struct _ENetAddress 
{
    struct in6_addr host;       // A specific host address can be specified by using enet_address_set_host(&address, "x.x.x.x") otherwise must be set to ENET_HOST_ANY;
    enet_uint16     port;
    enet_uint32     scope_id;   // Used to identify a set of interfaces as appropriate for the scope of the address carried in the host field. A value of zero does not identify any set of interfaces to be used, and might be specified for any address types and scopes. For a link scope address, this field might specify a link index which identifies a set of interfaces. For all other address scopes, this field must be set to zero.
} ENetAddress;

#define in6_equal(in6_addr_a, in6_addr_b) (memcmp(&in6_addr_a, &in6_addr_b, sizeof(struct in6_addr)) == 0)
    
    
#define ENET_PACKET_FLAG_RELIABLE                               (1 << 0)    // Packet must be received by the target peer and resend attempts should be made until the packet is delivered
#define ENET_PACKET_FLAG_UNSEQUENCED                            (1 << 1)    // Packet will not be sequenced with other packets not supported for reliable packets
#define ENET_PACKET_FLAG_NO_ALLOCATE                            (1 << 2)    // Packet will not allocate data, and user must supply it instead
#define ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT                    (1 << 3)    // If length exceeds the MTU, packet will be fragmented using unreliable (rather than reliable) sub-packets 
#define ENET_PACKET_FLAG_SENT                                   (1 << 8)    // Whether the packet has been sent from all queues it has been pushed into

typedef void (ENET_CALLBACK* ENetPacketFreeCallback) (void*);

typedef struct _ENetPacket 
{
    size_t                 referenceCount;
    enet_uint16            flags;
    enet_uint8*            data;
    size_t                 dataLength;
    ENetPacketFreeCallback freeCallback;    // Function called by enet_packet_destroy when the packet is no longer in use. Can be used when creating a packet with ENET_PACKET_FLAG_NO_ALLOCATE to free the pre-allocated memory passed to the packet.
    void*                  userData;        // Application data, may be freely modified 
} ENetPacket;

typedef struct _ENetAcknowledgement 
{
    ENetListNode acknowledgementList;
    enet_uint16  sentTime;
    ENetProtocol command;
} ENetAcknowledgement;

typedef struct _ENetOutgoingCommand 
{
    ENetListNode outgoingCommandList;
    enet_uint16  reliableSequenceNumber;
    enet_uint16  unreliableSequenceNumber;
    enet_uint32  sentTime;
    enet_uint32  roundTripTimeout;
    enet_uint32  roundTripTimeoutLimit;
    enet_uint32  fragmentOffset;
    enet_uint16  fragmentLength;
    enet_uint16  sendAttempts;
    ENetProtocol command;
    ENetPacket*  packet;
} ENetOutgoingCommand;

typedef struct _ENetIncomingCommand 
{
    ENetListNode incomingCommandList;
    enet_uint16  reliableSequenceNumber;
    enet_uint16  unreliableSequenceNumber;
    ENetProtocol command;
    enet_uint16  fragmentCount;
    enet_uint32  fragmentsRemaining;
    enet_uint32* fragments;
    ENetPacket*  packet;
} ENetIncomingCommand;

typedef enum _ENetPeerState 
{
    ENET_PEER_STATE_DISCONNECTED = 0,
    ENET_PEER_STATE_CONNECTING,
    ENET_PEER_STATE_ACKNOWLEDGING_CONNECT,
    ENET_PEER_STATE_CONNECTION_PENDING,
    ENET_PEER_STATE_CONNECTION_SUCCEEDED,
    ENET_PEER_STATE_CONNECTED,
    ENET_PEER_STATE_DISCONNECT_LATER,
    ENET_PEER_STATE_DISCONNECTING,
    ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT,
    ENET_PEER_STATE_ZOMBIE
} ENetPeerState;

#define ENET_HOST_RECEIVE_BUFFER_SIZE                           (256 * 1024)
#define ENET_HOST_SEND_BUFFER_SIZE                              (256 * 1024)
#define ENET_HOST_BANDWIDTH_THROTTLE_INTERVAL                   1000
#define ENET_HOST_DEFAULT_MTU                                   1400
#define ENET_HOST_DEFAULT_MAXIMUM_PACKET_SIZE                   (32 * 1024 * 1024)
#define ENET_HOST_DEFAULT_MAXIMUM_WAITING_DATA                  (32 * 1024 * 1024)
#define ENET_HOST_PACKET_DATA_LENGTH_MAX                        ((size_t)ENET_PROTOCOL_MAXIMUM_MTU)

#define ENET_PEER_DEFAULT_ROUND_TRIP_TIME                       500
#define ENET_PEER_DEFAULT_PACKET_THROTTLE                       32
#define ENET_PEER_PACKET_THROTTLE_SCALE                         32
#define ENET_PEER_PACKET_THROTTLE_COUNTER                       7
#define ENET_PEER_PACKET_THROTTLE_ACCELERATION                  2
#define ENET_PEER_PACKET_THROTTLE_DECELERATION                  2
#define ENET_PEER_PACKET_THROTTLE_INTERVAL                      5000
#define ENET_PEER_PACKET_LOSS_SCALE                             65536
#define ENET_PEER_PACKET_LOSS_INTERVAL                          10000
#define ENET_PEER_WINDOW_SIZE_SCALE                             (64 * 1024)
#define ENET_PEER_TIMEOUT_LIMIT                                 32
#define ENET_PEER_TIMEOUT_MINIMUM                               5000
#define ENET_PEER_TIMEOUT_MAXIMUM                               30000
#define ENET_PEER_PING_INTERVAL                                 500
#define ENET_PEER_UNSEQUENCED_WINDOWS                           64
#define ENET_PEER_UNSEQUENCED_WINDOW_SIZE                       1024
#define ENET_PEER_FREE_UNSEQUENCED_WINDOWS                      32
#define ENET_PEER_RELIABLE_WINDOWS                              16
#define ENET_PEER_RELIABLE_WINDOW_SIZE                          4096
#define ENET_PEER_FREE_RELIABLE_WINDOWS                         8

typedef enum _ENetEventType
{
    ENET_EVENT_TYPE_NONE = 0,
    ENET_EVENT_TYPE_CONNECT,
    ENET_EVENT_TYPE_DISCONNECT,
    ENET_EVENT_TYPE_RECEIVE,
    ENET_EVENT_TYPE_TIMEOUT
} ENetEventType;

typedef struct _ENetEvent
{
    ENetEventType       type;
    struct _ENetPeer*   peer;
    enet_uint8          channelId;
    enet_uint32         status;
    ENetPacket*         packet;
} ENetEvent;

typedef struct _ENetChannel 
{
    enet_uint16 outgoingReliableSequenceNumber;
    enet_uint16 outgoingUnreliableSequenceNumber;
    enet_uint16 usedReliableWindows;
    enet_uint16 reliableWindows[ENET_PEER_RELIABLE_WINDOWS];
    enet_uint16 incomingReliableSequenceNumber;
    enet_uint16 incomingUnreliableSequenceNumber;
    ENetList    incomingReliableCommands;
    ENetList    incomingUnreliableCommands;
} ENetChannel;

typedef struct _ENetPeer 
{
    ENetListNode      dispatchList;
    struct _ENetHost* host;
    enet_uint16       outgoingPeerId;
    enet_uint16       incomingPeerId;
    enet_uint32       connectId;
    enet_uint8        outgoingSessionId;
    enet_uint8        incomingSessionId;
    ENetAddress       address;
    void*             userData; // Application data, may be freely modified 
    ENetPeerState     state;
    ENetChannel*      channels;
    enet_uint16       channelCount;
    enet_uint32       incomingBandwidth;
    enet_uint32       outgoingBandwidth;
    enet_uint32       incomingBandwidthThrottleEpoch;
    enet_uint32       outgoingBandwidthThrottleEpoch;
    enet_uint32       incomingDataTotal;
    enet_uint64       totalDataReceived;
    enet_uint32       outgoingDataTotal;
    enet_uint64       totalDataSent;
    enet_uint32       lastSendTime;
    enet_uint32       lastReceiveTime;
    enet_uint32       nextTimeout;
    enet_uint32       earliestTimeout;
    enet_uint32       packetLossEpoch;
    enet_uint32       packetsSent;
    enet_uint64       totalPacketsSent;
    enet_uint32       packetsLost;
    enet_uint64       totalPacketsLost;
    enet_uint32       packetLoss;
    enet_uint32       packetLossVariance;
    enet_uint32       packetThrottle;
    enet_uint32       packetThrottleLimit;
    enet_uint32       packetThrottleCounter;
    enet_uint32       packetThrottleEpoch;
    enet_uint32       packetThrottleAcceleration;
    enet_uint32       packetThrottleDeceleration;
    enet_uint32       packetThrottleInterval;
    enet_uint32       pingInterval;
    enet_uint32       timeoutLimit;
    enet_uint32       timeoutMinimum;
    enet_uint32       timeoutMaximum;
    enet_uint32       smoothedRoundTripTime;
    enet_uint32       lastRoundTripTime;
    enet_uint32       lowestRoundTripTime;
    enet_uint32       lastRoundTripTimeVariance;
    enet_uint32       highestRoundTripTimeVariance;
    enet_uint32       roundTripTime;
    enet_uint32       roundTripTimeVariance;
    enet_uint16       mtu;
    enet_uint32       windowSize;
    enet_uint32       reliableDataInTransit;
    enet_uint16       outgoingReliableSequenceNumber;
    ENetList          acknowledgements;
    ENetList          sentReliableCommands;
    ENetList          sentUnreliableCommands;
    ENetList          outgoingReliableCommands;
    ENetList          outgoingUnreliableCommands;
    ENetList          dispatchedCommands;
    int               needsDispatch;
    enet_uint16       incomingUnsequencedGroup;
    enet_uint16       outgoingUnsequencedGroup;
    enet_uint32       unsequencedWindow[ENET_PEER_UNSEQUENCED_WINDOW_SIZE / 32];
    enet_uint32       eventStatus;
    size_t            totalWaitingData;
} ENetPeer;

typedef enet_uint32 (ENET_CALLBACK* ENetChecksumCallback) (const ENetBuffer* buffers, size_t bufferCount);

typedef int (ENET_CALLBACK* ENetHostInterceptCallback) (struct _ENetHost* host, struct _ENetEvent* event);

typedef struct _ENetHost 
{
    ENetSocket                  socket;
    ENetAddress                 address;
    enet_uint32                 incomingBandwidth;            // downstream bandwidth of the host
    enet_uint32                 outgoingBandwidth;            // upstream bandwidth of the host
    enet_uint32                 bandwidthThrottleEpoch;
    enet_uint16                 mtu;
    enet_uint32                 randomSeed;
    int                         recalculateBandwidthLimits;
    enet_uint8                  refuseConnections;
    ENetPeer*                   peers;                        // array of peers allocated for this host
    size_t                      peerCount;                    // number of peers allocated for this host
    enet_uint16                 channelLimit;                 // maximum number of channels allowed for connected peers
    enet_uint32                 serviceTime;
    enet_uint64                 startTime;                    // time this host was created can be used to obtain the uptime by means of (enet_time() - start_time)
    ENetList                    dispatchQueue;
    int                         continueSending;
    size_t                      packetSize;
    enet_uint8                  headerFlags;
    enet_uint64                 totalSentData;                // total data sent
    enet_uint64                 totalSentPackets;             // total UDP packets received
    enet_uint64                 totalReceivedData;            // total data received
    enet_uint64                 totalReceivedPackets;         // total UDP packets sent
    ENetProtocol                commands[ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS];
    size_t                      commandCount;
    ENetBuffer                  buffers[ENET_BUFFER_MAXIMUM];
    size_t                      bufferCount;
    enet_uint8                  compressionEnabled;           // if true will output packets compressed (incoming packets are always handled according to the COMP flag regardless of this setting)
    size_t                      compressionBufferSize;
    char*                       compressionBuffer;
    enet_uint8                  crcEnabled;                   // if true will output packets with crc (incoming packets are always handled according to the CRC flag regardless of this setting)
    enet_uint8                  packetData[2][ENET_HOST_PACKET_DATA_LENGTH_MAX];
    ENetAddress                 receivedAddress;
    enet_uint8*                 receivedData;
    enet_uint32                 receivedDataLength;
    ENetHostInterceptCallback   interceptCallback;            // callback the user can set to intercept received raw UDP packets
    enet_uint32                 connectedPeers;
    size_t                      bandwidthLimitedPeers;
    enet_uint16                 duplicatePeers;               // optional number of allowed peers from duplicate IPs, defaults to ENET_PROTOCOL_MAXIMUM_PEER_COUNT
    enet_uint32                 maximumPacketSize;            // the maximum allowable packet size that may be sent or received on a peer
    size_t                      maximumWaitingData;           // the maximum aggregate amount of buffer space a peer may use waiting for packets to be delivered
} ENetHost;


/**************************************************************************
 * Public API
 **************************************************************************/

ENET_API int                   enet_initialize(void);
ENET_API int                   enet_initialize_with_callbacks(const ENetCallbacks* callbacks);
ENET_API void                  enet_finalize(void);
ENET_API ENetVersion           enet_linked_version(void);
ENET_API enet_uint64           enet_time(void);

         ENetSocket            enet_socket_create(ENetSocketType type);
         int                   enet_socket_bind(ENetSocket socket, const ENetAddress* address);
         int                   enet_socket_get_address(ENetSocket socket, ENetAddress* address);
         int                   enet_socket_listen(ENetSocket socket, int backlog);
         ENetSocket            enet_socket_accept(ENetSocket socket, ENetAddress* address);
         int                   enet_socket_connect(ENetSocket socket, const ENetAddress* address);
         int                   enet_socket_send(ENetSocket socket, const ENetAddress* address, const ENetBuffer* buffers, size_t bufferCount);
         int                   enet_socket_receive(ENetSocket socket, ENetAddress* address, ENetBuffer* buffers, size_t bufferCount);
         int                   enet_socket_wait(ENetSocket socket, enet_uint32* condition, enet_uint32 timeout);
         int                   enet_socket_set_option(ENetSocket socket, ENetSocketOption option, int value);
         int                   enet_socket_get_option(ENetSocket socket, ENetSocketOption option, int* value);
         int                   enet_socket_shutdown(ENetSocket socket, ENetSocketShutdown how);
         void                  enet_socket_destroy(ENetSocket socket);
         int                   enet_socket_select(ENetSocket maxSocket, ENetSocketSet* readSet, ENetSocketSet* writeSet, enet_uint32 timeout);

ENET_API void                  enet_address_localhost(ENetAddress* address, enet_uint16 port);
ENET_API void                  enet_address_anyhost(ENetAddress* address, enet_uint16 port);

ENET_API int                   enet_address_set_ip(ENetAddress* address, const char* hostName);
ENET_API int                   enet_address_set_name(ENetAddress* address, const char* hostName);
ENET_API int                   enet_address_get_ip(const ENetAddress* address, char* hostName, size_t nameLength);
ENET_API int                   enet_address_get_name(const ENetAddress* address, char* hostName, size_t nameLength);

ENET_API ENetPacket*           enet_packet_create(const void* data, size_t dataLength, enet_uint16 flags);
ENET_API ENetPacket*           enet_packet_create_offset(const void* data, size_t dataLength, size_t dataOffset, enet_uint16 flags);
ENET_API void                  enet_packet_destroy(ENetPacket* packet);

ENET_API enet_uint32           enet_crc32(const ENetBuffer* buffers, size_t bufferCount);

ENET_API ENetHost*             enet_host_create(const ENetAddress* localAddress, size_t peerCount, enet_uint16 channelLimit, enet_uint32 incomingBandwidth, enet_uint32 outgoingBandwidth);
ENET_API void                  enet_host_destroy(ENetHost* host);

ENET_API void                  enet_host_set_compression_enabled(ENetHost* host, enet_uint8 value);
ENET_API enet_uint8            enet_host_get_compression_enabled(ENetHost* host);

ENET_API void                  enet_host_set_crc_enabled(ENetHost* host, enet_uint8 value);
ENET_API enet_uint8            enet_host_get_crc_enabled(ENetHost* host);

ENET_API void                  enet_host_set_refuse_connections(ENetHost* host, enet_uint8 value);
ENET_API enet_uint8            enet_host_get_refuse_connections(ENetHost* host);

ENET_API void                  enet_host_set_channel_limit(ENetHost* host, enet_uint16 channelLimit);
ENET_API enet_uint16           enet_host_get_channel_limit(ENetHost* host);

ENET_API enet_uint64           enet_host_get_start_time(ENetHost* host);

ENET_API ENetPeer*             enet_host_connect(ENetHost* host, const ENetAddress* address, enet_uint16 channelCount, enet_uint32 status);
ENET_API int                   enet_host_check_events(ENetHost* host, ENetEvent* event);
ENET_API int                   enet_host_service(ENetHost* host, ENetEvent* event, enet_uint32 timeout);
ENET_API void                  enet_host_flush(ENetHost* host);
ENET_API void                  enet_host_broadcast(ENetHost* host, enet_uint8 channelId, ENetPacket* packet);
ENET_API void                  enet_host_bandwidth_limit(ENetHost* host, enet_uint32 incomingBandwidth, enet_uint32 outgoingBandwidth);

         void                  enet_host_bandwidth_throttle(ENetHost* host);
         enet_uint32           enet_host_random_seed();
         enet_uint32           enet_host_next_random(ENetHost* host);

ENET_API int                   enet_peer_send(ENetPeer* peer, enet_uint8 channelId, ENetPacket* packet);
ENET_API ENetPacket*           enet_peer_receive(ENetPeer* peer, enet_uint8* channelId);

ENET_API void                  enet_peer_ping(ENetPeer* peer);
ENET_API void                  enet_peer_set_ping_interval(ENetPeer* peer, enet_uint32 pingInterval);
ENET_API enet_uint32           enet_peer_get_ping_interval(ENetPeer* peer);

ENET_API void                  enet_peer_disconnect(ENetPeer* peer, enet_uint32 status);
ENET_API void                  enet_peer_disconnect_immediately(ENetPeer* peer, enet_uint32 status);
ENET_API void                  enet_peer_disconnect_when_ready(ENetPeer* peer, enet_uint32 status);

ENET_API void                  enet_peer_reset(ENetPeer* peer);

ENET_API void                  enet_peer_timeout(ENetPeer* peer, enet_uint32 timeoutLimit, enet_uint32 timeoutMinimum, enet_uint32 timeoutMaximum);
ENET_API void                  enet_peer_throttle_configure(ENetPeer* peer, enet_uint32 interval, enet_uint32 acceleration, enet_uint32 deceleration);

         int                   enet_peer_throttle(ENetPeer* peer, enet_uint32 rtt);
         void                  enet_peer_reset_queues(ENetPeer* peer);
         void                  enet_peer_setup_outgoing_command(ENetPeer* peer, ENetOutgoingCommand* outgoingCommand);
         ENetOutgoingCommand*  enet_peer_queue_outgoing_command(ENetPeer* peer, const ENetProtocol* command, ENetPacket* packet, enet_uint32 offset, enet_uint16 length);
         ENetIncomingCommand*  enet_peer_queue_incoming_command(ENetPeer* peer, const ENetProtocol* command, const void* data, size_t dataLength, enet_uint16 flags, enet_uint16 fragmentCount);
         ENetAcknowledgement*  enet_peer_queue_acknowledgement(ENetPeer* peer, const ENetProtocol* command, enet_uint16 sentTime);
         void                  enet_peer_dispatch_incoming_unreliable_commands(ENetPeer* peer, ENetChannel* channel);
         void                  enet_peer_dispatch_incoming_reliable_commands(ENetPeer* peer, ENetChannel* channel);
         void                  enet_peer_on_connect(ENetPeer* peer);
         void                  enet_peer_on_disconnect(ENetPeer* peer);

         size_t                enet_protocol_command_size(enet_uint8 commandNumber);

/* Extended API for easier binding in other programming languages */
ENET_API void*                 enet_packet_get_data(ENetPacket* packet);
ENET_API int                   enet_packet_get_length(ENetPacket* packet);
ENET_API void                  enet_packet_set_free_callback(ENetPacket* packet, const void* callback);
ENET_API void                  enet_packet_dispose(ENetPacket* packet);

ENET_API void                  enet_host_set_intercept_callback(ENetHost* host, const void* callback);

ENET_API ENetPeer*             enet_host_get_peer(ENetHost* host, enet_uint32 index);
ENET_API enet_uint32           enet_host_get_peers_count(ENetHost* host);
ENET_API enet_uint32           enet_host_get_peers_capacity(ENetHost* host);
ENET_API enet_uint64           enet_host_get_packets_sent(ENetHost* host);
ENET_API enet_uint64           enet_host_get_packets_received(ENetHost* host);
ENET_API enet_uint64           enet_host_get_bytes_sent(ENetHost* host);
ENET_API enet_uint64           enet_host_get_bytes_received(ENetHost* host);

ENET_API enet_uint32           enet_peer_get_id(ENetPeer* peer);
ENET_API enet_uint16           enet_peer_get_incoming_id(ENetPeer* peer);
ENET_API enet_uint16           enet_peer_get_outgoing_id(ENetPeer* peer);
ENET_API int                   enet_peer_get_ip(ENetPeer* peer, char* ip, size_t length);
ENET_API int                   enet_peer_get_name(ENetPeer* peer, char* name, size_t length);
ENET_API enet_uint16           enet_peer_get_port(ENetPeer* peer);
ENET_API enet_uint16           enet_peer_get_mtu(ENetPeer* peer);
ENET_API ENetPeerState         enet_peer_get_state(ENetPeer* peer);
ENET_API enet_uint32           enet_peer_get_rtt(ENetPeer* peer);
ENET_API enet_uint32           enet_peer_get_lastsendtime(ENetPeer* peer);
ENET_API enet_uint32           enet_peer_get_lastreceivetime(ENetPeer* peer);
ENET_API enet_uint64           enet_peer_get_packets_sent(ENetPeer* peer);
ENET_API enet_uint64           enet_peer_get_packets_lost(ENetPeer* peer);
ENET_API enet_uint64           enet_peer_get_bytes_sent(ENetPeer* peer);
ENET_API enet_uint64           enet_peer_get_bytes_received(ENetPeer* peer);
ENET_API void*                 enet_peer_get_userdata(ENetPeer* peer);
ENET_API void                  enet_peer_set_userdata(ENetPeer* peer, const void* data);
ENET_API enet_uint16           enet_peer_get_channel_count(ENetPeer* peer);

#ifdef __cplusplus
}
#endif

#endif // ENET_INCLUDE_H
