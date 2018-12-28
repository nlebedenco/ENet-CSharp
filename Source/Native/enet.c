/*
 *  ENet reliable UDP networking library 
 *  Copyright (c) 2018 Lee Salzman, Vladyslav Hrytsenko, Dominik Madarász, Stanislav Denisov
 *  Copyright (c) 2018  Nicolas Lebedenco
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

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define ENET_IMPLEMENTATION
#define ENET_DLL
#include "enet.h"
#include "stdio.h"

#ifdef __cplusplus
extern "C" {
#endif



/**************************************************************************
 * Atomics
 **************************************************************************/

#ifdef _MSC_VER

#define ENET_AT_CASSERT_PRED(predicate) sizeof(char[2 * !!(predicate)-1])
#define ENET_IS_SUPPORTED_ATOMIC(size) ENET_AT_CASSERT_PRED(size == 1 || size == 2 || size == 4 || size == 8)
#define ENET_ATOMIC_SIZEOF(variable) (ENET_IS_SUPPORTED_ATOMIC(sizeof(*(variable))), sizeof(*(variable)))

__inline int64_t enet_at_atomic_read(char* ptr, size_t size) 
{
	switch (size) 
	{
	case 1: return _InterlockedExchangeAdd8((volatile char* )ptr, 0);
	case 2: return _InterlockedExchangeAdd16((volatile SHORT* )ptr, 0);
	case 4: return _InterlockedExchangeAdd((volatile LONG* )ptr, 0);
	case 8: return _InterlockedExchangeAdd64((volatile LONGLONG* )ptr, 0);
	default: return 0x0;
	}
}

__inline int64_t enet_at_atomic_write(char* ptr, int64_t value, size_t size) 
{
	switch (size) 
	{
	case 1: return _InterlockedExchange8((volatile char* )ptr, (char)value);
	case 2: return _InterlockedExchange16((volatile SHORT* )ptr, (SHORT)value);
	case 4:	return _InterlockedExchange((volatile LONG* )ptr, (LONG)value);
	case 8: return _InterlockedExchange64((volatile LONGLONG* )ptr, (LONGLONG)value);
	default: return 0x0;
	}
}

__inline int64_t enet_at_atomic_cas(char* ptr, int64_t new_val, int64_t old_val, size_t size) 
{
	switch (size) 
	{
	case 1: return _InterlockedCompareExchange8((volatile char*)ptr, (char)new_val, (char)old_val);
	case 2: return _InterlockedCompareExchange16((volatile SHORT*)ptr, (SHORT)new_val, (SHORT)old_val);
	case 4: return _InterlockedCompareExchange((volatile LONG*)ptr, (LONG)new_val, (LONG)old_val);
	case 8: return _InterlockedCompareExchange64((volatile LONGLONG*)ptr, (LONGLONG)new_val, (LONGLONG)old_val);
	default: return 0x0;
	}
}

__inline int64_t enet_at_atomic_inc(char* ptr, int64_t delta, size_t size)
{
	switch (size) 
	{
	case 1: return _InterlockedExchangeAdd8((volatile char*)ptr, (char)delta);
	case 2: return _InterlockedExchangeAdd16((volatile SHORT*)ptr, (SHORT)delta);
	case 4: return _InterlockedExchangeAdd((volatile LONG*)ptr, (LONG)delta);
	case 8: return _InterlockedExchangeAdd64((volatile LONGLONG*)ptr, (LONGLONG)delta);
	default: return 0x0;
	}
}

#define ENET_ATOMIC_READ(variable)						enet_at_atomic_read((char* ) (variable), ENET_ATOMIC_SIZEOF(variable))
#define ENET_ATOMIC_WRITE(variable, new_val)			enet_at_atomic_write((char* ) (variable), (int64_t) (new_val), ENET_ATOMIC_SIZEOF(variable))
#define ENET_ATOMIC_CAS(variable, old_value, new_val)	enet_at_atomic_cas((char* ) (variable), (int64_t) (new_val), (int64_t) (old_value), ENET_ATOMIC_SIZEOF(variable))
#define ENET_ATOMIC_INC(variable)						enet_at_atomic_inc((char* ) (variable), 1, ENET_ATOMIC_SIZEOF(variable))
#define ENET_ATOMIC_DEC(variable)						enet_at_atomic_inc((char* ) (variable), -1, ENET_ATOMIC_SIZEOF(variable))
#define ENET_ATOMIC_INC_BY(variable, delta)             enet_at_atomic_inc((char* ) (variable), (delta), ENET_ATOMIC_SIZEOF(variable))
#define ENET_ATOMIC_DEC_BY(variable, delta)             enet_at_atomic_inc((char* ) (variable), -(delta), ENET_ATOMIC_SIZEOF(variable))

#elif defined(__GNUC__) || defined(__clang__)
#if defined(__clang__) || (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7))
#define AT_HAVE_ATOMICS
#endif

/* We want to use __atomic built-ins if possible because the __sync primitives are
   deprecated, because the __atomic build-ins allow us to use ENET_ATOMIC_WRITE on
   uninitialized memory without running into undefined behavior, and because the
   __atomic versions generate more efficient code since we don't need to rely on
   CAS when we don't actually want it.

   Note that we use acquire-release memory order (like mutexes do). We could use
   sequentially consistent memory order but that has lower performance and is
   almost always unneeded. */
#ifdef AT_HAVE_ATOMICS
#define ENET_ATOMIC_READ(ptr) __atomic_load_n((ptr), __ATOMIC_ACQUIRE)
#define ENET_ATOMIC_WRITE(ptr, value) __atomic_store_n((ptr), (value), __ATOMIC_RELEASE)

#ifndef typeof
#define typeof __typeof__
#endif

/* clang_analyzer doesn't know that CAS writes to memory so it complains about
   potentially lost data. Replace the code with the equivalent non-sync code. */
#ifdef __clang_analyzer__
#define ENET_ATOMIC_CAS(ptr, old_value, new_value)                                                      \
                ({                                                                                                  \
                    typeof(*(ptr)) ENET_ATOMIC_CAS_old_actual_ = (*(ptr));                                          \
                    if (ATOMIC_CAS_old_actual_ == (old_value)) {                                                    \
                        *(ptr) = new_value;                                                                         \
                    }                                                                                               \
                    ENET_ATOMIC_CAS_old_actual_;                                                                    \
                })
#else
/* Could use __auto_type instead of typeof but that shouldn't work in C++.
   The ({ }) syntax is a GCC extension called statement expression. It lets
   us return a value out of the macro.

   TODO We should return bool here instead of the old value to avoid the ABA
   problem. */
#define ENET_ATOMIC_CAS(ptr, old_value, new_value)                                                      \
                ({                                                                                                  \
                    typeof(*(ptr)) ENET_ATOMIC_CAS_expected_ = (old_value);                                         \
                    __atomic_compare_exchange_n((ptr), &ENET_ATOMIC_CAS_expected_, (new_value), false,              \
                                                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);                                \
                    ENET_ATOMIC_CAS_expected_;                                                                      \
                })
#endif

#define ENET_ATOMIC_INC(ptr)							__atomic_fetch_add((ptr), 1, __ATOMIC_ACQ_REL)
#define ENET_ATOMIC_DEC(ptr)							__atomic_fetch_sub((ptr), 1, __ATOMIC_ACQ_REL)
#define ENET_ATOMIC_INC_BY(ptr, delta)					__atomic_fetch_add((ptr), (delta), __ATOMIC_ACQ_REL)
#define ENET_ATOMIC_DEC_BY(ptr, delta)					__atomic_fetch_sub((ptr), (delta), __ATOMIC_ACQ_REL)

#else

#define ENET_ATOMIC_READ(variable)						__sync_fetch_and_add(variable, 0)
#define ENET_ATOMIC_WRITE(variable, new_val)			(void) __sync_val_compare_and_swap((variable), *(variable), (new_val))
#define ENET_ATOMIC_CAS(variable, old_value, new_val)   __sync_val_compare_and_swap((variable), (old_value), (new_val))
#define ENET_ATOMIC_INC(variable)						__sync_fetch_and_add((variable), 1)
#define ENET_ATOMIC_DEC(variable)						__sync_fetch_and_sub((variable), 1)
#define ENET_ATOMIC_INC_BY(variable, delta)				__sync_fetch_and_add((variable), (delta), 1)
#define ENET_ATOMIC_DEC_BY(variable, delta)				__sync_fetch_and_sub((variable), (delta), 1)

#endif
#undef AT_HAVE_ATOMICS
#endif



/**************************************************************************
 * Globals
 **************************************************************************/

ENetVersion enet_linked_version(void) 
{
	return ENET_VERSION;
}



/**************************************************************************
 * Callbacks
 **************************************************************************/

static void* enet_default_malloc(size_t size)
{
    return malloc(size);
}

static void enet_default_free(void* ptr)
{
    free(ptr);
}

static ENetCallbacks enet_callbacks = { enet_default_malloc, enet_default_free, NULL };

int enet_initialize_with_callbacks(const ENetCallbacks* callbacks)
{
    if (callbacks->malloc == NULL || callbacks->free == NULL)
        return -1;

    enet_callbacks.malloc = callbacks->malloc;
    enet_callbacks.free = callbacks->free;
    enet_callbacks.out_of_memory = callbacks->out_of_memory;

	return enet_initialize();
}

void* enet_malloc(size_t size)
{
	void* memory = enet_callbacks.malloc(size);
    if (memory == NULL)
    {
        if (enet_callbacks.out_of_memory)
            enet_callbacks.out_of_memory(size);
    }

	return memory;
}

void enet_free(void* memory) 
{
    enet_callbacks.free(memory);
}



/**************************************************************************
 * List
 **************************************************************************/

void enet_list_clear(ENetList* list)
{
	list->sentinel.next = &list->sentinel;
	list->sentinel.previous = &list->sentinel;
}

ENetListIterator enet_list_insert(ENetListIterator position, void* data)
{
	ENetListIterator result = (ENetListIterator)data;

	result->previous = position->previous;
	result->next = position;

	result->previous->next = result;
	position->previous = result;

	return result;
}

void* enet_list_remove(ENetListIterator position)
{
	position->previous->next = position->next;
	position->next->previous = position->previous;

	return position;
}

ENetListIterator enet_list_move(ENetListIterator position, void* dataFirst, void* dataLast)
{
	ENetListIterator first = (ENetListIterator)dataFirst;
	ENetListIterator last = (ENetListIterator)dataLast;

	first->previous->next = last->next;
	last->next->previous = first->previous;

	first->previous = position->previous;
	last->next = position;

	first->previous->next = first;
	position->previous = last;

	return first;
}

size_t enet_list_size(ENetList* list)
{
	size_t size = 0;
	for (ENetListIterator position = enet_list_begin(list); position != enet_list_end(list); position = enet_list_next(position))
		size++;

	return size;
}



/**************************************************************************
 * Packet
 **************************************************************************/

ENetPacket* enet_packet_create(const void* data, size_t dataLength, enet_uint16 flags)
{
	ENetPacket* packet;

	if (flags & ENET_PACKET_FLAG_NO_ALLOCATE) 
	{
		if ((packet = (ENetPacket*)enet_malloc(sizeof(ENetPacket))) == NULL)
			return NULL;

		packet->data = (enet_uint8*)data;
	}
	else 
	{
        if ((packet = (ENetPacket*)enet_malloc(sizeof(ENetPacket) + dataLength)) == NULL)
			return NULL;

		packet->data = (enet_uint8*)packet + sizeof(ENetPacket);

		if (data != NULL)
			memcpy(packet->data, data, dataLength);
		else
			memset(packet->data, 0, dataLength);
	}

	packet->referenceCount = 0;
	packet->flags = flags;
	packet->dataLength = dataLength;
	packet->freeCallback = NULL;
	packet->userData = NULL;

	return packet;
}

ENetPacket* enet_packet_create_offset(const void* data, size_t dataLength, size_t dataOffset, enet_uint16 flags)
{
	ENetPacket* packet;

	if (flags & ENET_PACKET_FLAG_NO_ALLOCATE) 
	{
        if ((packet = (ENetPacket*)enet_malloc(sizeof(ENetPacket))) == NULL)
			return NULL;

		packet->data = (enet_uint8*)data;
	}
	else 
	{
		if ((packet = (ENetPacket*)enet_malloc(sizeof(ENetPacket) + dataLength + dataOffset)) == NULL)
			return NULL;

		packet->data = (enet_uint8*)packet + sizeof(ENetPacket);

		if (data != NULL)
			memcpy(packet->data + dataOffset, data, dataLength);
		else 
			memset(packet->data + dataOffset, 0, dataLength);
	}

	packet->referenceCount = 0;
	packet->flags = flags;
	packet->dataLength = dataLength + dataOffset;
	packet->freeCallback = NULL;
	packet->userData = NULL;

	return packet;
}

void enet_packet_destroy(ENetPacket* packet)
{
	if (packet == NULL)
		return;

	if (packet->freeCallback != NULL)
		(*packet->freeCallback) ((void*)packet);

	enet_free(packet);
}

static int initializedCRC32 = 0;
static enet_uint32 crcTable[256];

static enet_uint32 reflect_crc(int val, int bits)
{
	int result = 0;

	for (int bit = 0; bit < bits; bit++)
	{
		if (val & 1)
			result |= 1 << (bits - 1 - bit);

		val >>= 1;
	}

	return result;
}

static void initialize_crc32(void)
{
	for (int byte = 0; byte < 256; ++byte)
	{
		enet_uint32 crc = reflect_crc(byte, 8) << 24;
		for (int offset = 0; offset < 8; ++offset)
		{
			if (crc & 0x80000000)
				crc = (crc << 1) ^ 0x04c11db7;
			else
				crc <<= 1;
		}

		crcTable[byte] = reflect_crc(crc, 32);
	}

	initializedCRC32 = 1;
}

enet_uint32 enet_crc32(const ENetBuffer* buffers, size_t bufferCount)
{
	enet_uint32 crc = 0xFFFFFFFF;

	if (!initializedCRC32)
		initialize_crc32();

	while (bufferCount-- > 0)
	{
		const enet_uint8* data = (const enet_uint8*)buffers->data;
		const enet_uint8* dataEnd = &data[buffers->dataLength];

		while (data < dataEnd)
			crc = (crc >> 8) ^ crcTable[(crc & 0xFF) ^ *data++];

		++buffers;
	}

	return ENET_HOST_TO_NET_32(~crc);
}



/**************************************************************************
 * Protocol
 **************************************************************************/

static size_t commandSizes[ENET_PROTOCOL_COMMAND_COUNT] = {
	0,
	sizeof(ENetProtocolAcknowledge),
	sizeof(ENetProtocolConnect),
	sizeof(ENetProtocolAccept),
	sizeof(ENetProtocolDisconnect),
	sizeof(ENetProtocolPing),
	sizeof(ENetProtocolSendReliable),
	sizeof(ENetProtocolSendUnreliable),
	sizeof(ENetProtocolSendFragment),
	sizeof(ENetProtocolSendUnsequenced),
	sizeof(ENetProtocolBandwidthLimit),
	sizeof(ENetProtocolThrottleConfigure),
	sizeof(ENetProtocolSendFragment),
    0,
    0,
    0
};

size_t enet_protocol_command_size(enet_uint8 commandNumber)
{
	return commandSizes[commandNumber & ENET_PROTOCOL_COMMAND_MASK];
}

static void enet_protocol_change_state(ENetPeer* peer, const ENetPeerState state)
{
	if (state == ENET_PEER_STATE_CONNECTED || state == ENET_PEER_STATE_DISCONNECT_LATER)
		enet_peer_on_connect(peer);
	else
		enet_peer_on_disconnect(peer);

	peer->state = state;
}

static void enet_protocol_dispatch_state(ENetHost* host, ENetPeer* peer, const ENetPeerState state)
{
	enet_protocol_change_state(peer, state);

	if (!peer->needsDispatch)
	{
		enet_list_insert(enet_list_end(&host->dispatchQueue), &peer->dispatchList);
		peer->needsDispatch = 1;
	}
}

static int enet_protocol_dispatch_incoming_commands(ENetHost* host, ENetEvent* event)
{
	while (!enet_list_empty(&host->dispatchQueue))
	{
		ENetPeer* peer = (ENetPeer*)enet_list_remove(enet_list_begin(&host->dispatchQueue));
		peer->needsDispatch = 0;

		switch (peer->state)
		{
		case ENET_PEER_STATE_CONNECTION_PENDING:
		case ENET_PEER_STATE_CONNECTION_SUCCEEDED:
			enet_protocol_change_state(peer, ENET_PEER_STATE_CONNECTED);

			event->type = ENET_EVENT_TYPE_CONNECT;
			event->peer = peer;
			event->status = peer->eventStatus;
			return 1;

		case ENET_PEER_STATE_ZOMBIE:
			host->recalculateBandwidthLimits = 1;

			event->type = ENET_EVENT_TYPE_DISCONNECT;
			event->peer = peer;
			event->status = peer->eventStatus;

			enet_peer_reset(peer);
			return 1;

		case ENET_PEER_STATE_CONNECTED:
			if (enet_list_empty(&peer->dispatchedCommands))
				continue;

			event->packet = enet_peer_receive(peer, &event->channelId);

			if (event->packet == NULL)
				continue;

			event->type = ENET_EVENT_TYPE_RECEIVE;
			event->peer = peer;

			if (!enet_list_empty(&peer->dispatchedCommands))
			{
				peer->needsDispatch = 1;
				enet_list_insert(enet_list_end(&host->dispatchQueue), &peer->dispatchList);
			}
			return 1;

		default:
			break;
		}
	}

	return 0;
}

static void enet_protocol_notify_connect(ENetHost* host, ENetPeer* peer, ENetEvent* event)
{
	host->recalculateBandwidthLimits = 1;

	if (event != NULL) 
	{
		enet_protocol_change_state(peer, ENET_PEER_STATE_CONNECTED);

		peer->totalDataSent = 0;
		peer->totalDataReceived = 0;
		peer->totalPacketsSent = 0;
		peer->totalPacketsLost = 0;
		event->type = ENET_EVENT_TYPE_CONNECT;
		event->peer = peer;
		event->status = peer->eventStatus;
	}
	else 
	{
		enet_protocol_dispatch_state(host, peer, peer->state == ENET_PEER_STATE_CONNECTING ? ENET_PEER_STATE_CONNECTION_SUCCEEDED : ENET_PEER_STATE_CONNECTION_PENDING);
	}
}

static void enet_protocol_notify_disconnect(ENetHost* host, ENetPeer* peer, ENetEvent* event)
{
	if (peer->state >= ENET_PEER_STATE_CONNECTION_PENDING)
		host->recalculateBandwidthLimits = 1;

	if (peer->state != ENET_PEER_STATE_CONNECTING && peer->state < ENET_PEER_STATE_CONNECTION_SUCCEEDED)
	{
		enet_peer_reset(peer);
	}
	else if (event != NULL) 
	{
		event->type = ENET_EVENT_TYPE_DISCONNECT;
		event->peer = peer;
		event->status = 0;

		enet_peer_reset(peer);
	}
	else 
	{
		peer->eventStatus = 0;
		enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);
	}
}

static void enet_protocol_notify_disconnect_timeout(ENetHost*  host, ENetPeer*  peer, ENetEvent*  event)
{
	if (peer->state >= ENET_PEER_STATE_CONNECTION_PENDING)
		host->recalculateBandwidthLimits = 1;

	if (peer->state != ENET_PEER_STATE_CONNECTING && peer->state < ENET_PEER_STATE_CONNECTION_SUCCEEDED) 
	{
		enet_peer_reset(peer);
	}
	else if (event != NULL) 
	{
		event->type = ENET_EVENT_TYPE_TIMEOUT;
		event->peer = peer;
		event->status = 0;

		enet_peer_reset(peer);
	}
	else 
	{
		peer->eventStatus = 0;
		enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);
	}
}

static void enet_protocol_remove_sent_unreliable_commands(ENetPeer* peer)
{
	ENetOutgoingCommand* outgoingCommand;

	while (!enet_list_empty(&peer->sentUnreliableCommands)) 
	{
		outgoingCommand = (ENetOutgoingCommand*)enet_list_front(&peer->sentUnreliableCommands);
		enet_list_remove(&outgoingCommand->outgoingCommandList);

		if (outgoingCommand->packet != NULL) 
		{
			--outgoingCommand->packet->referenceCount;

			if (outgoingCommand->packet->referenceCount == 0) {
				outgoingCommand->packet->flags |= ENET_PACKET_FLAG_SENT;
				enet_packet_destroy(outgoingCommand->packet);
			}
		}

		enet_free(outgoingCommand);
	}
}

static enet_uint8 enet_protocol_remove_sent_reliable_command(ENetPeer* peer, enet_uint16 reliableSequenceNumber, enet_uint8 channelId)
{
	ENetOutgoingCommand* outgoingCommand = NULL;

	bool wasSent = true;
	ENetListIterator currentCommand;
	for (currentCommand = enet_list_begin(&peer->sentReliableCommands); currentCommand != enet_list_end(&peer->sentReliableCommands); currentCommand = enet_list_next(currentCommand)) 
	{
		outgoingCommand = (ENetOutgoingCommand*)currentCommand;

		if (outgoingCommand->reliableSequenceNumber == reliableSequenceNumber && outgoingCommand->command.header.channelId == channelId) {
			break;
		}
	}

	if (currentCommand == enet_list_end(&peer->sentReliableCommands)) 
	{
		for (currentCommand = enet_list_begin(&peer->outgoingReliableCommands); currentCommand != enet_list_end(&peer->outgoingReliableCommands); currentCommand = enet_list_next(currentCommand)) 
		{
			outgoingCommand = (ENetOutgoingCommand*)currentCommand;

			if (outgoingCommand->sendAttempts < 1)
				return ENET_PROTOCOL_COMMAND_NONE;

			if (outgoingCommand->reliableSequenceNumber == reliableSequenceNumber && outgoingCommand->command.header.channelId == channelId)
				break;
		}

		if (currentCommand == enet_list_end(&peer->outgoingReliableCommands))
			return ENET_PROTOCOL_COMMAND_NONE;

		wasSent = false;
	}

	if (outgoingCommand == NULL)
		return ENET_PROTOCOL_COMMAND_NONE;

	if (channelId < peer->channelCount)
	{
		ENetChannel* channel = &peer->channels[channelId];
		enet_uint16 reliableWindow = reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

		if (channel->reliableWindows[reliableWindow] > 0)
		{
			--channel->reliableWindows[reliableWindow];

			if (!channel->reliableWindows[reliableWindow])
                channel->usedReliableWindows &= ~(1 << reliableWindow);
		}
	}

    enet_uint8 commandNumber = outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK;

	enet_list_remove(&outgoingCommand->outgoingCommandList);

	if (outgoingCommand->packet != NULL)
	{
		if (wasSent)
			peer->reliableDataInTransit -= outgoingCommand->fragmentLength;

		--outgoingCommand->packet->referenceCount;

		if (outgoingCommand->packet->referenceCount == 0) 
		{
			outgoingCommand->packet->flags |= ENET_PACKET_FLAG_SENT;
			enet_packet_destroy(outgoingCommand->packet);
		}
	}

	enet_free(outgoingCommand);

	if (enet_list_empty(&peer->sentReliableCommands))
		return commandNumber;

	outgoingCommand = (ENetOutgoingCommand*)enet_list_front(&peer->sentReliableCommands);
	peer->nextTimeout = outgoingCommand->sentTime + outgoingCommand->roundTripTimeout;

	return commandNumber;
}



static ENetPeer*  enet_protocol_handle_connect(ENetHost* host, ENetProtocol* command)
{
    enet_uint16 channelCount = ENET_NET_TO_HOST_16(command->connect.channelCount);
	if (channelCount < ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT || channelCount > ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
		return NULL;

	ENetPeer* peer = NULL;
	enet_uint16 duplicatePeers = 0;
	for (ENetPeer* currentPeer = host->peers; duplicatePeers < host->duplicatePeers && currentPeer < &host->peers[host->peerCount]; ++currentPeer)
	{
		if (currentPeer->state == ENET_PEER_STATE_DISCONNECTED) 
		{
			if (peer == NULL)
				peer = currentPeer;
		}
		else if (currentPeer->state != ENET_PEER_STATE_CONNECTING && in6_equal(currentPeer->address.host, host->receivedAddress.host)) 
		{
			if (currentPeer->address.port == host->receivedAddress.port && currentPeer->connectId == command->connect.connectId)
				return NULL;

			++duplicatePeers;
		}
	}

	if (peer == NULL || duplicatePeers >= host->duplicatePeers)
		return NULL;

	if (channelCount > host->channelLimit)
		channelCount = host->channelLimit;

	peer->channels = (ENetChannel*)enet_malloc(channelCount * sizeof(ENetChannel));
	if (peer->channels == NULL)
		return NULL;

	peer->channelCount = channelCount;
	peer->state = ENET_PEER_STATE_ACKNOWLEDGING_CONNECT;
	peer->connectId = command->connect.connectId;
	peer->address = host->receivedAddress;
	peer->outgoingPeerId = ENET_NET_TO_HOST_16(command->connect.outgoingPeerId);
	peer->incomingBandwidth = ENET_NET_TO_HOST_32(command->connect.incomingBandwidth);
	peer->outgoingBandwidth = ENET_NET_TO_HOST_32(command->connect.outgoingBandwidth);
	peer->packetThrottleInterval = ENET_NET_TO_HOST_32(command->connect.packetThrottleInterval);
	peer->packetThrottleAcceleration = ENET_NET_TO_HOST_32(command->connect.packetThrottleAcceleration);
	peer->packetThrottleDeceleration = ENET_NET_TO_HOST_32(command->connect.packetThrottleDeceleration);
	peer->eventStatus = ENET_NET_TO_HOST_32(command->connect.status);

	enet_uint8 incomingSession = command->connect.incomingSessionId == 0xFF ? peer->outgoingSessionId : command->connect.incomingSessionId;
    incomingSession = (incomingSession + 1) & ENET_PROTOCOL_HEADER_SESSION;

	if (incomingSession == peer->outgoingSessionId)
        incomingSession = (incomingSession + 1) & ENET_PROTOCOL_HEADER_SESSION;

	peer->outgoingSessionId = incomingSession;

	enet_uint8 outgoingSession = command->connect.outgoingSessionId == 0xFF ? peer->incomingSessionId : command->connect.outgoingSessionId;
    outgoingSession = (outgoingSession + 1) & ENET_PROTOCOL_HEADER_SESSION;

	if (outgoingSession == peer->incomingSessionId)
        outgoingSession = (outgoingSession + 1) & ENET_PROTOCOL_HEADER_SESSION;

	peer->incomingSessionId = outgoingSession;

	for (ENetChannel* channel = peer->channels; channel < &peer->channels[channelCount]; ++channel)
	{ 
        channel->outgoingReliableSequenceNumber = 0;
        channel->outgoingUnreliableSequenceNumber = 0;
        channel->incomingReliableSequenceNumber = 0;
        channel->incomingUnreliableSequenceNumber = 0;

		enet_list_clear(&channel->incomingReliableCommands);
		enet_list_clear(&channel->incomingUnreliableCommands);

        channel->usedReliableWindows = 0;
		memset(channel->reliableWindows, 0, sizeof(channel->reliableWindows));
	}

	enet_uint16 mtu = ENET_NET_TO_HOST_16(command->connect.mtu);

	if (mtu < ENET_PROTOCOL_MINIMUM_MTU)
		mtu = ENET_PROTOCOL_MINIMUM_MTU;
	else if (mtu > ENET_PROTOCOL_MAXIMUM_MTU)
		mtu = ENET_PROTOCOL_MAXIMUM_MTU;

	peer->mtu = mtu;

	if (host->outgoingBandwidth == 0 && peer->incomingBandwidth == 0)
		peer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;
	else if (host->outgoingBandwidth == 0 || peer->incomingBandwidth == 0) 
		peer->windowSize = (ENET_MAX(host->outgoingBandwidth, peer->incomingBandwidth) / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
	else 
		peer->windowSize = (ENET_MIN(host->outgoingBandwidth, peer->incomingBandwidth) / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;

	if (peer->windowSize < ENET_PROTOCOL_MINIMUM_WINDOW_SIZE) 
		peer->windowSize = ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
	else if (peer->windowSize > ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE) 
		peer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;

	enet_uint32 windowSize;
	if (host->incomingBandwidth == 0) 
		windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;
	else 
		windowSize = (host->incomingBandwidth / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;

	if (windowSize > ENET_NET_TO_HOST_32(command->connect.windowSize))
		windowSize = ENET_NET_TO_HOST_32(command->connect.windowSize);

	if (windowSize < ENET_PROTOCOL_MINIMUM_WINDOW_SIZE) 
		windowSize = ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
	else if (windowSize > ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE) 
		windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;

	ENetProtocol reply;
	reply.header.command = ENET_PROTOCOL_COMMAND_ACCEPT | ENET_PROTOCOL_COMMAND_FLAG_ACK;
	reply.header.channelId = 0xFF;

	reply.accept.outgoingPeerId = ENET_HOST_TO_NET_16(peer->incomingPeerId);
	reply.accept.incomingSessionId = incomingSession;
	reply.accept.outgoingSessionId = outgoingSession;
	reply.accept.mtu = ENET_HOST_TO_NET_16(peer->mtu);
	reply.accept.windowSize = ENET_HOST_TO_NET_32(windowSize);
	reply.accept.channelCount = ENET_HOST_TO_NET_16(channelCount);
	reply.accept.incomingBandwidth = ENET_HOST_TO_NET_32(host->incomingBandwidth);
	reply.accept.outgoingBandwidth = ENET_HOST_TO_NET_32(host->outgoingBandwidth);
	reply.accept.packetThrottleInterval = ENET_HOST_TO_NET_32(peer->packetThrottleInterval);
	reply.accept.packetThrottleAcceleration = ENET_HOST_TO_NET_32(peer->packetThrottleAcceleration);
	reply.accept.packetThrottleDeceleration = ENET_HOST_TO_NET_32(peer->packetThrottleDeceleration);
	reply.accept.connectId = peer->connectId;

	enet_peer_queue_outgoing_command(peer, &reply, NULL, 0, 0);

	return peer;
}

static int enet_protocol_handle_reliable_packet(ENetHost* host, ENetPeer* peer, const ENetProtocol* command, enet_uint8** currentData) 
{
	if (command->header.channelId >= peer->channelCount || (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER))
		return -1;

	enet_uint16 dataLength = ENET_NET_TO_HOST_16(command->sendReliable.dataLength);
	*currentData += dataLength;

	if (dataLength > host->maximumPacketSize || *currentData < host->receivedData || *currentData > &host->receivedData[host->receivedDataLength])
		return -1;

	if (enet_peer_queue_incoming_command(peer, command, (const enet_uint8*)command + sizeof(ENetProtocolSendReliable), dataLength, ENET_PACKET_FLAG_RELIABLE, 0) == NULL)
		return -1;

	return 0;
}

static int enet_protocol_handle_unreliable_packet(ENetHost* host, ENetPeer* peer, const ENetProtocol* command, enet_uint8** currentData) 
{
	if (command->header.channelId >= peer->channelCount || (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER))
		return -1;

	enet_uint16 dataLength = ENET_NET_TO_HOST_16(command->sendUnreliable.dataLength);
	*currentData += dataLength;

	if (dataLength > host->maximumPacketSize || *currentData < host->receivedData || *currentData > &host->receivedData[host->receivedDataLength])
		return -1;

	if (enet_peer_queue_incoming_command(peer, command, (const enet_uint8*)command + sizeof(ENetProtocolSendUnreliable), dataLength, 0, 0) == NULL)
		return -1;

	return 0;
}

static int enet_protocol_handle_out_of_band_packet(ENetHost* host, ENetPeer* peer, const ENetProtocol* command, enet_uint8** currentData)
{
    if (command->header.channelId >= peer->channelCount || (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER))
        return -1;

    enet_uint16 dataLength = ENET_NET_TO_HOST_16(command->sendUnsequenced.dataLength);
    *currentData += dataLength;

    if (dataLength > host->maximumPacketSize || *currentData < host->receivedData || *currentData > &host->receivedData[host->receivedDataLength])
        return -1;

    enet_uint32 unsequencedGroup = ENET_NET_TO_HOST_16(command->sendUnsequenced.unsequencedGroup);
    enet_uint16 index = unsequencedGroup % ENET_PEER_UNSEQUENCED_WINDOW_SIZE;

    if (unsequencedGroup < peer->incomingUnsequencedGroup)
        unsequencedGroup += 0x10000;

    if (unsequencedGroup >= (enet_uint32)peer->incomingUnsequencedGroup + (ENET_PEER_FREE_UNSEQUENCED_WINDOWS * ENET_PEER_UNSEQUENCED_WINDOW_SIZE))
        return 0;

    unsequencedGroup &= 0xFFFF;
    const enet_uint16 incomingUnsequencedGroup = (enet_uint16)(unsequencedGroup)-index;
    if (incomingUnsequencedGroup != peer->incomingUnsequencedGroup)
    {
        peer->incomingUnsequencedGroup = incomingUnsequencedGroup;
        memset(peer->unsequencedWindow, 0, sizeof(peer->unsequencedWindow));
    }
    else if (peer->unsequencedWindow[index / 32] & (1 << (index % 32)))
    {
        return 0;
    }

    if (enet_peer_queue_incoming_command(peer, command, (const enet_uint8*)command + sizeof(ENetProtocolSendUnsequenced), dataLength, ENET_PACKET_FLAG_UNSEQUENCED, 0) == NULL)
        return -1;

    peer->unsequencedWindow[index / 32] |= 1 << (index % 32);

    return 0;
}

static int enet_protocol_handle_reliable_fragment(ENetHost* host, ENetPeer* peer, const ENetProtocol* command, enet_uint8** currentData)
{
	if (command->header.channelId >= peer->channelCount || (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER))
		return -1;

	enet_uint16 fragmentLength = ENET_NET_TO_HOST_16(command->sendFragment.dataLength);
	*currentData += fragmentLength;

	if (fragmentLength > host->maximumPacketSize || *currentData < host->receivedData || *currentData > &host->receivedData[host->receivedDataLength])
		return -1;

	ENetChannel* channel = &peer->channels[command->header.channelId];
	enet_uint16 startSequenceNumber = ENET_NET_TO_HOST_16(command->sendFragment.startSequenceNumber);
	enet_uint16 startWindow = startSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
	enet_uint16 currentWindow = channel->incomingReliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

	if (startSequenceNumber < channel->incomingReliableSequenceNumber)
		startWindow += ENET_PEER_RELIABLE_WINDOWS;

	if (startWindow < currentWindow || startWindow >= currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS - 1)
		return 0;

	enet_uint32 fragmentNumber = ENET_NET_TO_HOST_16(command->sendFragment.fragmentNumber);
	enet_uint16 fragmentCount = ENET_NET_TO_HOST_16(command->sendFragment.fragmentCount);
	enet_uint32 fragmentOffset = ENET_NET_TO_HOST_32(command->sendFragment.fragmentOffset);
	enet_uint32 totalLength = ENET_NET_TO_HOST_32(command->sendFragment.totalLength);

	if (fragmentCount > ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT 
	 || fragmentNumber >= fragmentCount 
	 || totalLength > host->maximumPacketSize 
	 || fragmentOffset >= totalLength 
	 || fragmentLength > (totalLength - fragmentOffset)) 
	{
		return -1;
	}

	ENetIncomingCommand* startCommand = NULL;
	for (ENetListIterator currentCommand = enet_list_previous(enet_list_end(&channel->incomingReliableCommands)); currentCommand != enet_list_end(&channel->incomingReliableCommands); currentCommand = enet_list_previous(currentCommand))
	{
		ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)currentCommand;

		if (startSequenceNumber >= channel->incomingReliableSequenceNumber)
		{
			if (incomingCommand->reliableSequenceNumber < channel->incomingReliableSequenceNumber)
				continue;
		}
		else if (incomingCommand->reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
		{
			break;
		}

		if (incomingCommand->reliableSequenceNumber <= startSequenceNumber) 
		{
			if (incomingCommand->reliableSequenceNumber < startSequenceNumber)
				break;

			if ((incomingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK) != ENET_PROTOCOL_COMMAND_SEND_RELIABLE_FRAGMENT 
				|| totalLength != incomingCommand->packet->dataLength 
				|| fragmentCount != incomingCommand->fragmentCount)
			{
				return -1;
			}

			startCommand = incomingCommand;

			break;
		}
	}

	if (startCommand == NULL) 
	{
		ENetProtocol hostCommand = *command;
		hostCommand.header.reliableSequenceNumber = startSequenceNumber;
		startCommand = enet_peer_queue_incoming_command(peer, &hostCommand, NULL, totalLength, ENET_PACKET_FLAG_RELIABLE, fragmentCount);

		if (startCommand == NULL)
			return -1;
	}

	if ((startCommand->fragments[fragmentNumber / 32] & (1 << (fragmentNumber % 32))) == 0) 
	{
		--startCommand->fragmentsRemaining;
		startCommand->fragments[fragmentNumber / 32] |= (1 << (fragmentNumber % 32));

		if (fragmentOffset + fragmentLength > startCommand->packet->dataLength)
			fragmentLength = (enet_uint16)(startCommand->packet->dataLength - fragmentOffset);

		memcpy(startCommand->packet->data + fragmentOffset, (enet_uint8*)command + sizeof(ENetProtocolSendFragment), fragmentLength);

		if (startCommand->fragmentsRemaining <= 0)
			enet_peer_dispatch_incoming_reliable_commands(peer, channel);
	}

	return 0;
}

static int enet_protocol_handle_unreliable_fragment(ENetHost* host, ENetPeer* peer, const ENetProtocol* command, enet_uint8** currentData) 
{
	if (command->header.channelId >= peer->channelCount || (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER))
		return -1;

	enet_uint16 fragmentLength = ENET_NET_TO_HOST_16(command->sendFragment.dataLength);
	*currentData += fragmentLength;

	if (fragmentLength > host->maximumPacketSize || *currentData < host->receivedData || *currentData > &host->receivedData[host->receivedDataLength])
		return -1;

	ENetChannel* channel = &peer->channels[command->header.channelId];
	enet_uint16 reliableSequenceNumber = command->header.reliableSequenceNumber;
	enet_uint16 startSequenceNumber = ENET_NET_TO_HOST_16(command->sendFragment.startSequenceNumber);

	enet_uint16 reliableWindow = reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
	enet_uint16 currentWindow = channel->incomingReliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

	if (reliableSequenceNumber < channel->incomingReliableSequenceNumber)
		reliableWindow += ENET_PEER_RELIABLE_WINDOWS;

	if (reliableWindow < currentWindow || reliableWindow >= currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS - 1)
		return 0;

	if (reliableSequenceNumber == channel->incomingReliableSequenceNumber && startSequenceNumber <= channel->incomingUnreliableSequenceNumber)
		return 0;

	enet_uint16 fragmentNumber = ENET_NET_TO_HOST_16(command->sendFragment.fragmentNumber);
	enet_uint16 fragmentCount = ENET_NET_TO_HOST_16(command->sendFragment.fragmentCount);
	enet_uint32 fragmentOffset = ENET_NET_TO_HOST_32(command->sendFragment.fragmentOffset);
	enet_uint32 totalLength = ENET_NET_TO_HOST_32(command->sendFragment.totalLength);

	if (fragmentCount > ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT 
	 || fragmentNumber >= fragmentCount 
	 || totalLength > host->maximumPacketSize 
	 || fragmentOffset >= totalLength 
	 || fragmentLength > totalLength - fragmentOffset) 
	{
		return -1;
	}

	ENetIncomingCommand* startCommand = NULL;
	for (ENetListIterator currentCommand = enet_list_previous(enet_list_end(&channel->incomingUnreliableCommands)); currentCommand != enet_list_end(&channel->incomingUnreliableCommands); currentCommand = enet_list_previous(currentCommand))
	{
		ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)currentCommand;

		if (reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
		{
			if (incomingCommand->reliableSequenceNumber < channel->incomingReliableSequenceNumber)
				continue;
		}
		else if (incomingCommand->reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
		{
			break;
		}

		if (incomingCommand->reliableSequenceNumber < reliableSequenceNumber)
			break;

		if (incomingCommand->reliableSequenceNumber > reliableSequenceNumber)
			continue;

		if (incomingCommand->unreliableSequenceNumber <= startSequenceNumber) 
		{
			if (incomingCommand->unreliableSequenceNumber < startSequenceNumber)
				break;

			if ((incomingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK) != ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT 
				|| totalLength != incomingCommand->packet->dataLength 
				|| fragmentCount != incomingCommand->fragmentCount) 
			{
				return -1;
			}

			startCommand = incomingCommand;

			break;
		}
	}

	if (startCommand == NULL) 
	{
		startCommand = enet_peer_queue_incoming_command(peer, command, NULL, totalLength, ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT, fragmentCount);
		if (startCommand == NULL) 
			return -1;
	}

	if ((startCommand->fragments[fragmentNumber / 32] & (1 << (fragmentNumber % 32))) == 0) 
	{
		--startCommand->fragmentsRemaining;
		startCommand->fragments[fragmentNumber / 32] |= (1 << (fragmentNumber % 32));

		if (fragmentOffset + fragmentLength > startCommand->packet->dataLength)
			fragmentLength = (enet_uint16)(startCommand->packet->dataLength - fragmentOffset);

		memcpy(startCommand->packet->data + fragmentOffset, (enet_uint8*)command + sizeof(ENetProtocolSendFragment), fragmentLength);

		if (startCommand->fragmentsRemaining <= 0)
			enet_peer_dispatch_incoming_unreliable_commands(peer, channel);
	}

	return 0;
}

static int enet_protocol_handle_ping(ENetPeer* peer) 
{
	if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER)
		return -1;

	return 0;
}

static int enet_protocol_handle_bandwidth_limit(ENetHost* host, ENetPeer* peer, const ENetProtocol* command) 
{
	if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER)
		return -1;

	if (peer->incomingBandwidth != 0)
		--host->bandwidthLimitedPeers;

	peer->incomingBandwidth = ENET_NET_TO_HOST_32(command->bandwidthLimit.incomingBandwidth);
	peer->outgoingBandwidth = ENET_NET_TO_HOST_32(command->bandwidthLimit.outgoingBandwidth);

	if (peer->incomingBandwidth != 0)
		++host->bandwidthLimitedPeers;

	if (peer->incomingBandwidth == 0 && host->outgoingBandwidth == 0)
		peer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;
	else if (peer->incomingBandwidth == 0 || host->outgoingBandwidth == 0)
		peer->windowSize = (ENET_MAX(peer->incomingBandwidth, host->outgoingBandwidth) / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
	else
		peer->windowSize = (ENET_MIN(peer->incomingBandwidth, host->outgoingBandwidth) / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;

	if (peer->windowSize < ENET_PROTOCOL_MINIMUM_WINDOW_SIZE)
		peer->windowSize = ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
	else if (peer->windowSize > ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE)
		peer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;

	return 0;
}

static int enet_protocol_handle_throttle_configure(ENetPeer* peer, const ENetProtocol* command)
{
	if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER)
		return -1;

	peer->packetThrottleInterval = ENET_NET_TO_HOST_32(command->throttleConfigure.packetThrottleInterval);
	peer->packetThrottleAcceleration = ENET_NET_TO_HOST_32(command->throttleConfigure.packetThrottleAcceleration);
	peer->packetThrottleDeceleration = ENET_NET_TO_HOST_32(command->throttleConfigure.packetThrottleDeceleration);

	return 0;
}

static int enet_protocol_handle_disconnect(ENetHost* host, ENetPeer* peer, const ENetProtocol* command)
{
	if (peer->state == ENET_PEER_STATE_DISCONNECTED 
	 || peer->state == ENET_PEER_STATE_ZOMBIE 
	 || peer->state == ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT) 
	{
		return 0;
	}

	enet_peer_reset_queues(peer);

	if (peer->state == ENET_PEER_STATE_CONNECTION_SUCCEEDED || peer->state == ENET_PEER_STATE_DISCONNECTING || peer->state == ENET_PEER_STATE_CONNECTING)
	{
		enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);
	}
	else if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER) 
	{
		if (peer->state == ENET_PEER_STATE_CONNECTION_PENDING)
			host->recalculateBandwidthLimits = 1;

		enet_peer_reset(peer);
	}
	else if (command->header.command & ENET_PROTOCOL_COMMAND_FLAG_ACK) 
	{
		enet_protocol_change_state(peer, ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT);
	}
	else 
	{
		enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);
	}

	if (peer->state != ENET_PEER_STATE_DISCONNECTED)
		peer->eventStatus = ENET_NET_TO_HOST_32(command->disconnect.status);

	return 0;
}

static int enet_protocol_handle_acknowledge(ENetHost* host, ENetEvent* event, ENetPeer* peer, const ENetProtocol* command)
{
	if (peer->state == ENET_PEER_STATE_DISCONNECTED || peer->state == ENET_PEER_STATE_ZOMBIE)
		return 0;

	enet_uint32 receivedSentTime = ENET_NET_TO_HOST_16(command->acknowledge.receivedSentTime);
	receivedSentTime |= host->serviceTime & 0xFFFF0000;

	if ((receivedSentTime & 0x8000) > (host->serviceTime & 0x8000))
		receivedSentTime -= 0x10000;

	if (ENET_TIME_LESS(host->serviceTime, receivedSentTime))
		return 0;

	peer->lastReceiveTime = host->serviceTime;
	peer->earliestTimeout = 0;
	enet_uint32 roundTripTime = ENET_TIME_DIFFERENCE(host->serviceTime, receivedSentTime);

	if (peer->smoothedRoundTripTime == 0) 
	{
		peer->smoothedRoundTripTime = (enet_uint32)((1 - ENET_SRTT_PARA_G) * ENET_SRTT_INITIAL + ENET_SRTT_PARA_G * roundTripTime);
	}
	else 
	{
		peer->smoothedRoundTripTime = (enet_uint32)((1 - ENET_SRTT_PARA_G) * peer->smoothedRoundTripTime + ENET_SRTT_PARA_G * roundTripTime);
	}

	enet_peer_throttle(peer, peer->smoothedRoundTripTime);

	peer->roundTripTimeVariance -= peer->roundTripTimeVariance / 4;

	if (peer->smoothedRoundTripTime >= peer->roundTripTime) 
	{
		peer->roundTripTime += (peer->smoothedRoundTripTime - peer->roundTripTime) / 8;
		peer->roundTripTimeVariance += (peer->smoothedRoundTripTime - peer->roundTripTime) / 4;
	}
	else 
	{
		peer->roundTripTime -= (peer->roundTripTime - peer->smoothedRoundTripTime) / 8;
		peer->roundTripTimeVariance += (peer->roundTripTime - peer->smoothedRoundTripTime) / 4;
	}

	if (peer->roundTripTime < peer->lowestRoundTripTime) 
	{
		peer->lowestRoundTripTime = peer->roundTripTime;
	}

	if (peer->roundTripTimeVariance > peer->highestRoundTripTimeVariance) 
	{
		peer->highestRoundTripTimeVariance = peer->roundTripTimeVariance;
	}

	if (peer->packetThrottleEpoch == 0 
		|| ENET_TIME_DIFFERENCE(host->serviceTime, peer->packetThrottleEpoch) >= peer->packetThrottleInterval) 
	{
		peer->lastRoundTripTime = peer->lowestRoundTripTime;
		peer->lastRoundTripTimeVariance = peer->highestRoundTripTimeVariance;
		peer->lowestRoundTripTime = peer->roundTripTime;
		peer->highestRoundTripTimeVariance = peer->roundTripTimeVariance;
		peer->packetThrottleEpoch = host->serviceTime;
	}

	enet_uint16 receivedReliableSequenceNumber = ENET_NET_TO_HOST_16(command->acknowledge.receivedReliableSequenceNumber);
    enet_uint8 commandNumber = enet_protocol_remove_sent_reliable_command(peer, receivedReliableSequenceNumber, command->header.channelId);

	switch (peer->state)
	{
	case ENET_PEER_STATE_ACKNOWLEDGING_CONNECT:
		if (commandNumber != ENET_PROTOCOL_COMMAND_ACCEPT)
			return -1;

		enet_protocol_notify_connect(host, peer, event);
		break;

	case ENET_PEER_STATE_DISCONNECTING:
		if (commandNumber != ENET_PROTOCOL_COMMAND_DISCONNECT)
			return -1;

		enet_protocol_notify_disconnect(host, peer, event);
		break;

	case ENET_PEER_STATE_DISCONNECT_LATER:
		if (enet_list_empty(&peer->outgoingReliableCommands) 
		 && enet_list_empty(&peer->outgoingUnreliableCommands) 
		 && enet_list_empty(&peer->sentReliableCommands))
		{
			enet_peer_disconnect(peer, peer->eventStatus);
		}
		break;

	default:
		break;
	}

	return 0;
}

static int enet_protocol_handle_accept(ENetHost* host, ENetEvent* event, ENetPeer* peer, const ENetProtocol* command)
{
	if (peer->state != ENET_PEER_STATE_CONNECTING)
		return 0;

	enet_uint16 channelCount = ENET_NET_TO_HOST_16(command->accept.channelCount);

	if (channelCount < ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT
	 || channelCount > ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT
	 || ENET_NET_TO_HOST_32(command->accept.packetThrottleInterval) != peer->packetThrottleInterval 
	 || ENET_NET_TO_HOST_32(command->accept.packetThrottleAcceleration) != peer->packetThrottleAcceleration 
	 || ENET_NET_TO_HOST_32(command->accept.packetThrottleDeceleration) != peer->packetThrottleDeceleration 
	 || command->accept.connectId != peer->connectId) 
	{
		peer->eventStatus = 0;
		enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);
		return -1;
	}

	enet_protocol_remove_sent_reliable_command(peer, 1, 0xFF);

	if (channelCount < peer->channelCount)
		peer->channelCount = channelCount;

	peer->outgoingPeerId = ENET_NET_TO_HOST_16(command->accept.outgoingPeerId);
	peer->incomingSessionId = command->accept.incomingSessionId;
	peer->outgoingSessionId = command->accept.outgoingSessionId;

	enet_uint16 mtu = ENET_NET_TO_HOST_16(command->accept.mtu);

	if (mtu < ENET_PROTOCOL_MINIMUM_MTU)
		mtu = ENET_PROTOCOL_MINIMUM_MTU;
	else if (mtu > ENET_PROTOCOL_MAXIMUM_MTU)
		mtu = ENET_PROTOCOL_MAXIMUM_MTU;

	if (mtu < peer->mtu)
		peer->mtu = mtu;

	enet_uint32 windowSize = ENET_NET_TO_HOST_32(command->accept.windowSize);

	if (windowSize < ENET_PROTOCOL_MINIMUM_WINDOW_SIZE)
		windowSize = ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;

	if (windowSize > ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE)
		windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;

	if (windowSize < peer->windowSize)
		peer->windowSize = windowSize;

	peer->incomingBandwidth = ENET_NET_TO_HOST_32(command->accept.incomingBandwidth);
	peer->outgoingBandwidth = ENET_NET_TO_HOST_32(command->accept.outgoingBandwidth);

	enet_protocol_notify_connect(host, peer, event);

	return 0;
}



static int enet_protocol_handle_incoming_commands(ENetHost* host, ENetEvent* event) 
{
	if (host->receivedDataLength < ((size_t)&((ENetProtocolHeader*)0)->sentTime) || host->receivedDataLength > ENET_HOST_PACKET_DATA_LENGTH_MAX)
		return 0;

	ENetProtocolHeader* header = (ENetProtocolHeader*)host->receivedData;

    enet_uint8 flags = header->flags;
	enet_uint8 sessionId = flags & ENET_PROTOCOL_HEADER_SESSION;
    enet_uint16 peerId = ENET_NET_TO_HOST_16(header->peerId);

    size_t headerSize = ((size_t)&((ENetProtocolHeader*)0)->sentTime);

    const bool hasTIME = (bool)(flags & ENET_PROTOCOL_HEADER_FLAG_TIME);
    if (hasTIME)
        headerSize += sizeof(enet_uint32);

    const bool hasCRC = (bool)(flags & ENET_PROTOCOL_HEADER_FLAG_CRC);
	if (hasCRC)
		headerSize += sizeof(enet_uint32);

    if (host->receivedDataLength < headerSize)
        return 0;

	ENetPeer* peer;
	if (peerId == ENET_PROTOCOL_NULL_PEER)
		peer = NULL;
	else if (peerId >= host->peerCount)
		return 0;
	else 
	{
		peer = &host->peers[peerId];

		if (peer->state == ENET_PEER_STATE_DISCONNECTED 
            || peer->state == ENET_PEER_STATE_ZOMBIE 
			|| (!in6_equal(host->receivedAddress.host, peer->address.host) || host->receivedAddress.port != peer->address.port) 
			|| (peer->outgoingPeerId <= ENET_PROTOCOL_MAXIMUM_PEER_ID && sessionId != peer->incomingSessionId))
		{
			return 0;
		}
	}

#ifdef ENET_LZ4
    const bool isCompressed = (bool)(flags & ENET_PROTOCOL_HEADER_FLAG_COMP);
	if (isCompressed)
	{
		size_t originalSize = LZ4_decompress_safe((const char*)host->receivedData + headerSize, (char*)host->packetData[1] + headerSize, (int)(host->receivedDataLength - headerSize), (int)(ENET_HOST_PACKET_DATA_LENGTH_MAX - headerSize));

		if (originalSize <= 0 || originalSize > sizeof(host->packetData[1]) - headerSize) 
			return 0;

		memcpy(host->packetData[1], header, headerSize);
		host->receivedData = host->packetData[1];
		host->receivedDataLength = (enet_uint32)(headerSize + originalSize);
	}
#endif

	if (hasCRC)
	{
		enet_uint32* checksum = (enet_uint32*)&host->receivedData[headerSize - sizeof(enet_uint32)];
		enet_uint32 desiredChecksum = *checksum;
		*checksum = peer != NULL ? peer->connectId : 0;

        ENetBuffer buffer;
		buffer.data = host->receivedData;
		buffer.dataLength = host->receivedDataLength;

		if (enet_crc32(&buffer, 1) != desiredChecksum)
			return 0;
	}

	if (peer != NULL) 
	{
		peer->address.host = host->receivedAddress.host;
		peer->address.port = host->receivedAddress.port;
		peer->incomingDataTotal += host->receivedDataLength;
		peer->totalDataReceived += host->receivedDataLength;
	}

	enet_uint8* currentData = host->receivedData + headerSize;

	while (currentData < &host->receivedData[host->receivedDataLength]) 
	{
		if (currentData + sizeof(ENetProtocolCommandHeader) > &host->receivedData[host->receivedDataLength])
			break;

		ENetProtocol* command = (ENetProtocol*)currentData;

		enet_uint8 commandNumber = command->header.command & ENET_PROTOCOL_COMMAND_MASK;
		if (commandNumber >= ENET_PROTOCOL_COMMAND_COUNT) {
			break;
		}

		size_t commandSize = commandSizes[commandNumber];
		if (commandSize == 0 || currentData + commandSize > &host->receivedData[host->receivedDataLength]) {
			break;
		}

		currentData += commandSize;

		if (peer == NULL && (commandNumber != ENET_PROTOCOL_COMMAND_CONNECT || currentData < &host->receivedData[host->receivedDataLength]))
			break;

		command->header.reliableSequenceNumber = ENET_NET_TO_HOST_16(command->header.reliableSequenceNumber);

		switch (commandNumber) 
		{
		case ENET_PROTOCOL_COMMAND_ACKNOWLEDGE:
			if (enet_protocol_handle_acknowledge(host, event, peer, command))
				goto commandError;

			break;

		case ENET_PROTOCOL_COMMAND_CONNECT:
			if (peer != NULL)
				goto commandError;

			if (!host->refuseConnections) 
			{
				peer = enet_protocol_handle_connect(host, command);

				if (peer == NULL)
					goto commandError;
			}
			break;

		case ENET_PROTOCOL_COMMAND_ACCEPT:
			if (enet_protocol_handle_accept(host, event, peer, command))
				goto commandError;

			break;

		case ENET_PROTOCOL_COMMAND_DISCONNECT:
			if (enet_protocol_handle_disconnect(host, peer, command))
				goto commandError;

			break;

		case ENET_PROTOCOL_COMMAND_PING:
			if (enet_protocol_handle_ping(peer))
				goto commandError;

			break;

		case ENET_PROTOCOL_COMMAND_SEND_RELIABLE_PACKET:
			if (enet_protocol_handle_reliable_packet(host, peer, command, &currentData))
				goto commandError;

			break;

		case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_PACKET:
			if (enet_protocol_handle_unreliable_packet(host, peer, command, &currentData))
				goto commandError;

			break;

		case ENET_PROTOCOL_COMMAND_SEND_OUTOFBAND_PACKET:
			if (enet_protocol_handle_out_of_band_packet(host, peer, command, &currentData))
				goto commandError;

			break;

		case ENET_PROTOCOL_COMMAND_SEND_RELIABLE_FRAGMENT:
			if (enet_protocol_handle_reliable_fragment(host, peer, command, &currentData))
				goto commandError;

			break;

        case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT:
            if (enet_protocol_handle_unreliable_fragment(host, peer, command, &currentData))
                goto commandError;

            break;

		case ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT:
			if (enet_protocol_handle_bandwidth_limit(host, peer, command)) {
				goto commandError;
			}
			break;

		case ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE:
			if (enet_protocol_handle_throttle_configure(peer, command))
				goto commandError;

			break;

		default:
			goto commandError;
		}

		if (peer != NULL && (command->header.command & ENET_PROTOCOL_COMMAND_FLAG_ACK) != 0)
		{
			if (!(flags & ENET_PROTOCOL_HEADER_FLAG_TIME)) 
				break;

			enet_uint16 sentTime = ENET_NET_TO_HOST_16((enet_uint16)header->sentTime);

			switch (peer->state) 
			{
			case ENET_PEER_STATE_DISCONNECTING:
			case ENET_PEER_STATE_ACKNOWLEDGING_CONNECT:
			case ENET_PEER_STATE_DISCONNECTED:
			case ENET_PEER_STATE_ZOMBIE:
				break;

			case ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT:
				if ((command->header.command & ENET_PROTOCOL_COMMAND_MASK) == ENET_PROTOCOL_COMMAND_DISCONNECT) 
					enet_peer_queue_acknowledgement(peer, command, sentTime);

				break;

			default:
				enet_peer_queue_acknowledgement(peer, command, sentTime);
				break;
			}
		}
	}

commandError:
	if (event != NULL && event->type != ENET_EVENT_TYPE_NONE)
		return 1;

	return 0;
}

static int enet_protocol_receive_incoming_commands(ENetHost* host, ENetEvent* event)
{
	for (int packets = 0; packets < 256; ++packets) 
	{
		ENetBuffer buffer;
		buffer.data = host->packetData[0];
		buffer.dataLength = host->mtu;

		int receivedLength = enet_socket_receive(host->socket, &host->receivedAddress, &buffer, 1);
		if (receivedLength == -2)
			continue;

		if (receivedLength < 0)
			return -1;

		if (receivedLength == 0)
			return 0;

		host->receivedData = host->packetData[0];
		host->receivedDataLength = receivedLength;

		host->totalReceivedData += receivedLength;
		host->totalReceivedPackets++;

		if (host->interceptCallback != NULL) 
		{
			switch (host->interceptCallback(host, event)) 
			{
			case 1:
				if (event != NULL && event->type != ENET_EVENT_TYPE_NONE)
					return 1;
				else
					continue;

			case -1: return -1;
			default: break;
			}
		}

		switch (enet_protocol_handle_incoming_commands(host, event)) 
		{
		case 1: return 1;
		case -1: return -1;
		default: break;
		}
	}

	return -1;
}



static int enet_protocol_check_timeouts(ENetHost* host, ENetPeer* peer, ENetEvent* event)
{
    ENetListIterator insertPosition = enet_list_begin(&peer->outgoingReliableCommands);
    ENetListIterator currentCommand = enet_list_begin(&peer->sentReliableCommands);
    while (currentCommand != enet_list_end(&peer->sentReliableCommands))
    {
        ENetOutgoingCommand* outgoingCommand = (ENetOutgoingCommand*)currentCommand;

        currentCommand = enet_list_next(currentCommand);

        if (ENET_TIME_DIFFERENCE(host->serviceTime, outgoingCommand->sentTime) < outgoingCommand->roundTripTimeout)
            continue;

        if (peer->earliestTimeout == 0 || ENET_TIME_LESS(outgoingCommand->sentTime, peer->earliestTimeout))
            peer->earliestTimeout = outgoingCommand->sentTime;

        if (peer->earliestTimeout != 0
            && (ENET_TIME_DIFFERENCE(host->serviceTime, peer->earliestTimeout) >= peer->timeoutMaximum
                || (outgoingCommand->roundTripTimeout >= outgoingCommand->roundTripTimeoutLimit && ENET_TIME_DIFFERENCE(host->serviceTime, peer->earliestTimeout) >= peer->timeoutMinimum)))
        {
            enet_protocol_notify_disconnect_timeout(host, peer, event);
            return 1;
        }

        if (outgoingCommand->packet != NULL)
            peer->reliableDataInTransit -= outgoingCommand->fragmentLength;

        ++peer->packetsLost;
        ++peer->totalPacketsLost;

        outgoingCommand->roundTripTimeout = peer->roundTripTime + 4 * peer->roundTripTimeVariance;
        outgoingCommand->roundTripTimeoutLimit = peer->timeoutLimit * outgoingCommand->roundTripTimeout;

        enet_list_insert(insertPosition, enet_list_remove(&outgoingCommand->outgoingCommandList));

        if (currentCommand == enet_list_begin(&peer->sentReliableCommands) && !enet_list_empty(&peer->sentReliableCommands))
        {
            outgoingCommand = (ENetOutgoingCommand*)currentCommand;
            peer->nextTimeout = outgoingCommand->sentTime + outgoingCommand->roundTripTimeout;
        }
    }

    return 0;
}

static void enet_protocol_send_acknowledgements(ENetHost* host, ENetPeer* peer) 
{
	ENetProtocol* command = &host->commands[host->commandCount];
	ENetBuffer* buffer = &host->buffers[host->bufferCount];

	ENetListIterator currentAcknowledgement = enet_list_begin(&peer->acknowledgements);
	while (currentAcknowledgement != enet_list_end(&peer->acknowledgements)) 
	{
		if (command >= &host->commands[sizeof(host->commands) / sizeof(ENetProtocol)] 
		 || buffer >= &host->buffers[sizeof(host->buffers) / sizeof(ENetBuffer)] 
		 || peer->mtu - host->packetSize < sizeof(ENetProtocolAcknowledge))
		{
			host->continueSending = 1;
			break;
		}

		ENetAcknowledgement* acknowledgement = (ENetAcknowledgement*)currentAcknowledgement;
		currentAcknowledgement = enet_list_next(currentAcknowledgement);

		buffer->data = command;
		buffer->dataLength = sizeof(ENetProtocolAcknowledge);
		host->packetSize += buffer->dataLength;

		enet_uint16 reliableSequenceNumber = ENET_HOST_TO_NET_16(acknowledgement->command.header.reliableSequenceNumber);

		command->header.command = ENET_PROTOCOL_COMMAND_ACKNOWLEDGE;
		command->header.channelId = acknowledgement->command.header.channelId;
		command->header.reliableSequenceNumber = reliableSequenceNumber;

		command->acknowledge.receivedReliableSequenceNumber = reliableSequenceNumber;
		command->acknowledge.receivedSentTime = ENET_HOST_TO_NET_16(acknowledgement->sentTime);

		if ((acknowledgement->command.header.command & ENET_PROTOCOL_COMMAND_MASK) == ENET_PROTOCOL_COMMAND_DISCONNECT) 
			enet_protocol_dispatch_state(host, peer, ENET_PEER_STATE_ZOMBIE);

		enet_list_remove(&acknowledgement->acknowledgementList);
		enet_free(acknowledgement);

		++command;
		++buffer;
	}

	host->commandCount = command - host->commands;
	host->bufferCount = buffer - host->buffers;
}

static void enet_protocol_send_unreliable_outgoing_commands(ENetHost* host, ENetPeer* peer) 
{
	ENetProtocol* command = &host->commands[host->commandCount];
	ENetBuffer* buffer = &host->buffers[host->bufferCount];

	ENetListIterator currentCommand = enet_list_begin(&peer->outgoingUnreliableCommands);
	while (currentCommand != enet_list_end(&peer->outgoingUnreliableCommands)) 
	{

		ENetOutgoingCommand* outgoingCommand = (ENetOutgoingCommand*)currentCommand;
		size_t commandSize = commandSizes[outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK];

		if (command >= &host->commands[sizeof(host->commands) / sizeof(ENetProtocol)] 
		 || buffer + 1 >= &host->buffers[sizeof(host->buffers) / sizeof(ENetBuffer)] 
		 || peer->mtu - host->packetSize < commandSize 
		 || (outgoingCommand->packet != NULL && peer->mtu - host->packetSize < commandSize + outgoingCommand->fragmentLength)) 
		{
			host->continueSending = 1;
			break;
		}

		currentCommand = enet_list_next(currentCommand);

		if (outgoingCommand->packet != NULL && outgoingCommand->fragmentOffset == 0) 
		{
			peer->packetThrottleCounter += ENET_PEER_PACKET_THROTTLE_COUNTER;
			peer->packetThrottleCounter %= ENET_PEER_PACKET_THROTTLE_SCALE;

			if (peer->packetThrottleCounter > peer->packetThrottle) 
			{
				const enet_uint16 reliableSequenceNumber = outgoingCommand->reliableSequenceNumber;
				const enet_uint16 unreliableSequenceNumber = outgoingCommand->unreliableSequenceNumber;

				for (;;) 
				{
					--outgoingCommand->packet->referenceCount;

					if (outgoingCommand->packet->referenceCount == 0) 
						enet_packet_destroy(outgoingCommand->packet);

					enet_list_remove(&outgoingCommand->outgoingCommandList);
					enet_free(outgoingCommand);

					if (currentCommand == enet_list_end(&peer->outgoingUnreliableCommands))
						break;

					outgoingCommand = (ENetOutgoingCommand*)currentCommand;

					if (outgoingCommand->reliableSequenceNumber != reliableSequenceNumber || outgoingCommand->unreliableSequenceNumber != unreliableSequenceNumber)
						break;

					currentCommand = enet_list_next(currentCommand);
				}

				continue;
			}
		}

		buffer->data = command;
		buffer->dataLength = commandSize;
		host->packetSize += buffer->dataLength;
		*command = outgoingCommand->command;
		enet_list_remove(&outgoingCommand->outgoingCommandList);

		if (outgoingCommand->packet != NULL) {
			++buffer;

			buffer->data = outgoingCommand->packet->data + outgoingCommand->fragmentOffset;
			buffer->dataLength = outgoingCommand->fragmentLength;

			host->packetSize += buffer->dataLength;

			enet_list_insert(enet_list_end(&peer->sentUnreliableCommands), outgoingCommand);
		}
		else {
			enet_free(outgoingCommand);
		}

		++command;
		++buffer;
	}

	host->commandCount = command - host->commands;
	host->bufferCount = buffer - host->buffers;

	if (peer->state == ENET_PEER_STATE_DISCONNECT_LATER 
	 && enet_list_empty(&peer->outgoingReliableCommands) 
	 && enet_list_empty(&peer->outgoingUnreliableCommands) 
	 && enet_list_empty(&peer->sentReliableCommands))
	{
		enet_peer_disconnect(peer, peer->eventStatus);
	}
}

static int enet_protocol_send_reliable_outgoing_commands(ENetHost* host, ENetPeer* peer) 
{
	ENetProtocol* command = &host->commands[host->commandCount];
	ENetBuffer* buffer = &host->buffers[host->bufferCount];

	bool windowExceeded = false;
	bool windowWrap = false;
	int canPing = 1;

	ENetListIterator currentCommand = enet_list_begin(&peer->outgoingReliableCommands);

	while (currentCommand != enet_list_end(&peer->outgoingReliableCommands)) 
	{
		ENetOutgoingCommand* outgoingCommand = (ENetOutgoingCommand*)currentCommand;
		ENetChannel* channel = outgoingCommand->command.header.channelId < peer->channelCount ? &peer->channels[outgoingCommand->command.header.channelId] : NULL;
		enet_uint16 reliableWindow = outgoingCommand->reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

		if (channel != NULL)
		{
			if (!windowWrap
             && outgoingCommand->sendAttempts < 1 
			 && !(outgoingCommand->reliableSequenceNumber % ENET_PEER_RELIABLE_WINDOW_SIZE) 
			 && (channel->reliableWindows[(reliableWindow + ENET_PEER_RELIABLE_WINDOWS - 1) % ENET_PEER_RELIABLE_WINDOWS] >= ENET_PEER_RELIABLE_WINDOW_SIZE
			  || channel->usedReliableWindows & ((((1 << ENET_PEER_FREE_RELIABLE_WINDOWS) - 1) << reliableWindow) | (((1 << ENET_PEER_FREE_RELIABLE_WINDOWS) - 1) >> (ENET_PEER_RELIABLE_WINDOWS - reliableWindow)))))
			{
				windowWrap = 1;
			}

			if (windowWrap) 
			{
				currentCommand = enet_list_next(currentCommand);
				continue;
			}
		}

		if (outgoingCommand->packet != NULL) 
		{
			if (!windowExceeded) 
			{
				enet_uint32 windowSize = (peer->packetThrottle * peer->windowSize) / ENET_PEER_PACKET_THROTTLE_SCALE;
				if (peer->reliableDataInTransit + outgoingCommand->fragmentLength > ENET_MAX(windowSize, peer->mtu)) 
					windowExceeded = true;
			}

			if (windowExceeded) 
			{
				currentCommand = enet_list_next(currentCommand);
				continue;
			}
		}

		canPing = 0;

		size_t commandSize = commandSizes[outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK];

		if (command >= &host->commands[sizeof(host->commands) / sizeof(ENetProtocol)] 
         || buffer + 1 >= &host->buffers[sizeof(host->buffers) / sizeof(ENetBuffer)] 
         || peer->mtu - host->packetSize < commandSize 
         || (outgoingCommand->packet != NULL && (enet_uint16)(peer->mtu - host->packetSize) < (enet_uint16)(commandSize + outgoingCommand->fragmentLength))) 
		{
			host->continueSending = 1;
			break;
		}

		currentCommand = enet_list_next(currentCommand);

		if (channel != NULL && outgoingCommand->sendAttempts < 1)
		{
            channel->usedReliableWindows |= 1 << reliableWindow;
			++channel->reliableWindows[reliableWindow];
		}

		++outgoingCommand->sendAttempts;

		if (outgoingCommand->roundTripTimeout == 0) 
		{
			outgoingCommand->roundTripTimeout = peer->roundTripTime + 4 * peer->roundTripTimeVariance;
			outgoingCommand->roundTripTimeoutLimit = peer->timeoutLimit * outgoingCommand->roundTripTimeout;
		}

		if (enet_list_empty(&peer->sentReliableCommands))
			peer->nextTimeout = host->serviceTime + outgoingCommand->roundTripTimeout;

		enet_list_insert(enet_list_end(&peer->sentReliableCommands), enet_list_remove(&outgoingCommand->outgoingCommandList));

		outgoingCommand->sentTime = host->serviceTime;

		buffer->data = command;
		buffer->dataLength = commandSize;

		host->packetSize += buffer->dataLength;
		host->headerFlags |= ENET_PROTOCOL_HEADER_FLAG_TIME;

		*command = outgoingCommand->command;

		if (outgoingCommand->packet != NULL) 
		{
			++buffer;
			buffer->data = outgoingCommand->packet->data + outgoingCommand->fragmentOffset;
			buffer->dataLength = outgoingCommand->fragmentLength;
			host->packetSize += outgoingCommand->fragmentLength;
			peer->reliableDataInTransit += outgoingCommand->fragmentLength;
		}

		++peer->packetsSent;
		++peer->totalPacketsSent;

		++command;
		++buffer;
	}

	host->commandCount = command - host->commands;
	host->bufferCount = buffer - host->buffers;

	return canPing;
}

static int enet_protocol_send_outgoing_commands(ENetHost* host, ENetEvent* event, int checkForTimeouts)
{
	enet_uint8 headerData[sizeof(ENetProtocolHeader) + sizeof(enet_uint32)];
	ENetProtocolHeader* header = (ENetProtocolHeader*)headerData;
		
	host->continueSending = 1;

	while (host->continueSending)
	{
		ENetPeer* currentPeer;
		for (host->continueSending = 0, currentPeer = host->peers; currentPeer < &host->peers[host->peerCount]; ++currentPeer)
		{
			if (currentPeer->state == ENET_PEER_STATE_DISCONNECTED || currentPeer->state == ENET_PEER_STATE_ZOMBIE) 
				continue;

			host->headerFlags = 0;
			host->commandCount = 0;
			host->bufferCount = 1;
			host->packetSize = sizeof(ENetProtocolHeader);

			if (!enet_list_empty(&currentPeer->acknowledgements)) 
			{
				enet_protocol_send_acknowledgements(host, currentPeer);
			}

			if (checkForTimeouts != 0 
			 && !enet_list_empty(&currentPeer->sentReliableCommands) 
			 && ENET_TIME_GREATER_EQUAL(host->serviceTime, currentPeer->nextTimeout) 
			 && enet_protocol_check_timeouts(host, currentPeer, event) == 1) 
			{
				if (event != NULL && event->type != ENET_EVENT_TYPE_NONE) 
					return 1;
				else 
					continue;
			}

			if ((enet_list_empty(&currentPeer->outgoingReliableCommands) || enet_protocol_send_reliable_outgoing_commands(host, currentPeer)) 
			 && enet_list_empty(&currentPeer->sentReliableCommands) 
			 && ENET_TIME_DIFFERENCE(host->serviceTime, currentPeer->lastReceiveTime) >= currentPeer->pingInterval 
			 && currentPeer->mtu - host->packetSize >= sizeof(ENetProtocolPing))
			{
				enet_peer_ping(currentPeer);
				enet_protocol_send_reliable_outgoing_commands(host, currentPeer);
			}

			if (!enet_list_empty(&currentPeer->outgoingUnreliableCommands))
				enet_protocol_send_unreliable_outgoing_commands(host, currentPeer);

			if (host->commandCount == 0)
				continue;

			if (currentPeer->packetLossEpoch == 0) 
			{
				currentPeer->packetLossEpoch = host->serviceTime;
			}
			else if (ENET_TIME_DIFFERENCE(host->serviceTime, currentPeer->packetLossEpoch) >= ENET_PEER_PACKET_LOSS_INTERVAL && currentPeer->packetsSent > 0) 
			{
				enet_uint32 packetLoss = currentPeer->packetsLost * ENET_PEER_PACKET_LOSS_SCALE / currentPeer->packetsSent;

#ifdef ENET_DEBUG
				printf(
					"peer %u: %f%%+-%f%% packet loss, %u+-%u ms round trip time, %f%% throttle, %u/%u outgoing, %u/%u incoming\n", currentPeer->incomingPeerId,
					currentPeer->packetLoss / (float)ENET_PEER_PACKET_LOSS_SCALE,
					currentPeer->packetLossVariance / (float)ENET_PEER_PACKET_LOSS_SCALE, currentPeer->roundTripTime, currentPeer->roundTripTimeVariance,
					currentPeer->packetThrottle / (float)ENET_PEER_PACKET_THROTTLE_SCALE,
					enet_list_size(&currentPeer->outgoingReliableCommands),
					enet_list_size(&currentPeer->outgoingUnreliableCommands),
					currentPeer->channels != NULL ? enet_list_size(&currentPeer->channels->incomingReliableCommands) : 0,
					currentPeer->channels != NULL ? enet_list_size(&currentPeer->channels->incomingUnreliableCommands) : 0
				);
#endif

				currentPeer->packetLossVariance -= currentPeer->packetLossVariance / 4;

				if (packetLoss >= currentPeer->packetLoss) 
				{
					currentPeer->packetLoss += (packetLoss - currentPeer->packetLoss) / 8;
					currentPeer->packetLossVariance += (packetLoss - currentPeer->packetLoss) / 4;
				}
				else 
				{
					currentPeer->packetLoss -= (currentPeer->packetLoss - packetLoss) / 8;
					currentPeer->packetLossVariance += (currentPeer->packetLoss - packetLoss) / 4;
				}

				currentPeer->packetLossEpoch = host->serviceTime;
				currentPeer->packetsSent = 0;
				currentPeer->packetsLost = 0;
			}

			host->buffers->data = headerData;

			if (host->headerFlags & ENET_PROTOCOL_HEADER_FLAG_TIME) 
			{
				header->sentTime = ENET_HOST_TO_NET_16((enet_uint16)(host->serviceTime & 0x0000FFFF));
				host->buffers->dataLength = sizeof(ENetProtocolHeader);
			}
			else 
			{
                host->buffers->dataLength = ((size_t)&((ENetProtocolHeader*)0)->sentTime);
			}

#ifdef ENET_LZ4
            size_t shouldCompress = 0;
			if (host->compressionEnabled) 
			{
				size_t originalSize = host->packetSize - sizeof(ENetProtocolHeader);
				size_t totalSize = originalSize;
				size_t dataSize = 0;

				const ENetBuffer* buffers = &host->buffers[1];
				char* data = (char*)enet_malloc(originalSize);
                if (data != NULL)
                {
                    while (totalSize)
                    {
                        for (int i = 0; i < host->bufferCount - 1; i++)
                        {
                            size_t copySize = ENET_MIN(totalSize, buffers[i].dataLength);
                            memcpy(data + dataSize, buffers[i].data, copySize);
                            totalSize -= copySize;
                            dataSize += copySize;
                        }
                    }

                    size_t compressedSize = LZ4_compress_default((const char*)data, (char*)host->packetData[1], (int)dataSize, (int)originalSize);

                    enet_free(data);

                    if (compressedSize > 0 && compressedSize < originalSize)
                    {
                        host->headerFlags |= ENET_PROTOCOL_HEADER_FLAG_COMP;
                        shouldCompress = compressedSize;

#ifdef ENET_DEBUG_COMPRESS
                        printf("peer %u: compressed %u->%u (%u%%)\n", currentPeer->incomingPeerId, originalSize, compressedSize, (compressedSize * 100) / originalSize);
#endif
                    }
                }
			}
#endif
            bool useCRC = host->crcEnabled;
            if (useCRC)
                host->headerFlags |= ENET_PROTOCOL_HEADER_FLAG_CRC;

			if (currentPeer->outgoingPeerId <= ENET_PROTOCOL_MAXIMUM_PEER_ID)
				host->headerFlags |= currentPeer->outgoingSessionId;

            header->flags = host->headerFlags;
			header->peerId = ENET_HOST_TO_NET_16(currentPeer->outgoingPeerId);

			if (useCRC) 
			{
				enet_uint32* checksum = (enet_uint32*)&headerData[host->buffers->dataLength];
				*checksum = currentPeer->outgoingPeerId <= ENET_PROTOCOL_MAXIMUM_PEER_ID ? currentPeer->connectId : 0;
				host->buffers->dataLength += sizeof(enet_uint32);
				*checksum = enet_crc32(host->buffers, host->bufferCount);
			}

#ifdef ENET_LZ4
			if (shouldCompress > 0) {
				host->buffers[1].data = host->packetData[1];
				host->buffers[1].dataLength = shouldCompress;
				host->bufferCount = 2;
			}
#endif

			currentPeer->lastSendTime = host->serviceTime;
			int sentLength = enet_socket_send(host->socket, &currentPeer->address, host->buffers, host->bufferCount);
			enet_protocol_remove_sent_unreliable_commands(currentPeer);

			if (sentLength < 0) {
				return -1;
			}

			host->totalSentData += sentLength;
			currentPeer->totalDataSent += sentLength;
			host->totalSentPackets++;
		}
	}

	return 0;
}



void enet_host_flush(ENetHost* host) 
{
	host->serviceTime = (enet_uint32)enet_time();
	enet_protocol_send_outgoing_commands(host, NULL, 0);
}

int enet_host_check_events(ENetHost* host, ENetEvent* event) 
{
	if (event == NULL)
		return -1;

	event->type = ENET_EVENT_TYPE_NONE;
	event->peer = NULL;
	event->packet = NULL;

	return enet_protocol_dispatch_incoming_commands(host, event);
}

int enet_host_service(ENetHost* host, ENetEvent* event, enet_uint32 timeout) 
{
	if (event != NULL) 
	{
		event->type = ENET_EVENT_TYPE_NONE;
		event->peer = NULL;
		event->packet = NULL;

		switch (enet_protocol_dispatch_incoming_commands(host, event)) 
		{
		case 1: 
			return 1;

		case -1:
#ifdef ENET_DEBUG
			perror("Error dispatching incoming packets");
#endif
			return -1;

		default: 
			break;
		}
	}

	host->serviceTime = (enet_uint32)enet_time();
	timeout += host->serviceTime;

	enet_uint32 waitCondition = 0;

	do 
	{
		if (ENET_TIME_DIFFERENCE(host->serviceTime, host->bandwidthThrottleEpoch) >= ENET_HOST_BANDWIDTH_THROTTLE_INTERVAL)
			enet_host_bandwidth_throttle(host);

		switch (enet_protocol_send_outgoing_commands(host, event, 1)) 
		{
		case 1:
			return 1;

		case -1:
#ifdef ENET_DEBUG
			perror("Error sending outgoing packets");
#endif
			return -1;

		default:
			break;
		}

		switch (enet_protocol_receive_incoming_commands(host, event)) 
		{
		case 1:
			return 1;

		case -1:
#ifdef ENET_DEBUG
			perror("Error receiving incoming packets");
#endif
			return -1;

		default:
			break;
		}

		switch (enet_protocol_send_outgoing_commands(host, event, 1)) 
		{
		case 1:
			return 1;

		case -1:
#ifdef ENET_DEBUG
			perror("Error sending outgoing packets");
#endif
			return -1;

		default:
			break;
		}

		if (event != NULL) 
		{
			switch (enet_protocol_dispatch_incoming_commands(host, event)) 
			{
			case 1:
				return 1;

			case -1:
#ifdef ENET_DEBUG
				perror("Error dispatching incoming packets");
#endif
				return -1;

			default:
				break;
			}
		}

		if (ENET_TIME_GREATER_EQUAL(host->serviceTime, timeout))
			return 0;

		do 
		{
			host->serviceTime = (enet_uint32)enet_time();

			if (ENET_TIME_GREATER_EQUAL(host->serviceTime, timeout))
				return 0;

			waitCondition = ENET_SOCKET_WAIT_RECEIVE | ENET_SOCKET_WAIT_INTERRUPT;

			if (enet_socket_wait(host->socket, &waitCondition, ENET_TIME_DIFFERENCE(timeout, host->serviceTime)) != 0)
				return -1;

		} 
		while (waitCondition & ENET_SOCKET_WAIT_INTERRUPT);

		host->serviceTime = (enet_uint32)enet_time();
	} while (waitCondition & ENET_SOCKET_WAIT_RECEIVE);

	return 0;
}



/**************************************************************************
 * Peer
 **************************************************************************/
	
void enet_peer_throttle_configure(ENetPeer* peer, enet_uint32 interval, enet_uint32 acceleration, enet_uint32 deceleration) 
{
	peer->packetThrottleInterval = interval;
	peer->packetThrottleAcceleration = acceleration;
	peer->packetThrottleDeceleration = deceleration;

	ENetProtocol command;
	command.header.command = ENET_PROTOCOL_COMMAND_THROTTLE_CONFIGURE | ENET_PROTOCOL_COMMAND_FLAG_ACK;
	command.header.channelId = 0xFF;

	command.throttleConfigure.packetThrottleInterval = ENET_HOST_TO_NET_32(interval);
	command.throttleConfigure.packetThrottleAcceleration = ENET_HOST_TO_NET_32(acceleration);
	command.throttleConfigure.packetThrottleDeceleration = ENET_HOST_TO_NET_32(deceleration);

	enet_peer_queue_outgoing_command(peer, &command, NULL, 0, 0);
}

int enet_peer_throttle(ENetPeer* peer, enet_uint32 rtt) 
{
	if (peer->lastRoundTripTime <= peer->lastRoundTripTimeVariance)
	{
		peer->packetThrottle = peer->packetThrottleLimit;
	}
	else if (rtt < peer->lastRoundTripTime) 
	{
		peer->packetThrottle += peer->packetThrottleAcceleration;

		if (peer->packetThrottle > peer->packetThrottleLimit) 
			peer->packetThrottle = peer->packetThrottleLimit;

		return 1;
	}
	else if (rtt > peer->lastRoundTripTime + 2 * peer->lastRoundTripTimeVariance) 
	{
		if (peer->packetThrottle > peer->packetThrottleDeceleration) 
			peer->packetThrottle -= peer->packetThrottleDeceleration;
		else 
			peer->packetThrottle = 0;

		return -1;
	}

	return 0;
}

int enet_peer_send(ENetPeer* peer, enet_uint8 channelId, ENetPacket* packet) 
{
	if (peer->state != ENET_PEER_STATE_CONNECTED || channelId >= peer->channelCount || packet->dataLength > peer->host->maximumPacketSize) {
		return -1;
	}

	ENetChannel* channel = &peer->channels[channelId];
	enet_uint16 fragmentLength = peer->mtu - sizeof(ENetProtocolHeader) - sizeof(ENetProtocolSendFragment);

	if (peer->host->crcEnabled)
		fragmentLength -= sizeof(enet_uint32);

	if (packet->dataLength > fragmentLength) 
	{
		size_t calculatedFragmentCount = (packet->dataLength + fragmentLength - 1) / fragmentLength;
		if (calculatedFragmentCount > ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT)
			return -1;

        enet_uint16 fragmentCount = (enet_uint16)calculatedFragmentCount;
		enet_uint8 commandNumber;
		enet_uint16 startSequenceNumber;
		if ((packet->flags & (ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT)) == ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT && channel->outgoingUnreliableSequenceNumber < 0xFFFF) {
			commandNumber = ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT;
			startSequenceNumber = ENET_HOST_TO_NET_16(channel->outgoingUnreliableSequenceNumber + 1);
		}
		else {
			commandNumber = ENET_PROTOCOL_COMMAND_SEND_RELIABLE_FRAGMENT | ENET_PROTOCOL_COMMAND_FLAG_ACK;
			startSequenceNumber = ENET_HOST_TO_NET_16(channel->outgoingReliableSequenceNumber + 1);
		}

		ENetList fragments;
		enet_list_clear(&fragments);

		ENetOutgoingCommand* fragment = NULL;

		enet_uint16 fragmentNumber = 0;
		for (enet_uint32 fragmentOffset = 0; fragmentOffset < packet->dataLength; fragmentOffset += fragmentLength, ++fragmentNumber)
		{
			if (packet->dataLength - fragmentOffset < fragmentLength) 
				fragmentLength = (enet_uint16)(packet->dataLength - fragmentOffset);

			fragment = (ENetOutgoingCommand*)enet_malloc(sizeof(ENetOutgoingCommand));

			if (fragment == NULL) 
			{
				while (!enet_list_empty(&fragments)) 
				{
					fragment = (ENetOutgoingCommand*)enet_list_remove(enet_list_begin(&fragments));

					enet_free(fragment);
				}

				return -1;
			}

			fragment->fragmentOffset = fragmentOffset;
			fragment->fragmentLength = fragmentLength;
			fragment->packet = packet;
			fragment->command.header.command = commandNumber;
			fragment->command.header.channelId = channelId;

			fragment->command.sendFragment.startSequenceNumber = startSequenceNumber;

			fragment->command.sendFragment.dataLength = ENET_HOST_TO_NET_16(fragmentLength);
			fragment->command.sendFragment.fragmentCount = ENET_HOST_TO_NET_16(fragmentCount);
			fragment->command.sendFragment.fragmentNumber = ENET_HOST_TO_NET_16(fragmentNumber);
			fragment->command.sendFragment.totalLength = ENET_HOST_TO_NET_32((enet_uint32)packet->dataLength);
			fragment->command.sendFragment.fragmentOffset = ENET_NET_TO_HOST_32(fragmentOffset);

			enet_list_insert(enet_list_end(&fragments), fragment);
		}

		packet->referenceCount += fragmentNumber;

		while (!enet_list_empty(&fragments)) 
		{
			fragment = (ENetOutgoingCommand*)enet_list_remove(enet_list_begin(&fragments));
			enet_peer_setup_outgoing_command(peer, fragment);
		}
	}
    else
    {
        ENetProtocol command;
        command.header.channelId = channelId;

        if ((packet->flags & (ENET_PACKET_FLAG_RELIABLE | ENET_PACKET_FLAG_UNSEQUENCED)) == ENET_PACKET_FLAG_UNSEQUENCED)
        {
            command.header.command = ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_PACKET | ENET_PROTOCOL_COMMAND_FLAG_USQ;
            command.sendUnsequenced.dataLength = ENET_HOST_TO_NET_16((enet_uint16)packet->dataLength);
        }
        else if (packet->flags & ENET_PACKET_FLAG_RELIABLE || channel->outgoingUnreliableSequenceNumber >= 0xFFFF)
        {
            command.header.command = ENET_PROTOCOL_COMMAND_SEND_RELIABLE_PACKET | ENET_PROTOCOL_COMMAND_FLAG_ACK;
            command.sendReliable.dataLength = ENET_HOST_TO_NET_16((enet_uint16)packet->dataLength);
        }
        else
        {
            command.header.command = ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_PACKET;
            command.sendUnreliable.dataLength = ENET_HOST_TO_NET_16((enet_uint16)packet->dataLength);
        }

        if (enet_peer_queue_outgoing_command(peer, &command, packet, 0, (enet_uint16)packet->dataLength) == NULL)
            return -1;

    }

	return 0;
}

ENetPacket*  enet_peer_receive(ENetPeer* peer, enet_uint8* channelId) 
{
	if (enet_list_empty(&peer->dispatchedCommands))
		return NULL;

	ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)enet_list_remove(enet_list_begin(&peer->dispatchedCommands));

	if (channelId != NULL)
		*channelId = incomingCommand->command.header.channelId;

	ENetPacket* packet = incomingCommand->packet;
	--packet->referenceCount;

	if (incomingCommand->fragments != NULL)
		enet_free(incomingCommand->fragments);

	enet_free(incomingCommand);
	peer->totalWaitingData -= packet->dataLength;

	return packet;
}

static void enet_peer_reset_outgoing_commands(ENetList* queue) 
{
	while (!enet_list_empty(queue)) 
	{
		ENetOutgoingCommand* outgoingCommand = (ENetOutgoingCommand*)enet_list_remove(enet_list_begin(queue));

		if (outgoingCommand->packet != NULL) 
		{
			--outgoingCommand->packet->referenceCount;

			if (outgoingCommand->packet->referenceCount == 0)
				enet_packet_destroy(outgoingCommand->packet);
		}

		enet_free(outgoingCommand);
	}
}

static void enet_peer_remove_incoming_commands(ENetListIterator startCommand, ENetListIterator endCommand) 
{
	for (ENetListIterator currentCommand = startCommand; currentCommand != endCommand;) 
	{
		ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)currentCommand;

		currentCommand = enet_list_next(currentCommand);
		enet_list_remove(&incomingCommand->incomingCommandList);

		if (incomingCommand->packet != NULL) 
		{
			--incomingCommand->packet->referenceCount;

			if (incomingCommand->packet->referenceCount == 0)
				enet_packet_destroy(incomingCommand->packet);
		}

		if (incomingCommand->fragments != NULL)
			enet_free(incomingCommand->fragments);

		enet_free(incomingCommand);
	}
}

static void enet_peer_reset_incoming_commands(ENetList* queue) 
{
	enet_peer_remove_incoming_commands(enet_list_begin(queue), enet_list_end(queue));
}

void enet_peer_reset_queues(ENetPeer* peer) 
{
	if (peer->needsDispatch) 
	{
		enet_list_remove(&peer->dispatchList);
		peer->needsDispatch = 0;
	}

	while (!enet_list_empty(&peer->acknowledgements)) 
	{
		enet_free(enet_list_remove(enet_list_begin(&peer->acknowledgements)));
	}

	enet_peer_reset_outgoing_commands(&peer->sentReliableCommands);
	enet_peer_reset_outgoing_commands(&peer->sentUnreliableCommands);
	enet_peer_reset_outgoing_commands(&peer->outgoingReliableCommands);
	enet_peer_reset_outgoing_commands(&peer->outgoingUnreliableCommands);
	enet_peer_reset_incoming_commands(&peer->dispatchedCommands);

	if (peer->channels != NULL && peer->channelCount > 0) 
	{
		for (ENetChannel* channel = peer->channels; channel < &peer->channels[peer->channelCount]; ++channel)
		{
			enet_peer_reset_incoming_commands(&channel->incomingReliableCommands);
			enet_peer_reset_incoming_commands(&channel->incomingUnreliableCommands);
		}

		enet_free(peer->channels);
	}

	peer->channels = NULL;
	peer->channelCount = 0;
}

void enet_peer_on_connect(ENetPeer* peer) 
{
	if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER) 
	{
		if (peer->incomingBandwidth != 0) 
		{
			++peer->host->bandwidthLimitedPeers;
		}

		++peer->host->connectedPeers;
	}
}

void enet_peer_on_disconnect(ENetPeer* peer) 
{
	if (peer->state == ENET_PEER_STATE_CONNECTED || peer->state == ENET_PEER_STATE_DISCONNECT_LATER) 
	{
		if (peer->incomingBandwidth != 0) 
		{
			--peer->host->bandwidthLimitedPeers;
		}

		--peer->host->connectedPeers;
	}
}

void enet_peer_reset(ENetPeer* peer) 
{
    if (peer == NULL)
        return;

	enet_peer_on_disconnect(peer);

	peer->outgoingPeerId = ENET_PROTOCOL_NULL_PEER;
	peer->state = ENET_PEER_STATE_DISCONNECTED;
	peer->incomingBandwidth = 0;
	peer->outgoingBandwidth = 0;
	peer->incomingBandwidthThrottleEpoch = 0;
	peer->outgoingBandwidthThrottleEpoch = 0;
	peer->incomingDataTotal = 0;
	peer->totalDataReceived = 0;
	peer->outgoingDataTotal = 0;
	peer->totalDataSent = 0;
	peer->lastSendTime = 0;
	peer->lastReceiveTime = 0;
	peer->nextTimeout = 0;
	peer->earliestTimeout = 0;
	peer->packetLossEpoch = 0;
	peer->packetsSent = 0;
	peer->totalPacketsSent = 0;
	peer->packetsLost = 0;
	peer->totalPacketsLost = 0;
	peer->packetLoss = 0;
	peer->packetLossVariance = 0;
	peer->packetThrottle = ENET_PEER_DEFAULT_PACKET_THROTTLE;
	peer->packetThrottleLimit = ENET_PEER_PACKET_THROTTLE_SCALE;
	peer->packetThrottleCounter = 0;
	peer->packetThrottleEpoch = 0;
	peer->packetThrottleAcceleration = ENET_PEER_PACKET_THROTTLE_ACCELERATION;
	peer->packetThrottleDeceleration = ENET_PEER_PACKET_THROTTLE_DECELERATION;
	peer->packetThrottleInterval = ENET_PEER_PACKET_THROTTLE_INTERVAL;
	peer->pingInterval = ENET_PEER_PING_INTERVAL;
	peer->timeoutLimit = ENET_PEER_TIMEOUT_LIMIT;
	peer->timeoutMinimum = ENET_PEER_TIMEOUT_MINIMUM;
	peer->timeoutMaximum = ENET_PEER_TIMEOUT_MAXIMUM;
	peer->smoothedRoundTripTime = 0;
	peer->lastRoundTripTime = ENET_PEER_DEFAULT_ROUND_TRIP_TIME;
	peer->lowestRoundTripTime = ENET_PEER_DEFAULT_ROUND_TRIP_TIME;
	peer->lastRoundTripTimeVariance = 0;
	peer->highestRoundTripTimeVariance = 0;
	peer->roundTripTime = ENET_PEER_DEFAULT_ROUND_TRIP_TIME;
	peer->roundTripTimeVariance = 0;
	peer->mtu = peer->host->mtu;
	peer->reliableDataInTransit = 0;
	peer->outgoingReliableSequenceNumber = 0;
	peer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;
	peer->incomingUnsequencedGroup = 0;
	peer->outgoingUnsequencedGroup = 0;
	peer->eventStatus = 0;
	peer->totalWaitingData = 0;

	memset(peer->unsequencedWindow, 0, sizeof(peer->unsequencedWindow));
	enet_peer_reset_queues(peer);
}

void enet_peer_ping(ENetPeer* peer) 
{
	if (peer->state != ENET_PEER_STATE_CONNECTED)
		return;

	ENetProtocol command;
	command.header.command = ENET_PROTOCOL_COMMAND_PING | ENET_PROTOCOL_COMMAND_FLAG_ACK;
	command.header.channelId = 0xFF;

	enet_peer_queue_outgoing_command(peer, &command, NULL, 0, 0);
}

void enet_peer_set_ping_interval(ENetPeer* peer, enet_uint32 pingInterval) 
{
	peer->pingInterval = pingInterval ? pingInterval : ENET_PEER_PING_INTERVAL;
}

ENET_API enet_uint32 enet_peer_get_ping_interval(ENetPeer* peer)
{
    return peer->pingInterval;
}

void enet_peer_timeout(ENetPeer* peer, enet_uint32 timeoutLimit, enet_uint32 timeoutMinimum, enet_uint32 timeoutMaximum) 
{
	peer->timeoutLimit = timeoutLimit ? timeoutLimit : ENET_PEER_TIMEOUT_LIMIT;
	peer->timeoutMinimum = timeoutMinimum ? timeoutMinimum : ENET_PEER_TIMEOUT_MINIMUM;
	peer->timeoutMaximum = timeoutMaximum ? timeoutMaximum : ENET_PEER_TIMEOUT_MAXIMUM;
}

void enet_peer_disconnect_immediately(ENetPeer* peer, enet_uint32 status)
{
	if (peer->state == ENET_PEER_STATE_DISCONNECTED)
		return;

	if (peer->state != ENET_PEER_STATE_ZOMBIE && peer->state != ENET_PEER_STATE_DISCONNECTING) 
	{
		enet_peer_reset_queues(peer);

		ENetProtocol command;
		command.header.command = ENET_PROTOCOL_COMMAND_DISCONNECT | ENET_PROTOCOL_COMMAND_FLAG_USQ;
		command.header.channelId = 0xFF;
		command.disconnect.status = ENET_HOST_TO_NET_32(status);

		enet_peer_queue_outgoing_command(peer, &command, NULL, 0, 0);
		enet_host_flush(peer->host);
	}

	enet_peer_reset(peer);
}

void enet_peer_disconnect(ENetPeer* peer, enet_uint32 status)
{
	if (peer->state == ENET_PEER_STATE_DISCONNECTING 
	 || peer->state == ENET_PEER_STATE_DISCONNECTED 
	 || peer->state == ENET_PEER_STATE_ACKNOWLEDGING_DISCONNECT 
	 || peer->state == ENET_PEER_STATE_ZOMBIE) 
	{
		return;
	}

	enet_peer_reset_queues(peer);

	ENetProtocol command;
	command.header.command = ENET_PROTOCOL_COMMAND_DISCONNECT;
	command.header.channelId = 0xFF;
	command.disconnect.status = ENET_HOST_TO_NET_32(status);

	if (peer->state == ENET_PEER_STATE_CONNECTED || peer->state == ENET_PEER_STATE_DISCONNECT_LATER) 
		command.header.command |= ENET_PROTOCOL_COMMAND_FLAG_ACK;
	else 
		command.header.command |= ENET_PROTOCOL_COMMAND_FLAG_USQ;

	enet_peer_queue_outgoing_command(peer, &command, NULL, 0, 0);

	if (peer->state == ENET_PEER_STATE_CONNECTED || peer->state == ENET_PEER_STATE_DISCONNECT_LATER) 
	{
		enet_peer_on_disconnect(peer);
		peer->state = ENET_PEER_STATE_DISCONNECTING;
	}
	else // if (any connecting state)
	{
		enet_host_flush(peer->host);
		enet_peer_reset(peer);
	}
}

void enet_peer_disconnect_when_ready(ENetPeer* peer, enet_uint32 status)
{
	if ((peer->state == ENET_PEER_STATE_CONNECTED || peer->state == ENET_PEER_STATE_DISCONNECT_LATER) 
	 && !(enet_list_empty(&peer->outgoingReliableCommands) && enet_list_empty(&peer->outgoingUnreliableCommands) && enet_list_empty(&peer->sentReliableCommands))) 
	{
		peer->state = ENET_PEER_STATE_DISCONNECT_LATER;
		peer->eventStatus = status;
	}
	else 
	{
		enet_peer_disconnect(peer, status);
	}
}

ENetAcknowledgement* enet_peer_queue_acknowledgement(ENetPeer* peer, const ENetProtocol* command, enet_uint16 sentTime) 
{
	if (command->header.channelId < peer->channelCount) 
	{
		ENetChannel* channel = &peer->channels[command->header.channelId];
		enet_uint16 reliableWindow = command->header.reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
		enet_uint16 currentWindow = channel->incomingReliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

		if (command->header.reliableSequenceNumber < channel->incomingReliableSequenceNumber)
			reliableWindow += ENET_PEER_RELIABLE_WINDOWS;

		if (reliableWindow >= currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS - 1 && reliableWindow <= currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS)
			return NULL;
	}

	ENetAcknowledgement* acknowledgement = (ENetAcknowledgement*)enet_malloc(sizeof(ENetAcknowledgement));

	if (acknowledgement == NULL)
		return NULL;

	peer->outgoingDataTotal += sizeof(ENetProtocolAcknowledge);

	acknowledgement->sentTime = sentTime;
	acknowledgement->command = *command;

	enet_list_insert(enet_list_end(&peer->acknowledgements), acknowledgement);

	return acknowledgement;
}

void enet_peer_setup_outgoing_command(ENetPeer* peer, ENetOutgoingCommand* outgoingCommand) 
{
	ENetChannel* channel = &peer->channels[outgoingCommand->command.header.channelId];
	peer->outgoingDataTotal += (enet_uint32)enet_protocol_command_size(outgoingCommand->command.header.command) + outgoingCommand->fragmentLength;

	if (outgoingCommand->command.header.channelId == 0xFF) 
	{
		++peer->outgoingReliableSequenceNumber;

		outgoingCommand->reliableSequenceNumber = peer->outgoingReliableSequenceNumber;
		outgoingCommand->unreliableSequenceNumber = 0;
	}
	else if (outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_FLAG_ACK) 
	{
		++channel->outgoingReliableSequenceNumber;
        channel->outgoingUnreliableSequenceNumber = 0;

		outgoingCommand->reliableSequenceNumber = channel->outgoingReliableSequenceNumber;
		outgoingCommand->unreliableSequenceNumber = 0;
	}
	else if (outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_FLAG_USQ) 
	{
		++peer->outgoingUnsequencedGroup;

		outgoingCommand->reliableSequenceNumber = 0;
		outgoingCommand->unreliableSequenceNumber = 0;
	}
	else 
	{
		if (outgoingCommand->fragmentOffset == 0)
			++channel->outgoingUnreliableSequenceNumber;

		outgoingCommand->reliableSequenceNumber = channel->outgoingReliableSequenceNumber;
		outgoingCommand->unreliableSequenceNumber = channel->outgoingUnreliableSequenceNumber;
	}

	outgoingCommand->sendAttempts = 0;
	outgoingCommand->sentTime = 0;
	outgoingCommand->roundTripTimeout = 0;
	outgoingCommand->roundTripTimeoutLimit = 0;
	outgoingCommand->command.header.reliableSequenceNumber = ENET_HOST_TO_NET_16(outgoingCommand->reliableSequenceNumber);

	switch (outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK) 
	{
	case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_PACKET:
		outgoingCommand->command.sendUnreliable.unreliableSequenceNumber = ENET_HOST_TO_NET_16(outgoingCommand->unreliableSequenceNumber);
		break;

	case ENET_PROTOCOL_COMMAND_SEND_OUTOFBAND_PACKET:
		outgoingCommand->command.sendUnsequenced.unsequencedGroup = ENET_HOST_TO_NET_16(peer->outgoingUnsequencedGroup);
		break;

	default:
		break;
	}

	if (outgoingCommand->command.header.command & ENET_PROTOCOL_COMMAND_FLAG_ACK) 
		enet_list_insert(enet_list_end(&peer->outgoingReliableCommands), outgoingCommand);
	else 
		enet_list_insert(enet_list_end(&peer->outgoingUnreliableCommands), outgoingCommand);
}

ENetOutgoingCommand*  enet_peer_queue_outgoing_command(ENetPeer* peer, const ENetProtocol* command, ENetPacket* packet, enet_uint32 offset, enet_uint16 length) 
{
	ENetOutgoingCommand* outgoingCommand = (ENetOutgoingCommand*)enet_malloc(sizeof(ENetOutgoingCommand));

	if (outgoingCommand == NULL)
		return NULL;

	outgoingCommand->command = *command;
	outgoingCommand->fragmentOffset = offset;
	outgoingCommand->fragmentLength = length;
	outgoingCommand->packet = packet;

	if (packet != NULL)
		++packet->referenceCount;

	enet_peer_setup_outgoing_command(peer, outgoingCommand);

	return outgoingCommand;
}

void enet_peer_dispatch_incoming_unreliable_commands(ENetPeer* peer, ENetChannel* channel)
{
	ENetListIterator droppedCommand, startCommand, currentCommand;

	for (droppedCommand = startCommand = currentCommand = enet_list_begin(&channel->incomingUnreliableCommands); currentCommand != enet_list_end(&channel->incomingUnreliableCommands); currentCommand = enet_list_next(currentCommand))
	{
		ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)currentCommand;

		if ((incomingCommand->command.header.command & ENET_PROTOCOL_COMMAND_MASK) == ENET_PROTOCOL_COMMAND_SEND_OUTOFBAND_PACKET)
			continue;

		if (incomingCommand->reliableSequenceNumber == channel->incomingReliableSequenceNumber)
		{
			if (incomingCommand->fragmentsRemaining <= 0) 
			{
                channel->incomingUnreliableSequenceNumber = incomingCommand->unreliableSequenceNumber;
				continue;
			}

			if (startCommand != currentCommand) 
			{
				enet_list_move(enet_list_end(&peer->dispatchedCommands), startCommand, enet_list_previous(currentCommand));

				if (!peer->needsDispatch) 
				{
					enet_list_insert(enet_list_end(&peer->host->dispatchQueue), &peer->dispatchList);
					peer->needsDispatch = 1;
				}

				droppedCommand = currentCommand;
			}
			else if (droppedCommand != currentCommand) 
			{
				droppedCommand = enet_list_previous(currentCommand);
			}
		}
		else 
		{
			enet_uint16 reliableWindow = incomingCommand->reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
			enet_uint16 currentWindow = channel->incomingReliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

			if (incomingCommand->reliableSequenceNumber < channel->incomingReliableSequenceNumber)
				reliableWindow += ENET_PEER_RELIABLE_WINDOWS;

			if (reliableWindow >= currentWindow && reliableWindow < currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS - 1)
				break;

			droppedCommand = enet_list_next(currentCommand);

			if (startCommand != currentCommand) 
			{
				enet_list_move(enet_list_end(&peer->dispatchedCommands), startCommand, enet_list_previous(currentCommand));

				if (!peer->needsDispatch) 
				{
					enet_list_insert(enet_list_end(&peer->host->dispatchQueue), &peer->dispatchList);
					peer->needsDispatch = 1;
				}
			}
		}

		startCommand = enet_list_next(currentCommand);
	}

	if (startCommand != currentCommand) 
	{
		enet_list_move(enet_list_end(&peer->dispatchedCommands), startCommand, enet_list_previous(currentCommand));

		if (!peer->needsDispatch) 
		{
			enet_list_insert(enet_list_end(&peer->host->dispatchQueue), &peer->dispatchList);
			peer->needsDispatch = 1;
		}

		droppedCommand = currentCommand;
	}

	enet_peer_remove_incoming_commands(enet_list_begin(&channel->incomingUnreliableCommands), droppedCommand);
}

void enet_peer_dispatch_incoming_reliable_commands(ENetPeer* peer, ENetChannel* channel) 
{
	ENetListIterator currentCommand;

	for (currentCommand = enet_list_begin(&channel->incomingReliableCommands); currentCommand != enet_list_end(&channel->incomingReliableCommands); currentCommand = enet_list_next(currentCommand))
	{
		ENetIncomingCommand* incomingCommand = (ENetIncomingCommand*)currentCommand;

		if (incomingCommand->fragmentsRemaining > 0 || incomingCommand->reliableSequenceNumber != (enet_uint16)(channel->incomingReliableSequenceNumber + 1))
			break;

        channel->incomingReliableSequenceNumber = incomingCommand->reliableSequenceNumber;

		if (incomingCommand->fragmentCount > 0)
            channel->incomingReliableSequenceNumber += incomingCommand->fragmentCount - 1;
	}

	if (currentCommand == enet_list_begin(&channel->incomingReliableCommands))
		return;

    channel->incomingUnreliableSequenceNumber = 0;
	enet_list_move(enet_list_end(&peer->dispatchedCommands), enet_list_begin(&channel->incomingReliableCommands), enet_list_previous(currentCommand));

	if (!peer->needsDispatch) 
	{
		enet_list_insert(enet_list_end(&peer->host->dispatchQueue), &peer->dispatchList);
		peer->needsDispatch = 1;
	}

	if (!enet_list_empty(&channel->incomingUnreliableCommands))
	{
		enet_peer_dispatch_incoming_unreliable_commands(peer, channel);
	}
}

ENetIncomingCommand*  enet_peer_queue_incoming_command(ENetPeer* peer, const ENetProtocol* command, const void* data, size_t dataLength, enet_uint16 flags, enet_uint16 fragmentCount) 
{
	static ENetIncomingCommand dummyCommand;

	ENetChannel* channel = &peer->channels[command->header.channelId];
	enet_uint32 unreliableSequenceNumber = 0;
	enet_uint16 reliableWindow, currentWindow, reliableSequenceNumber = 0;
	ENetIncomingCommand* incomingCommand;
	ENetListIterator currentCommand;
	ENetPacket* packet = NULL;

	if (peer->state == ENET_PEER_STATE_DISCONNECT_LATER)
		goto discardCommand;

	if ((command->header.command & ENET_PROTOCOL_COMMAND_MASK) != ENET_PROTOCOL_COMMAND_SEND_OUTOFBAND_PACKET)
	{
		reliableSequenceNumber = command->header.reliableSequenceNumber;
		reliableWindow = reliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;
		currentWindow = channel->incomingReliableSequenceNumber / ENET_PEER_RELIABLE_WINDOW_SIZE;

		if (reliableSequenceNumber < channel->incomingReliableSequenceNumber)
			reliableWindow += ENET_PEER_RELIABLE_WINDOWS;

		if (reliableWindow < currentWindow || reliableWindow >= currentWindow + ENET_PEER_FREE_RELIABLE_WINDOWS - 1)
			goto discardCommand;
	}

	switch (command->header.command & ENET_PROTOCOL_COMMAND_MASK) 
	{
	case ENET_PROTOCOL_COMMAND_SEND_RELIABLE_FRAGMENT:
	case ENET_PROTOCOL_COMMAND_SEND_RELIABLE_PACKET:
		if (reliableSequenceNumber == channel->incomingReliableSequenceNumber)
			goto discardCommand;

		for (currentCommand = enet_list_previous(enet_list_end(&channel->incomingReliableCommands)); currentCommand != enet_list_end(&channel->incomingReliableCommands); currentCommand = enet_list_previous(currentCommand))
		{
			incomingCommand = (ENetIncomingCommand*)currentCommand;

			if (reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
			{
				if (incomingCommand->reliableSequenceNumber < channel->incomingReliableSequenceNumber)
					continue;
			}
			else if (incomingCommand->reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
			{
				break;
			}

			if (incomingCommand->reliableSequenceNumber <= reliableSequenceNumber) 
			{
				if (incomingCommand->reliableSequenceNumber < reliableSequenceNumber)
					break;

				goto discardCommand;
			}
		}
		break;

	case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_PACKET:
	case ENET_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT:
		unreliableSequenceNumber = ENET_NET_TO_HOST_16(command->sendUnreliable.unreliableSequenceNumber);

		if (reliableSequenceNumber == channel->incomingReliableSequenceNumber && unreliableSequenceNumber <= channel->incomingUnreliableSequenceNumber)
			goto discardCommand;

		for (currentCommand = enet_list_previous(enet_list_end(&channel->incomingUnreliableCommands)); currentCommand != enet_list_end(&channel->incomingUnreliableCommands); currentCommand = enet_list_previous(currentCommand))
		{
			incomingCommand = (ENetIncomingCommand*)currentCommand;

			if ((command->header.command & ENET_PROTOCOL_COMMAND_MASK) == ENET_PROTOCOL_COMMAND_SEND_OUTOFBAND_PACKET)
				continue;

			if (reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
			{
				if (incomingCommand->reliableSequenceNumber < channel->incomingReliableSequenceNumber)
					continue;
			}
			else if (incomingCommand->reliableSequenceNumber >= channel->incomingReliableSequenceNumber)
			{
				break;
			}

			if (incomingCommand->reliableSequenceNumber < reliableSequenceNumber)
				break;

			if (incomingCommand->reliableSequenceNumber > reliableSequenceNumber)
				continue;

			if (incomingCommand->unreliableSequenceNumber <= unreliableSequenceNumber) 
			{
				if (incomingCommand->unreliableSequenceNumber < unreliableSequenceNumber)
					break;

				goto discardCommand;
			}
		}
		break;

	case ENET_PROTOCOL_COMMAND_SEND_OUTOFBAND_PACKET:
		currentCommand = enet_list_end(&channel->incomingUnreliableCommands);
		break;

	default:
		goto discardCommand;
	}

	if (peer->totalWaitingData >= peer->host->maximumWaitingData)
		goto notifyError;

	packet = enet_packet_create(data, dataLength, flags);

	if (packet == NULL)
		goto notifyError;

	incomingCommand = (ENetIncomingCommand*)enet_malloc(sizeof(ENetIncomingCommand));

	if (incomingCommand == NULL)
		goto notifyError;

	incomingCommand->reliableSequenceNumber = command->header.reliableSequenceNumber;
	incomingCommand->unreliableSequenceNumber = unreliableSequenceNumber & 0xFFFF;
	incomingCommand->command = *command;
	incomingCommand->fragmentCount = fragmentCount;
	incomingCommand->fragmentsRemaining = fragmentCount;
	incomingCommand->packet = packet;
	incomingCommand->fragments = NULL;

	if (fragmentCount > 0) 
	{
		if (fragmentCount <= ENET_PROTOCOL_MAXIMUM_FRAGMENT_COUNT) 
			incomingCommand->fragments = (enet_uint32*)enet_malloc((fragmentCount + 31) / 32 * sizeof(enet_uint32));

		if (incomingCommand->fragments == NULL) 
		{
			enet_free(incomingCommand);
			goto notifyError;
		}

		memset(incomingCommand->fragments, 0, (fragmentCount + 31) / 32 * sizeof(enet_uint32));
	}

	if (packet != NULL) 
	{
		++packet->referenceCount;
		peer->totalWaitingData += packet->dataLength;
	}

	enet_list_insert(enet_list_next(currentCommand), incomingCommand);

	switch (command->header.command & ENET_PROTOCOL_COMMAND_MASK) 
	{
	case ENET_PROTOCOL_COMMAND_SEND_RELIABLE_FRAGMENT:
	case ENET_PROTOCOL_COMMAND_SEND_RELIABLE_PACKET:
		enet_peer_dispatch_incoming_reliable_commands(peer, channel);
		break;

	default:
		enet_peer_dispatch_incoming_unreliable_commands(peer, channel);
		break;
	}

	return incomingCommand;

discardCommand:
	if (fragmentCount > 0) 
		goto notifyError;

	if (packet != NULL && packet->referenceCount == 0) 
		enet_packet_destroy(packet);

	return &dummyCommand;

notifyError:
	if (packet != NULL && packet->referenceCount == 0)
		enet_packet_destroy(packet);

	return NULL;
}



/**************************************************************************
 * Host
 **************************************************************************/

ENetHost* enet_host_create(const ENetAddress* localAddress, size_t peerCount, enet_uint16 channelLimit, enet_uint32 incomingBandwidth, enet_uint32 outgoingBandwidth) 
{
	if (peerCount < 1)
        peerCount = 1;

    if (peerCount > ENET_PROTOCOL_MAXIMUM_PEER_COUNT)
        peerCount ENET_PROTOCOL_MAXIMUM_PEER_COUNT;

	ENetHost* host = (ENetHost*)enet_malloc(sizeof(ENetHost));

	if (host == NULL)
		return NULL;

	memset(host, 0, sizeof(ENetHost));

	host->peers = (ENetPeer*)enet_malloc(peerCount * sizeof(ENetPeer));

	if (host->peers == NULL) 
	{
		enet_free(host);
		return NULL;
	}

	memset(host->peers, 0, peerCount * sizeof(ENetPeer));

	host->socket = enet_socket_create(ENET_SOCKET_TYPE_DATAGRAM);

	if (host->socket != ENET_SOCKET_NULL)
		enet_socket_set_option(host->socket, ENET_SOCKOPT_IPV6_V6ONLY, 0);

    // Check if socket has been created properly.
    // localAddress can be null for clients as they don't need to bind to a local port or interface.
	if (host->socket == ENET_SOCKET_NULL || (localAddress != NULL && enet_socket_bind(host->socket, localAddress) < 0))
	{
		if (host->socket != ENET_SOCKET_NULL)
			enet_socket_destroy(host->socket);

		enet_free(host->peers);
		enet_free(host);

		return NULL;
	}

	enet_socket_set_option(host->socket, ENET_SOCKOPT_NONBLOCK, 1);
	enet_socket_set_option(host->socket, ENET_SOCKOPT_BROADCAST, 1);
	enet_socket_set_option(host->socket, ENET_SOCKOPT_RCVBUF, ENET_HOST_RECEIVE_BUFFER_SIZE);
	enet_socket_set_option(host->socket, ENET_SOCKOPT_SNDBUF, ENET_HOST_SEND_BUFFER_SIZE);
	enet_socket_set_option(host->socket, ENET_SOCKOPT_IPV6_V6ONLY, 0);

	if (localAddress != NULL && enet_socket_get_address(host->socket, &host->address) < 0)
		host->address = *localAddress;

	if (channelLimit == 0 || channelLimit > ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
	{
		channelLimit = ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT;
	}
	else if (channelLimit < ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT) 
	{
		channelLimit = ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT;
	}

	host->randomSeed = (enet_uint32)(size_t)host;
	host->randomSeed += enet_host_random_seed();
	host->randomSeed = (host->randomSeed << 16) | (host->randomSeed >> 16);
	host->channelLimit = channelLimit;
	host->incomingBandwidth = incomingBandwidth;
	host->outgoingBandwidth = outgoingBandwidth;
	host->bandwidthThrottleEpoch = 0;
	host->recalculateBandwidthLimits = 0;
	host->refuseConnections = 0;
	host->mtu = ENET_HOST_DEFAULT_MTU;
	host->peerCount = peerCount;
    host->startTime = enet_time();
	host->commandCount = 0;
	host->bufferCount = 0;
	host->compressionEnabled = 0;
    host->crcEnabled = 1;
	host->receivedAddress.host = ENET_HOST_ANY;
	host->receivedAddress.port = 0;
	host->receivedData = NULL;
	host->receivedDataLength = 0;
	host->totalSentData = 0;
	host->totalSentPackets = 0;
	host->totalReceivedData = 0;
	host->totalReceivedPackets = 0;
	host->connectedPeers = 0;
	host->bandwidthLimitedPeers = 0;
	host->duplicatePeers = ENET_PROTOCOL_MAXIMUM_PEER_COUNT;
	host->maximumPacketSize = ENET_HOST_DEFAULT_MAXIMUM_PACKET_SIZE;
	host->maximumWaitingData = ENET_HOST_DEFAULT_MAXIMUM_WAITING_DATA;
	host->interceptCallback = NULL;

	enet_list_clear(&host->dispatchQueue);

	for (ENetPeer* currentPeer = host->peers; currentPeer < &host->peers[host->peerCount]; ++currentPeer) 
	{
		currentPeer->host = host;
		currentPeer->incomingPeerId = (enet_uint16)(currentPeer - host->peers);
		currentPeer->outgoingSessionId = currentPeer->incomingSessionId = 0xFF;
		currentPeer->userData = NULL;

		enet_list_clear(&currentPeer->acknowledgements);
		enet_list_clear(&currentPeer->sentReliableCommands);
		enet_list_clear(&currentPeer->sentUnreliableCommands);
		enet_list_clear(&currentPeer->outgoingReliableCommands);
		enet_list_clear(&currentPeer->outgoingUnreliableCommands);
		enet_list_clear(&currentPeer->dispatchedCommands);

		enet_peer_reset(currentPeer);
	}

	return host;
}

void enet_host_destroy(ENetHost* host) 
{
	if (host == NULL)
		return;

	enet_socket_destroy(host->socket);

	for (ENetPeer* currentPeer = host->peers; currentPeer < &host->peers[host->peerCount]; ++currentPeer)
		enet_peer_reset(currentPeer);

	enet_free(host->peers);
	enet_free(host);
}

void enet_host_set_compression_enabled(ENetHost* host, enet_uint8 value) 
{
	if (host == NULL)
		return;

	host->compressionEnabled = value;
}

enet_uint8 enet_host_get_compression_enabled(ENetHost* host)
{
    return (host == NULL) ? 0 : host->compressionEnabled;
}

void enet_host_set_crc_enabled(ENetHost* host, enet_uint8 value)
{
    if (host == NULL)
        return;

    host->crcEnabled = value;
}

enet_uint8 enet_host_get_crc_enabled(ENetHost* host)
{
    return (host == NULL) ? 0 : host->crcEnabled;
}

void enet_host_disable_crc(ENetHost* host)
{
    if (host == NULL)
        return;

    host->crcEnabled = 0;
}

void enet_host_set_refuse_connections(ENetHost* host, enet_uint8 value)
{
	if (host == NULL)
		return;

	host->refuseConnections = value;
}

enet_uint8 enet_host_get_refuse_connections(ENetHost* host)
{
    return (host == NULL) ? 0 : host->refuseConnections;
}

ENetPeer* enet_host_connect(ENetHost* host, const ENetAddress* address, enet_uint16 channelCount, enet_uint32 status)
{
	if (channelCount < ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT)
		channelCount = ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT;
	else if (channelCount > ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
		channelCount = ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT;

	ENetPeer* currentPeer;
	for (currentPeer = host->peers; currentPeer < &host->peers[host->peerCount]; ++currentPeer) 
	{
		if (currentPeer->state == ENET_PEER_STATE_DISCONNECTED)
			break;
	}

	if (currentPeer >= &host->peers[host->peerCount])
		return NULL;

	currentPeer->channels = (ENetChannel*)enet_malloc(channelCount * sizeof(ENetChannel));

	if (currentPeer->channels == NULL)
		return NULL;

	currentPeer->channelCount = channelCount;
	currentPeer->state = ENET_PEER_STATE_CONNECTING;
	currentPeer->address = *address;
	currentPeer->connectId = ++host->randomSeed;

	if (host->outgoingBandwidth == 0) 
		currentPeer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;
	else 
		currentPeer->windowSize = (host->outgoingBandwidth / ENET_PEER_WINDOW_SIZE_SCALE) * ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;

	if (currentPeer->windowSize < ENET_PROTOCOL_MINIMUM_WINDOW_SIZE) 
		currentPeer->windowSize = ENET_PROTOCOL_MINIMUM_WINDOW_SIZE;
	else if (currentPeer->windowSize > ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE) 
		currentPeer->windowSize = ENET_PROTOCOL_MAXIMUM_WINDOW_SIZE;

	for (ENetChannel* channel = currentPeer->channels; channel < &currentPeer->channels[channelCount]; ++channel)
	{
		channel->outgoingReliableSequenceNumber = 0;
		channel->outgoingUnreliableSequenceNumber = 0;
		channel->incomingReliableSequenceNumber = 0;
		channel->incomingUnreliableSequenceNumber = 0;

		enet_list_clear(&channel->incomingReliableCommands);
		enet_list_clear(&channel->incomingUnreliableCommands);

        channel->usedReliableWindows = 0;
		memset(channel->reliableWindows, 0, sizeof(channel->reliableWindows));
	}

	ENetProtocol command;
	command.header.command = ENET_PROTOCOL_COMMAND_CONNECT;
	command.header.channelId = 0xFF;

	command.connect.outgoingPeerId = ENET_HOST_TO_NET_16(currentPeer->incomingPeerId);
	command.connect.incomingSessionId = currentPeer->incomingSessionId;
	command.connect.outgoingSessionId = currentPeer->outgoingSessionId;
	command.connect.mtu = ENET_HOST_TO_NET_16(currentPeer->mtu);
	command.connect.windowSize = ENET_HOST_TO_NET_32(currentPeer->windowSize);
	command.connect.channelCount = ENET_HOST_TO_NET_16(channelCount);
	command.connect.incomingBandwidth = ENET_HOST_TO_NET_32(host->incomingBandwidth);
	command.connect.outgoingBandwidth = ENET_HOST_TO_NET_32(host->outgoingBandwidth);
	command.connect.packetThrottleInterval = ENET_HOST_TO_NET_32(currentPeer->packetThrottleInterval);
	command.connect.packetThrottleAcceleration = ENET_HOST_TO_NET_32(currentPeer->packetThrottleAcceleration);
	command.connect.packetThrottleDeceleration = ENET_HOST_TO_NET_32(currentPeer->packetThrottleDeceleration);
	command.connect.connectId = currentPeer->connectId;
	command.connect.status = ENET_HOST_TO_NET_32(status);

	enet_peer_queue_outgoing_command(currentPeer, &command, NULL, 0, 0);

	return currentPeer;
}

void enet_host_broadcast(ENetHost* host, enet_uint8 channelId, ENetPacket* packet) 
{
	for (ENetPeer* currentPeer = host->peers; currentPeer < &host->peers[host->peerCount]; ++currentPeer) 
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;

		enet_peer_send(currentPeer, channelId, packet);
	}

	if (packet->referenceCount == 0)
		enet_packet_destroy(packet);
}

void enet_host_set_channel_limit(ENetHost* host, enet_uint16 channelLimit)
{
	if (channelLimit == 0 || channelLimit > ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT) 
	{
		channelLimit = ENET_PROTOCOL_MAXIMUM_CHANNEL_COUNT;
	}
	else if (channelLimit < ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT)
	{
		channelLimit = ENET_PROTOCOL_MINIMUM_CHANNEL_COUNT;
	}

	host->channelLimit = channelLimit;
}

enet_uint16 enet_host_get_channel_limit(ENetHost* host)
{
    return host->channelLimit;
}

void enet_host_bandwidth_limit(ENetHost* host, enet_uint32 incomingBandwidth, enet_uint32 outgoingBandwidth) 
{
	host->incomingBandwidth = incomingBandwidth;
	host->outgoingBandwidth = outgoingBandwidth;
	host->recalculateBandwidthLimits = 1;
}

void enet_host_bandwidth_throttle(ENetHost* host) 
{
	const enet_uint32 timeCurrent = (enet_uint32)enet_time();
	const enet_uint32 elapsedTime = timeCurrent - host->bandwidthThrottleEpoch;

	if (elapsedTime < ENET_HOST_BANDWIDTH_THROTTLE_INTERVAL)
		return;

	if (host->outgoingBandwidth == 0 && host->incomingBandwidth == 0)
		return;

	host->bandwidthThrottleEpoch = timeCurrent;

	enet_uint32 peersRemaining = (enet_uint32)host->connectedPeers;
	if (peersRemaining == 0)
		return;

	enet_uint32 dataTotal = 0xFFFFFFFFUL;
	enet_uint32 bandwidth = 0xFFFFFFFFUL;
	enet_uint32 throttle = 0;
	enet_uint32 bandwidthLimit = 0;

	bool needsAdjustment = host->bandwidthLimitedPeers > 0 ? true : false;

	if (host->outgoingBandwidth != 0) 
	{
		dataTotal = 0;
		bandwidth = (host->outgoingBandwidth * elapsedTime) / 1000;

		for (ENetPeer* peer = host->peers; peer < &host->peers[host->peerCount]; ++peer) 
		{
			if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER) 
				continue;

			dataTotal += peer->outgoingDataTotal;
		}
	}

	while (peersRemaining > 0 && needsAdjustment) 
	{
		needsAdjustment = false;

		if (dataTotal <= bandwidth)
			throttle = ENET_PEER_PACKET_THROTTLE_SCALE;
		else 
			throttle = (bandwidth * ENET_PEER_PACKET_THROTTLE_SCALE) / dataTotal;

		for (ENetPeer* peer = host->peers; peer < &host->peers[host->peerCount]; ++peer) 
		{
			if ((peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER) 
				|| peer->incomingBandwidth == 0 
				|| peer->outgoingBandwidthThrottleEpoch == timeCurrent) 
			{
				continue;
			}

			enet_uint32 peerBandwidth = (peer->incomingBandwidth * elapsedTime) / 1000;

			if ((throttle * peer->outgoingDataTotal) / ENET_PEER_PACKET_THROTTLE_SCALE <= peerBandwidth)
				continue;

			peer->packetThrottleLimit = (peerBandwidth * ENET_PEER_PACKET_THROTTLE_SCALE) / peer->outgoingDataTotal;

			if (peer->packetThrottleLimit == 0)
				peer->packetThrottleLimit = 1;

			if (peer->packetThrottle > peer->packetThrottleLimit)
				peer->packetThrottle = peer->packetThrottleLimit;

			peer->outgoingBandwidthThrottleEpoch = timeCurrent;

			peer->incomingDataTotal = 0;
			peer->outgoingDataTotal = 0;

			needsAdjustment = true;
			--peersRemaining;
			bandwidth -= peerBandwidth;
			dataTotal -= peerBandwidth;
		}
	}

	if (peersRemaining > 0) 
	{
		if (dataTotal <= bandwidth) 
			throttle = ENET_PEER_PACKET_THROTTLE_SCALE;
		else 
			throttle = (bandwidth * ENET_PEER_PACKET_THROTTLE_SCALE) / dataTotal;

		for (ENetPeer* peer = host->peers; peer < &host->peers[host->peerCount]; ++peer)
		{
			if ((peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER) || peer->outgoingBandwidthThrottleEpoch == timeCurrent) 
				continue;

			peer->packetThrottleLimit = throttle;

			if (peer->packetThrottle > peer->packetThrottleLimit)
				peer->packetThrottle = peer->packetThrottleLimit;

			peer->incomingDataTotal = 0;
			peer->outgoingDataTotal = 0;
		}
	}

	if (host->recalculateBandwidthLimits) 
	{
		host->recalculateBandwidthLimits = 0;

		peersRemaining = (enet_uint32)host->connectedPeers;
		bandwidth = host->incomingBandwidth;
		needsAdjustment = true;

		if (bandwidth == 0) 
		{
			bandwidthLimit = 0;
		}
		else 
		{
			while (peersRemaining > 0 && needsAdjustment) 
			{
				needsAdjustment = false;
				bandwidthLimit = bandwidth / peersRemaining;

				for (ENetPeer* peer = host->peers; peer < &host->peers[host->peerCount]; ++peer) 
				{
					if ((peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER) 
						|| peer->incomingBandwidthThrottleEpoch == timeCurrent)
						continue;

					if (peer->outgoingBandwidth > 0 && peer->outgoingBandwidth >= bandwidthLimit)
						continue;

					peer->incomingBandwidthThrottleEpoch = timeCurrent;

					needsAdjustment = true;
					--peersRemaining;
					bandwidth -= peer->outgoingBandwidth;
				}
			}
		}

		for (ENetPeer* peer = host->peers; peer < &host->peers[host->peerCount]; ++peer) 
		{
			if (peer->state != ENET_PEER_STATE_CONNECTED && peer->state != ENET_PEER_STATE_DISCONNECT_LATER)
				continue;

			ENetProtocol command;
			command.header.command = ENET_PROTOCOL_COMMAND_BANDWIDTH_LIMIT | ENET_PROTOCOL_COMMAND_FLAG_ACK;
			command.header.channelId = 0xFF;
			command.bandwidthLimit.outgoingBandwidth = ENET_HOST_TO_NET_32(host->outgoingBandwidth);

			if (peer->incomingBandwidthThrottleEpoch == timeCurrent)
				command.bandwidthLimit.incomingBandwidth = ENET_HOST_TO_NET_32(peer->outgoingBandwidth);
			else
				command.bandwidthLimit.incomingBandwidth = ENET_HOST_TO_NET_32(bandwidthLimit);

			enet_peer_queue_outgoing_command(peer, &command, NULL, 0, 0);
		}
	}
}



/**************************************************************************
 * Time
 **************************************************************************/
	
#ifdef _WIN32
static LARGE_INTEGER getFILETIMEoffset() 
{
	SYSTEMTIME s;
	FILETIME f;
	LARGE_INTEGER t;

	s.wYear = 1970;
	s.wMonth = 1;
	s.wDay = 1;
	s.wHour = 0;
	s.wMinute = 0;
	s.wSecond = 0;
	s.wMilliseconds = 0;
	SystemTimeToFileTime(&s, &f);
	t.QuadPart = f.dwHighDateTime;
	t.QuadPart <<= 32;
	t.QuadPart |= f.dwLowDateTime;

	return (t);
}

#pragma warning(disable: 4100) /* unreferenced formal parameter */
int clock_gettime(int X, struct timespec* tv) 
{
	LARGE_INTEGER t;
	FILETIME f;
	double microseconds;

	static LARGE_INTEGER offset;
	static double frequencyToMicroseconds;
	static int initialized = 0;
	static BOOL usePerformanceCounter = 0;

	if (!initialized) 
	{
		LARGE_INTEGER performanceFrequency;
		initialized = 1;
		usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);

		if (usePerformanceCounter) 
		{
			QueryPerformanceCounter(&offset);
			frequencyToMicroseconds = (double)performanceFrequency.QuadPart / 1000000.;
		}
		else 
		{
			offset = getFILETIMEoffset();
			frequencyToMicroseconds = 10.;
		}
	}

	if (usePerformanceCounter) 
	{
		QueryPerformanceCounter(&t);
	}
	else 
	{
		GetSystemTimeAsFileTime(&f);

		t.QuadPart = f.dwHighDateTime;
		t.QuadPart <<= 32;
		t.QuadPart |= f.dwLowDateTime;
	}

	t.QuadPart -= offset.QuadPart;
	microseconds = (double)t.QuadPart / frequencyToMicroseconds;
	t.QuadPart = (LONGLONG)microseconds;
	tv->tv_sec = (long)(t.QuadPart / 1000000);
	tv->tv_nsec = t.QuadPart % 1000000 * 1000;

	return (0);
}
#pragma warning(default: 4100) /* unreferenced formal parameter */
#elif __APPLE__ && __MAC_OS_X_VERSION_MIN_REQUIRED < 101200
#define CLOCK_MONOTONIC 0

int clock_gettime(int X, struct timespec *ts) 
{
	clock_serv_t cclock;
	mach_timespec_t mts;

	host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
	clock_get_time(cclock, &mts);
	mach_port_deallocate(mach_task_self(), cclock);

	ts->tv_sec = mts.tv_sec;
	ts->tv_nsec = mts.tv_nsec;

	return 0;
}
#endif

enet_uint64 enet_time()
{
	static enet_uint64 start_time_ns = 0;

	struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
	clock_gettime(CLOCK_MONOTONIC, &ts);
#endif

	static const enet_uint64 ns_in_s = 1000 * 1000 * 1000;
	static const enet_uint64 ns_in_ms = 1000 * 1000;

	enet_uint64 current_time_ns = ts.tv_nsec + (enet_uint64)ts.tv_sec * ns_in_s;
	enet_uint64 offset_ns = ENET_ATOMIC_READ(&start_time_ns);

	if (offset_ns == 0) 
	{
		enet_uint64 want_value = current_time_ns - 1 * ns_in_ms;
		enet_uint64 old_value = ENET_ATOMIC_CAS(&start_time_ns, 0, want_value);

		offset_ns = old_value == 0 ? want_value : old_value;
	}

	enet_uint64 result_in_ns = current_time_ns - offset_ns;

	return result_in_ns / ns_in_ms;
}



/**************************************************************************
 * Extended functionality
 **************************************************************************/

void*  enet_packet_get_data(ENetPacket* packet) 
{
	return (void*)packet->data;
}

int enet_packet_get_length(ENetPacket* packet)
{
	return (int)packet->dataLength;
}

void enet_packet_set_free_callback(ENetPacket* packet, const void* callback) 
{
	packet->freeCallback = (ENetPacketFreeCallback)callback;
}

void enet_packet_dispose(ENetPacket* packet) 
{
	if (packet->referenceCount == 0) 
		enet_packet_destroy(packet);
}

ENetPeer* enet_host_get_peer(ENetHost* host, enet_uint32 index)
{
    return index < host->connectedPeers ? &host->peers[index] : NULL;
}

enet_uint32 enet_host_get_peers_count(ENetHost* host) 
{
	return host->connectedPeers;
}

enet_uint32 enet_host_get_peers_capacity(ENetHost* host)
{
    return host->peerCount;
}

enet_uint64 enet_host_get_packets_sent(ENetHost* host) 
{
	return host->totalSentPackets;
}

enet_uint64 enet_host_get_packets_received(ENetHost* host) 
{
	return host->totalReceivedPackets;
}

enet_uint64 enet_host_get_bytes_sent(ENetHost* host) 
{
	return host->totalSentData;
}

enet_uint64 enet_host_get_bytes_received(ENetHost* host) 
{
	return host->totalReceivedData;
}

enet_uint32 enet_peer_get_id(ENetPeer* peer) 
{
	return peer->connectId;
}

int enet_peer_get_ip(ENetPeer* peer, char* ip, size_t length)
{
	return enet_address_get_ip(&peer->address, ip, length);
}

int enet_peer_get_name(ENetPeer* peer, char* name, size_t length)
{
    return enet_address_get_name(&peer->address, name, length);
}

enet_uint16 enet_peer_get_port(ENetPeer* peer) 
{
	return peer->address.port;
}

enet_uint16 enet_peer_get_mtu(ENetPeer* peer) 
{
	return peer->mtu;
}

ENetPeerState enet_peer_get_state(ENetPeer* peer) 
{
	return peer->state;
}

enet_uint32 enet_peer_get_rtt(ENetPeer* peer) 
{
	return peer->smoothedRoundTripTime;
}

enet_uint32 enet_peer_get_lastsendtime(ENetPeer* peer) 
{
	return peer->lastSendTime;
}

enet_uint32 enet_peer_get_lastreceivetime(ENetPeer* peer) 
{
	return peer->lastReceiveTime;
}

enet_uint64 enet_peer_get_packets_sent(ENetPeer* peer) 
{
	return peer->totalPacketsSent;
}

enet_uint64 enet_peer_get_packets_lost(ENetPeer* peer) 
{
	return peer->totalPacketsLost;
}

enet_uint64 enet_peer_get_bytes_sent(ENetPeer* peer) 
{
	return peer->totalDataSent;
}

enet_uint64 enet_peer_get_bytes_received(ENetPeer* peer) 
{
	return peer->totalDataReceived;
}

void*  enet_peer_get_userdata(ENetPeer* peer) 
{
	return (void*)peer->userData;
}

void enet_peer_set_userdata(ENetPeer* peer, const void* data) 
{
	peer->userData = (enet_uint32*)data;
}

enet_uint16 enet_peer_get_channel_count(ENetPeer* peer)
{
    return peer->channelCount;
}

	
/**************************************************************************
 * Platform Specific (Unix)
 **************************************************************************/

#ifndef _WIN32
int enet_initialize(void) 
{
	return 0;
}

void enet_finalize(void) { }

enet_uint32 enet_host_random_seed(void) 
{
	return (enet_uint32)time(NULL);
}

int enet_address_set_host_ip(ENetAddress* address, const char* name) 
{
	if (!inet_pton(AF_INET6, name, &address->host)) 
		return -1;

	return 0;
}

int enet_address_set_host(ENetAddress* address, const char* name) 
{
	struct addrinfo hints, *resultList = NULL, *result = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;

	if (getaddrinfo(name, NULL, &hints, &resultList) != 0) 
		return -1;

	for (result = resultList; result != NULL; result = result->ai_next) 
	{
		if (result->ai_addr != NULL && result->ai_addrlen >= sizeof(struct sockaddr_in)) 
		{
			if (result->ai_family == AF_INET) 
			{
				struct sockaddr_in*  sin = (struct sockaddr_in*)result->ai_addr;

				((uint32_t*)&address->host.s6_addr)[0] = 0;
				((uint32_t*)&address->host.s6_addr)[1] = 0;
				((uint32_t*)&address->host.s6_addr)[2] = htonl(0xffff);
				((uint32_t*)&address->host.s6_addr)[3] = sin->sin_addr.s_addr;

				freeaddrinfo(resultList);

				return 0;
			}
			else if (result->ai_family == AF_INET6) 
			{
				struct sockaddr_in6*  sin = (struct sockaddr_in6*)result->ai_addr;

				address->host = sin->sin6_addr;
				address->sin6_scope_id = sin->sin6_scope_id;

				freeaddrinfo(resultList);

				return 0;
			}
		}
	}

	if (resultList != NULL) 
		freeaddrinfo(resultList);

	return enet_address_set_host_ip(address, name);
}

int enet_address_get_host_ip(const ENetAddress* address, char* name, size_t nameLength) 
{
	if (inet_ntop(AF_INET6, &address->host, name, nameLength) == NULL) 
		return -1;

	return 0;
}

int enet_address_get_host_name(const ENetAddress* address, char* name, size_t nameLength) 
{
	struct sockaddr_in6 sin;
	int err;

	memset(&sin, 0, sizeof(struct sockaddr_in6));

	sin.sin6_family = AF_INET6;
	sin.sin6_port = ENET_HOST_TO_NET_16(address->port);
	sin.sin6_addr = address->host;
	sin.sin6_scope_id = address->sin6_scope_id;

	err = getnameinfo((struct sockaddr*)&sin, sizeof(sin), name, nameLength, NULL, 0, NI_NAMEREQD);

	if (!err) 
	{
		if (name != NULL && nameLength > 0 && !memchr(name, '\0', nameLength)) 
			return -1;

		return 0;
	}

	if (err != EAI_NONAME) 
		return -1;

	return enet_address_get_host_ip(address, name, nameLength);
}

int enet_socket_bind(ENetSocket socket, const ENetAddress* address) 
{
	struct sockaddr_in6 sin;
	memset(&sin, 0, sizeof(struct sockaddr_in6));

	sin.sin6_family = AF_INET6;

	if (address != NULL) 
	{
		sin.sin6_port = ENET_HOST_TO_NET_16(address->port);
		sin.sin6_addr = address->host;
		sin.sin6_scope_id = address->sin6_scope_id;
	}
	else 
	{
		sin.sin6_port = 0;
		sin.sin6_addr = ENET_HOST_ANY;
		sin.sin6_scope_id = 0;
	}

	return bind(socket, (struct sockaddr*)&sin, sizeof(struct sockaddr_in6));
}

int enet_socket_get_address(ENetSocket socket, ENetAddress* address) 
{
	struct sockaddr_in6 sin;
	socklen_t sinLength = sizeof(struct sockaddr_in6);

	if (getsockname(socket, (struct sockaddr*)&sin, &sinLength) == -1) 
		return -1;

	address->host = sin.sin6_addr;
	address->port = ENET_NET_TO_HOST_16(sin.sin6_port);
	address->sin6_scope_id = sin.sin6_scope_id;

	return 0;
}

int enet_socket_listen(ENetSocket socket, int backlog) 
{
	return listen(socket, backlog < 0 ? SOMAXCONN : backlog);
}

ENetSocket enet_socket_create(ENetSocketType type) 
{
	return socket(PF_INET6, type == ENET_SOCKET_TYPE_DATAGRAM ? SOCK_DGRAM : SOCK_STREAM, 0);
}

int enet_socket_set_option(ENetSocket socket, ENetSocketOption option, int value) 
{
	int result = -1;

	switch (option) 
	{
	case ENET_SOCKOPT_NONBLOCK:
		result = fcntl(socket, F_SETFL, (value ? O_NONBLOCK : 0) | (fcntl(socket, F_GETFL) & ~O_NONBLOCK));
		break;

	case ENET_SOCKOPT_BROADCAST:
		result = setsockopt(socket, SOL_SOCKET, SO_BROADCAST, (char*)&value, sizeof(int));
		break;

	case ENET_SOCKOPT_REUSEADDR:
		result = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char*)&value, sizeof(int));
		break;

	case ENET_SOCKOPT_RCVBUF:
		result = setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (char*)&value, sizeof(int));
		break;

	case ENET_SOCKOPT_SNDBUF:
		result = setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (char*)&value, sizeof(int));
		break;

	case ENET_SOCKOPT_RCVTIMEO: 
	{
		struct timeval timeVal;
		timeVal.tv_sec = value / 1000;
		timeVal.tv_usec = (value % 1000) * 1000;
		result = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeVal, sizeof(struct timeval));
		break;
	}

	case ENET_SOCKOPT_SNDTIMEO: 
	{
		struct timeval timeVal;
		timeVal.tv_sec = value / 1000;
		timeVal.tv_usec = (value % 1000) * 1000;
		result = setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeVal, sizeof(struct timeval));
		break;
	}

	case ENET_SOCKOPT_NODELAY:
		result = setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char*)&value, sizeof(int));
		break;

	case ENET_SOCKOPT_IPV6_V6ONLY:
		result = setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&value, sizeof(int));
		break;

	default:
		break;
	}

	return result == -1 ? -1 : 0;
}

int enet_socket_get_option(ENetSocket socket, ENetSocketOption option, int* value) 
{
	int result = -1;
	socklen_t len;

	switch (option) 
	{
	case ENET_SOCKOPT_ERROR:
		len = sizeof(int);
		result = getsockopt(socket, SOL_SOCKET, SO_ERROR, value, &len);
		break;

	default:
		break;
	}

	return result == -1 ? -1 : 0;
}

int enet_socket_connect(ENetSocket socket, const ENetAddress* address) 
{
	struct sockaddr_in6 sin;
	int result;

	memset(&sin, 0, sizeof(struct sockaddr_in6));

	sin.sin6_family = AF_INET6;
	sin.sin6_port = ENET_HOST_TO_NET_16(address->port);
	sin.sin6_addr = address->host;
	sin.sin6_scope_id = address->sin6_scope_id;

	result = connect(socket, (struct sockaddr*)&sin, sizeof(struct sockaddr_in6));

	if (result == -1 && errno == EINPROGRESS) 
		return 0;

	return result;
}

ENetSocket enet_socket_accept(ENetSocket socket, ENetAddress* address) 
{
	int result;
	struct sockaddr_in6 sin;
	socklen_t sinLength = sizeof(struct sockaddr_in6);

	result = accept(socket, address != NULL ? (struct sockaddr*)&sin : NULL, address != NULL ? &sinLength : NULL);

	if (result == -1) 
		return ENET_SOCKET_NULL;

	if (address != NULL) 
	{
		address->host = sin.sin6_addr;
		address->port = ENET_NET_TO_HOST_16(sin.sin6_port);
		address->sin6_scope_id = sin.sin6_scope_id;
	}

	return result;
}

int enet_socket_shutdown(ENetSocket socket, ENetSocketShutdown how) 
{
	return shutdown(socket, (int)how);
}

void enet_socket_destroy(ENetSocket socket) 
{
	if (socket != -1) 
		close(socket);
}

int enet_socket_send(ENetSocket socket, const ENetAddress* address, const ENetBuffer* buffers, size_t bufferCount) 
{
	struct msghdr msgHdr;
	struct sockaddr_in6 sin;
	int sentLength;

	memset(&msgHdr, 0, sizeof(struct msghdr));

	if (address != NULL) 
	{
		memset(&sin, 0, sizeof(struct sockaddr_in6));

		sin.sin6_family = AF_INET6;
		sin.sin6_port = ENET_HOST_TO_NET_16(address->port);
		sin.sin6_addr = address->host;
		sin.sin6_scope_id = address->sin6_scope_id;

		msgHdr.msg_name = &sin;
		msgHdr.msg_namelen = sizeof(struct sockaddr_in6);
	}

	msgHdr.msg_iov = (struct iovec*)buffers;
	msgHdr.msg_iovlen = bufferCount;

	sentLength = sendmsg(socket, &msgHdr, MSG_NOSIGNAL);

	if (sentLength == -1) 
	{
		if (errno == EWOULDBLOCK) 
			return 0;

		return -1;
	}

	return sentLength;
}

int enet_socket_receive(ENetSocket socket, ENetAddress* address, ENetBuffer* buffers, size_t bufferCount) 
{
	struct msghdr msgHdr;
	struct sockaddr_in6 sin;
	int recvLength;

	memset(&msgHdr, 0, sizeof(struct msghdr));

	if (address != NULL) 
	{
		msgHdr.msg_name = &sin;
		msgHdr.msg_namelen = sizeof(struct sockaddr_in6);
	}

	msgHdr.msg_iov = (struct iovec*)buffers;
	msgHdr.msg_iovlen = bufferCount;

	recvLength = recvmsg(socket, &msgHdr, MSG_NOSIGNAL);

	if (recvLength == -1) 
	{
		if (errno == EWOULDBLOCK) 
			return 0;

		return -1;
	}

	if (msgHdr.msg_flags & MSG_TRUNC) 
		return -1;

	if (address != NULL) 
	{
		address->host = sin.sin6_addr;
		address->port = ENET_NET_TO_HOST_16(sin.sin6_port);
		address->sin6_scope_id = sin.sin6_scope_id;
	}

	return recvLength;
}

int enet_socket_select(ENetSocket maxSocket, ENetSocketSet* readSet, ENetSocketSet* writeSet, enet_uint32 timeout) 
{
	struct timeval timeVal;

	timeVal.tv_sec = timeout / 1000;
	timeVal.tv_usec = (timeout % 1000) * 1000;

	return select(maxSocket + 1, readSet, writeSet, NULL, &timeVal);
}

int enet_socket_wait(ENetSocket socket, enet_uint32* condition, enet_uint64 timeout) 
{
	struct pollfd pollSocket;
	int pollCount;

	pollSocket.fd = socket;
	pollSocket.events = 0;

	if (*condition & ENET_SOCKET_WAIT_SEND) 
		pollSocket.events |= POLLOUT;

	if (*condition & ENET_SOCKET_WAIT_RECEIVE) 
		pollSocket.events |= POLLIN;

	pollCount = poll(&pollSocket, 1, timeout);

	if (pollCount < 0) 
	{
		if (errno == EINTR && *condition & ENET_SOCKET_WAIT_INTERRUPT) 
		{
			*condition = ENET_SOCKET_WAIT_INTERRUPT;
			return 0;
		}

		return -1;
	}

	*condition = ENET_SOCKET_WAIT_NONE;

	if (pollCount == 0) 
		return 0;

	if (pollSocket.revents & POLLOUT) 
		*condition |= ENET_SOCKET_WAIT_SEND;

	if (pollSocket.revents & POLLIN) 
		*condition |= ENET_SOCKET_WAIT_RECEIVE;

	return 0;
}
#endif


/**************************************************************************
 * Platform Specific (Windows)
 **************************************************************************/

#ifdef _WIN32
#ifdef __MINGW32__
	const char* inet_ntop(int af, const void* src, char* dst, socklen_t cnt) 
	{
		if (af == AF_INET) 
		{
			struct sockaddr_in in;
			memset(&in, 0, sizeof(in));
			in.sin_family = AF_INET;
			memcpy(&in.sin_addr, src, sizeof(struct in_addr));
			getnameinfo((struct sockaddr*)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);

			return dst;
		}
		else if (af == AF_INET6) 
		{
			struct sockaddr_in6 in;
			memset(&in, 0, sizeof(in));
			in.sin6_family = AF_INET6;
			memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
			getnameinfo((struct sockaddr*)&in, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);

			return dst;
		}

		return NULL;
	}

#define NS_INADDRSZ  4
#define NS_IN6ADDRSZ 16
#define NS_INT16SZ   2

int inet_pton4(const char* src, char* dst) 
{
	uint8_t tmp[NS_INADDRSZ], *tp;

	int saw_digit = 0;
	int octets = 0;
	*(tp = tmp) = 0;

	int ch;

	while ((ch = *src++) != '\0') 
	{
		if (ch >= '0' && ch <= '9') 
		{
			uint32_t n = *tp * 10 + (ch - '0');

			if (saw_digit && *tp == 0)
				return 0;

			if (n > 255)
				return 0;

			*tp = n;

			if (!saw_digit) {
				if (++octets > 4)
					return 0;

				saw_digit = 1;
			}
		}
		else if (ch == '.' && saw_digit) 
		{
			if (octets == 4)
				return 0;

			*++tp = 0;
			saw_digit = 0;
		}
		else
			return 0;
	}
	if (octets < 4)
		return 0;

	memcpy(dst, tmp, NS_INADDRSZ);

	return 1;
}

int inet_pton6(const char* src, char* dst) 
{
	static const char xdigits[] = "0123456789abcdef";
	uint8_t tmp[NS_IN6ADDRSZ];

	uint8_t* tp = (uint8_t*)memset(tmp, '\0', NS_IN6ADDRSZ);
	uint8_t* endp = tp + NS_IN6ADDRSZ;
	uint8_t* colonp = NULL;

	/* Leading :: requires some special handling. */
	if (*src == ':') 
	{
		if (*++src != ':')
			return 0;
	}

	const char* curtok = src;
	int saw_xdigit = 0;
	uint32_t val = 0;
	int ch;

	while ((ch = tolower(*src++)) != '\0') 
	{
		const char* pch = strchr(xdigits, ch);

		if (pch != NULL) 
		{
			val <<= 4;
			val |= (pch - xdigits);

			if (val > 0xffff)
				return 0;

			saw_xdigit = 1;

			continue;
		}

		if (ch == ':') 
		{
			curtok = src;
			if (!saw_xdigit) 
			{
				if (colonp)
					return 0;

				colonp = tp;

				continue;
			}
			else if (*src == '\0') 
			{
				return 0;
			}

			if (tp + NS_INT16SZ > endp)
				return 0;

			*tp++ = (uint8_t)(val >> 8) & 0xff;
			*tp++ = (uint8_t)val & 0xff;
			saw_xdigit = 0;
			val = 0;

			continue;
		}

		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) && inet_pton4(curtok, (char*)tp) > 0) 
		{
			tp += NS_INADDRSZ;
			saw_xdigit = 0;

			break; /* '\0' was seen by inet_pton4(). */
		}

		return 0;
	}

	if (saw_xdigit) 
	{
		if (tp + NS_INT16SZ > endp)
			return 0;

		*tp++ = (uint8_t)(val >> 8) & 0xff;
		*tp++ = (uint8_t)val & 0xff;
	}

	if (colonp != NULL) 
	{
		/*
			* Since some memmove()'s erroneously fail to handle
			* overlapping regions, we'll do the shift by hand.
			*/
		const int n = tp - colonp;

		if (tp == endp)
			return 0;

		for (int i = 1; i <= n; i++) 
		{
			endp[-i] = colonp[n - i];
			colonp[n - i] = 0;
		}

		tp = endp;
	}

	if (tp != endp)
		return 0;

	memcpy(dst, tmp, NS_IN6ADDRSZ);

	return 1;
}

int inet_pton(int af, const char* src, struct in6_addr* dst) 
{
	switch (af) 
	{
	case AF_INET: return inet_pton4(src, (char*)dst);
	case AF_INET6: return inet_pton6(src, (char*)dst);
	default: return -1;
	}
}
#endif

	int enet_initialize(void) 
	{
		WORD versionRequested = MAKEWORD(1, 1);
		WSADATA wsaData;

		if (WSAStartup(versionRequested, &wsaData))
			return -1;

		if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1) 
		{
			WSACleanup();
			return -1;
		}

		timeBeginPeriod(1);

		return 0;
	}

	void enet_finalize(void) 
	{
		timeEndPeriod(1);
		WSACleanup();
	}

	enet_uint32 enet_host_random_seed(void) 
	{
		return (enet_uint32)timeGetTime();
	}

	int enet_address_set_ip(ENetAddress* address, const char* name) 
	{
		enet_uint8 vals[4] = {0, 0, 0, 0};

		for (int i = 0; i < 4; ++i) 
		{
			const char* next = name + 1;

			if (*name != '0') 
			{
				long val = strtol(name, (char**)&next, 10);

				if (val < 0 || val > 255 || next == name || next - name > 3)
					return -1;

				vals[i] = (enet_uint8)val;
			}

			if (*next != (i < 3 ? '.' : '\0')) 
				return -1;

			name = next + 1;
		}

		memcpy(&address->host, vals, sizeof(enet_uint32));

		return 0;
	}

	int enet_address_set_name(ENetAddress* address, const char* name) 
	{
		struct hostent* hostEntry = gethostbyname(name);

		if (hostEntry == NULL || hostEntry->h_addrtype != AF_INET) 
		{
			if (!inet_pton(AF_INET6, name, &address->host))
				return -1;

			return 0;
		}

		((enet_uint32*)&address->host.s6_addr)[0] = 0;
		((enet_uint32*)&address->host.s6_addr)[1] = 0;
		((enet_uint32*)&address->host.s6_addr)[2] = htonl(0xffff);
		((enet_uint32*)&address->host.s6_addr)[3] = *(enet_uint32*)hostEntry->h_addr_list[0];

		return 0;
	}

	int enet_address_get_ip(const ENetAddress *address, char* name, size_t nameLength)
	{
		if (inet_ntop(AF_INET6, (PVOID)&address->host, name, nameLength) == NULL)
			return -1;

		return 0;
	}

	int enet_address_get_name(const ENetAddress* address, char* name, size_t nameLength)
	{
		struct in6_addr in = address->host;
		struct hostent* hostEntry = gethostbyaddr((char*)&in, sizeof(struct in6_addr), AF_INET6);

		if (hostEntry == NULL) 
		{
			return enet_address_get_ip(address, name, nameLength);
		}
		else 
		{
			size_t hostLen = strlen(hostEntry->h_name);
			if (hostLen >= nameLength)
				return -1;

			memcpy(name, hostEntry->h_name, hostLen + 1);
		}

		return 0;
	}

	int enet_socket_bind(ENetSocket socket, const ENetAddress* address) 
	{
		struct sockaddr_in6 sin;
		memset(&sin, 0, sizeof(struct sockaddr_in6));

		sin.sin6_family = AF_INET6;

		if (address != NULL) 
		{
			sin.sin6_port = ENET_HOST_TO_NET_16(address->port);
			sin.sin6_addr = address->host;
			sin.sin6_scope_id = address->scope_id;
		}
		else 
		{
			sin.sin6_port = 0;
			sin.sin6_addr = in6addr_any;
			sin.sin6_scope_id = 0;
		}

		return (bind(socket, (struct sockaddr*)&sin, sizeof(struct sockaddr_in6)) == SOCKET_ERROR) ? -1 : 0;
	}

	int enet_socket_get_address(ENetSocket socket, ENetAddress* address) 
	{
		struct sockaddr_in6 sin;
		int sinLength = sizeof(struct sockaddr_in6);

		if (getsockname(socket, (struct sockaddr*)&sin, &sinLength) == -1)
			return -1;

		address->host = sin.sin6_addr;
		address->port = ENET_NET_TO_HOST_16(sin.sin6_port);
		address->scope_id = sin.sin6_scope_id;

		return 0;
	}

	int enet_socket_listen(ENetSocket socket, int backlog) 
	{
		return listen(socket, backlog < 0 ? SOMAXCONN : backlog) == SOCKET_ERROR ? -1 : 0;
	}

	ENetSocket enet_socket_create(ENetSocketType type) 
	{
		return socket(PF_INET6, type == ENET_SOCKET_TYPE_DATAGRAM ? SOCK_DGRAM : SOCK_STREAM, 0);
	}

	int enet_socket_set_option(ENetSocket socket, ENetSocketOption option, int value) 
	{
		int result = SOCKET_ERROR;

		switch (option) 
		{
		case ENET_SOCKOPT_NONBLOCK: 
		{
			u_long nonBlocking = (u_long)value;
			result = ioctlsocket(socket, FIONBIO, &nonBlocking);
			break;
		}

		case ENET_SOCKOPT_BROADCAST:
			result = setsockopt(socket, SOL_SOCKET, SO_BROADCAST, (char*)&value, sizeof(int));
			break;

		case ENET_SOCKOPT_REUSEADDR:
			result = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, (char*)&value, sizeof(int));
			break;

		case ENET_SOCKOPT_RCVBUF:
			result = setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (char*)&value, sizeof(int));
			break;

		case ENET_SOCKOPT_SNDBUF:
			result = setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (char*)&value, sizeof(int));
			break;

		case ENET_SOCKOPT_RCVTIMEO:
			result = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&value, sizeof(int));
			break;

		case ENET_SOCKOPT_SNDTIMEO:
			result = setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&value, sizeof(int));
			break;

		case ENET_SOCKOPT_NODELAY:
			result = setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, (char*)&value, sizeof(int));
			break;

		case ENET_SOCKOPT_IPV6_V6ONLY:
			result = setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&value, sizeof(int));
			break;

		default:
			break;
		}
		return result == SOCKET_ERROR ? -1 : 0;
	}

	int enet_socket_get_option(ENetSocket socket, ENetSocketOption option, int* value) 
	{
		int result = SOCKET_ERROR, len;

		switch (option) 
		{
		case ENET_SOCKOPT_ERROR:
			len = sizeof(int);
			result = getsockopt(socket, SOL_SOCKET, SO_ERROR, (char*)value, &len);
			break;

		default:
			break;
		}
		return result == SOCKET_ERROR ? -1 : 0;
	}

	int enet_socket_connect(ENetSocket socket, const ENetAddress* address)
	{
		struct sockaddr_in6 sin;
		memset(&sin, 0, sizeof(struct sockaddr_in6));

		sin.sin6_family = AF_INET6;
		sin.sin6_port = ENET_HOST_TO_NET_16(address->port);
		sin.sin6_addr = address->host;
		sin.sin6_scope_id = address->scope_id;

		int result = connect(socket, (struct sockaddr*)&sin, sizeof(struct sockaddr_in6));

		if (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
			return -1;
		}

		return 0;
	}

	ENetSocket enet_socket_accept(ENetSocket socket, ENetAddress* address)
	{
		struct sockaddr_in6 sin; memset(&sin, 0, sizeof(sin));
		int sinLength = sizeof(struct sockaddr_in6);

		SOCKET result = accept(socket, address != NULL ? (struct sockaddr*)&sin : NULL, address != NULL ? &sinLength : NULL);

		if (result == INVALID_SOCKET)
			return ENET_SOCKET_NULL;

		if (address != NULL) 
		{
			address->host = sin.sin6_addr;
			address->port = ENET_NET_TO_HOST_16(sin.sin6_port);
			address->scope_id = sin.sin6_scope_id;
		}

		return result;
	}

	int enet_socket_shutdown(ENetSocket socket, ENetSocketShutdown how)
	{
		return shutdown(socket, (int)how) == SOCKET_ERROR ? -1 : 0;
	}

	void enet_socket_destroy(ENetSocket socket)
	{
		if (socket != INVALID_SOCKET)
			closesocket(socket);
	}

	int enet_socket_send(ENetSocket socket, const ENetAddress* address, const ENetBuffer* buffers, size_t bufferCount)
	{
		struct sockaddr_in6 sin;
		DWORD sentLength;

		if (address != NULL)
		{
			memset(&sin, 0, sizeof(struct sockaddr_in6));

			sin.sin6_family = AF_INET6;
			sin.sin6_port = ENET_HOST_TO_NET_16(address->port);
			sin.sin6_addr = address->host;
			sin.sin6_scope_id = address->scope_id;
		}

		if (WSASendTo(socket, (LPWSABUF)buffers, (DWORD)bufferCount, &sentLength, 0, address != NULL ? (struct sockaddr*)&sin : NULL, address != NULL ? sizeof(struct sockaddr_in6) : 0, NULL, NULL) == SOCKET_ERROR) 
			return (WSAGetLastError() == WSAEWOULDBLOCK) ? 0 : 1;

		return (int)sentLength;
	}

	int enet_socket_receive(ENetSocket socket, ENetAddress* address, ENetBuffer* buffers, size_t bufferCount)
	{
		INT sinLength = sizeof(struct sockaddr_in6);
		DWORD flags = 0, recvLength;
		struct sockaddr_in6 sin; memset(&sin, 0, sizeof(sin));

		if (WSARecvFrom(socket, (LPWSABUF)buffers, (DWORD)bufferCount, &recvLength, &flags, address != NULL ? (struct sockaddr*)&sin : NULL, address != NULL ? &sinLength : NULL, NULL, NULL) == SOCKET_ERROR) 
		{
			switch (WSAGetLastError()) 
			{
			case WSAEWOULDBLOCK:
			case WSAECONNRESET:
				return 0;
			default:
				return -1;
			}
		}

		if (flags & MSG_PARTIAL)
			return -1;

		if (address != NULL) 
		{
			address->host = sin.sin6_addr;
			address->port = ENET_NET_TO_HOST_16(sin.sin6_port);
			address->scope_id = sin.sin6_scope_id;
		}

		return (int)recvLength;
	}

	int enet_socket_select(ENetSocket maxSocket, ENetSocketSet* readSet, ENetSocketSet* writeSet, enet_uint32 timeout) 
	{
		struct timeval timeVal;
		timeVal.tv_sec = timeout / 1000;
		timeVal.tv_usec = (timeout % 1000) * 1000;

		return select((int)maxSocket + 1, readSet, writeSet, NULL, &timeVal);
	}

	int enet_socket_wait(ENetSocket socket, enet_uint32* condition, enet_uint32 timeout)
	{
		struct timeval timeVal;
		timeVal.tv_sec = timeout / 1000;
		timeVal.tv_usec = (timeout % 1000) * 1000;

		fd_set readSet, writeSet;
		FD_ZERO(&readSet);
		FD_ZERO(&writeSet);

		if (*condition & ENET_SOCKET_WAIT_SEND)
			FD_SET(socket, &writeSet);

		if (*condition & ENET_SOCKET_WAIT_RECEIVE)
			FD_SET(socket, &readSet);

		int selectCount = select((int)socket + 1, &readSet, &writeSet, NULL, &timeVal);

		if (selectCount < 0)
			return -1;

		*condition = ENET_SOCKET_WAIT_NONE;

		if (selectCount == 0)
			return 0;

		if (FD_ISSET(socket, &writeSet))
			*condition |= ENET_SOCKET_WAIT_SEND;

		if (FD_ISSET(socket, &readSet))
			*condition |= ENET_SOCKET_WAIT_RECEIVE;

		return 0;
	}
#endif

#ifdef __cplusplus
}
#endif
