#include <cstdlib>
#include <cstdio>
#include <string>
#include <iostream>
#include <thread>

#include "enet.h"

#define TEST_PORT                       1234
#define TEST_CHANNEL_COUNT              2
#define TEST_CONNECT_TIMEOUT            5000

static const char* ChallengeMsg = "Hello, I'm a client who are you?";
static const char* ResponseMsg = "Hi, I'm the server.";

int send_message(ENetPeer* peer, const void* data, size_t length, enet_uint16 flags, enet_uint8 channelId)
{
    ENetPacket * packet = enet_packet_create(data, length, flags);
    return enet_peer_send(peer, channelId, packet);
}

#define client_info(M, ...) fprintf(stdout, "[CLIENT] " M, __VA_ARGS__)
#define client_error(M, ...) fprintf(stderr, "[CLIENT] " M, __VA_ARGS__)

void client()
{
    char name[256] = {0};

    client_info("Thread started\n");

    ENetHost* client = enet_host_create(
        NULL,                   // create a client host
        1,                      // only allow 1 outgoing connection
        TEST_CHANNEL_COUNT,     // allow up 2 channels to be used, 0 and 1
        0,                      // assume any amount of incoming bandwidth
        0                       // assume any amount of incoming bandwidth
    );

    
    ENetPeer* peer = NULL;    

    if (client == NULL)
    {
        fprintf(stderr, "An error occurred while trying to create a client host.\n");
        goto finish;
    }

    ENetAddress address;
    address.host = ENET_HOST_LOCALHOST;
    address.port = TEST_PORT;
    address.scope_id = ENET_SCOPE_ID_NONE;

    /* Initiate the connection, allocating the two channels 0 and 1. */
    peer = enet_host_connect(client, &address, TEST_CHANNEL_COUNT, 0);
    if (peer == NULL)
    {
        client_error("Connection failed. Peer is null.\n");
        goto finish;
    }

    ENetEvent event;
    while (enet_host_service(client, (ENetEvent*)memset(&event, 0, sizeof(event)), TEST_CONNECT_TIMEOUT / 2 ) > 0)
    {
        if (event.type == ENET_EVENT_TYPE_NONE)
            continue;

        // Clients only receive events from a connected peer.
        if (peer != event.peer)
        {
            client_error("Connected peer and event peer do not match.\n");
            goto terminate;
        }
        
        switch (event.type)
        {
        case ENET_EVENT_TYPE_CONNECT:
            enet_peer_get_name(event.peer, name, sizeof(name));
            client_info("Connected to %s:%d. Connection Id=%08X. Incoming Peer Id=%d. Outgoing Peer Id=%d.\n", name, enet_peer_get_port(event.peer), event.peer->connectId, event.peer->incomingPeerId, event.peer->outgoingPeerId);
            send_message(event.peer, ChallengeMsg, strlen(ChallengeMsg) + 1, ENET_PACKET_FLAG_RELIABLE, 0);
            break;
        case ENET_EVENT_TYPE_RECEIVE:
            client_info("Received packet with %Iu bytes of data from %s:%d on channel %u. Connection Id=%08X. Incoming Peer Id=%d. Outgoing Peer Id=%d.\n", event.packet->dataLength, name, enet_peer_get_port(event.peer), event.channelId, event.peer->connectId, event.peer->incomingPeerId, event.peer->outgoingPeerId);
            if (event.packet->dataLength != (strlen(ResponseMsg) + 1))
            {
                client_error("Invalid packet size.\n");
                goto terminate;
            }

            if (memcmp(event.packet->data, ResponseMsg, event.packet->dataLength) != 0)
            {
                client_error("Invalid packet data.\n");
                goto terminate;
            }

            client_info("Packet data: %s.\n", event.packet->data);

            enet_packet_destroy(event.packet); // release the packet now that we're done using it.
            enet_peer_disconnect(event.peer, 0);
            break;
        case ENET_EVENT_TYPE_DISCONNECT:
            client_info("Disconnected from %s:%d. Connection Id=%08X. Incoming Peer Id=%d. Outgoing Peer Id=%d.\n", name, enet_peer_get_port(event.peer), event.peer->connectId, event.peer->incomingPeerId, event.peer->outgoingPeerId);
            break;
        case ENET_EVENT_TYPE_TIMEOUT:
            client_error("Timeout. Connection Id=%08X. Incoming Peer Id=%d. Outgoing Peer Id=%d.\n", event.peer->connectId, event.peer->incomingPeerId, event.peer->outgoingPeerId);
            goto terminate;
        }
    }

terminate:
    enet_peer_disconnect_immediately(peer, 0);
    enet_host_destroy(client);

finish:
    client_info("Thread finished\n");
}

#undef client_info
#undef client_error

#define server_info(M, ...) fprintf(stdout, "[SERVER] " M, __VA_ARGS__)
#define server_error(M, ...) fprintf(stderr, "[SERVER] " M, __VA_ARGS__)

void server()
{
    char name[256] = {0};

    server_info("Thread started\n");

    ENetAddress address;
    address.host = ENET_HOST_ANY;
    address.port = TEST_PORT;
    address.scope_id = ENET_SCOPE_ID_NONE;

    ENetHost* server = enet_host_create(
        &address,           // the address to bind the server host to
        32,                 // allow up to 32 clients and/or outgoing connections
        TEST_CHANNEL_COUNT, // allow up to 2 channels to be used, 0 and 1
        0,                  // assume any amount of incoming bandwidth
        0                   // assume any amount of outgoing bandwidth
    );

    if (server == NULL)
    {
        server_error("An error occurred while trying to create a server host.\n");
        goto finish;
    }

    ENetEvent event;
    while (enet_host_service(server, (ENetEvent*)memset(&event, 0, sizeof(event)), TEST_CONNECT_TIMEOUT) > 0)
    {
        if (event.type == ENET_EVENT_TYPE_NONE)
            continue;

        switch (event.type)
        {
        case ENET_EVENT_TYPE_CONNECT:
            enet_peer_get_name(event.peer, name, sizeof(name));
            server_info("Connected to %s:%d. Connection Id=%08X. Incoming Peer Id=%d. Outgoing Peer Id=%d.\n", name, enet_peer_get_port(event.peer), event.peer->connectId, event.peer->incomingPeerId, event.peer->outgoingPeerId);
            break;
        case ENET_EVENT_TYPE_RECEIVE:
            server_info("Received packet with %Iu bytes of data from %s:%d on channel %u. Connection Id=%08X. Incoming Peer Id=%d. Outgoing Peer Id=%d.\n", event.packet->dataLength, name, enet_peer_get_port(event.peer), event.channelId, event.peer->connectId, event.peer->incomingPeerId, event.peer->outgoingPeerId);
            if (event.packet->dataLength != (strlen(ChallengeMsg) + 1))
            {
                server_error("Invalid packet size.\n");
                goto terminate;
            }

            if (memcmp(event.packet->data, ChallengeMsg, event.packet->dataLength) != 0)
            {
                server_error("Invalid packet data.\n");
                goto terminate;
            }

            server_info("Packet data: %s.\n", event.packet->data);
            enet_packet_destroy(event.packet); // release the packet now that we're done using it.

            send_message(event.peer, ResponseMsg, strlen(ResponseMsg) + 1, ENET_PACKET_FLAG_RELIABLE, 1);
            break;
        case ENET_EVENT_TYPE_DISCONNECT:
            server_info("Disconnected from %s:%d. Connection Id=%08X. Incoming Peer Id=%d. Outgoing Peer Id=%d.\n", name, enet_peer_get_port(event.peer), event.peer->connectId, event.peer->incomingPeerId, event.peer->outgoingPeerId);
            break;
        case ENET_EVENT_TYPE_TIMEOUT:
            server_error("Timeout. Connection Id=%08X. Incoming Peer Id=%d. Outgoing Peer Id=%d.\n", event.peer->connectId, event.peer->incomingPeerId, event.peer->outgoingPeerId);
            goto terminate;
        }
    }

terminate:
    enet_host_destroy(server);

finish:
    server_info("Thread finished\n");
}

#undef server_info
#undef server_error


int main(int argc, char* argv[])
{
    if (enet_initialize() != 0)
    {
        fprintf(stderr, "An error occurred while initializing ENet.\n");
        exit(EXIT_FAILURE);
    }

    atexit(enet_finalize);

    std::thread server(&server);
    std::thread clients[] = {
        std::thread(&client),
        std::thread(&client),
        std::thread(&client)
    };
    
    server.join();
    for (auto& client: clients)
        client.join();

    return EXIT_SUCCESS;
}


