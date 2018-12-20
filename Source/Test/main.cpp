#include <cstdlib>
#include <cstdio>
#include <string>
#include <iostream>
#include <thread>

#include "enet.h"

#define TEST_PORT                       1234
#define TEST_CHANNEL_COUNT              2
#define TEST_CLIENT_CONNECT_TIMEOUT     5000

void client()
{
    printf("Client thread started\n");

    ENetHost* client = enet_host_create(
        NULL,   // create a client host
        1,      // only allow 1 outgoing connection
        2,      // allow up 2 channels to be used, 0 and 1
        0,      // assume any amount of incoming bandwidth
        0       // assume any amount of incoming bandwidth
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
        fprintf(stderr, "ENet host connection failed.\n");
        goto finish;
    }

    ENetEvent event;
    // Wait up to 5 seconds for the connection attempt to succeed.
    if (enet_host_service(client, &event, TEST_CLIENT_CONNECT_TIMEOUT) > 0
     && event.type == ENET_EVENT_TYPE_CONNECT)
    {
        char name[256];
        name[0] = '\0';
        enet_peer_get_name(peer, name, sizeof(name));
        printf("Client connected to %s:%d .\n", name, enet_peer_get_port(peer));
    }
    else
    {
        char name[256];
        name[0] = '\0';
        enet_address_get_host_name(&address, name, sizeof(name));
        fprintf(stderr, "Connection to %s:%d failed with event %d.", name, address.port, event.type);

        // Either the 5 seconds are up or a disconnect event was received. Reset the peer in this case.
        enet_peer_reset(peer);
    }

    enet_host_destroy(client);

finish:
    printf("Client thread finished\n");
}

void server()
{
    printf("Server thread started\n");

    ENetAddress address;
    address.host = ENET_HOST_ANY;
    address.port = 1234;
    address.scope_id = 0;

    ENetHost* server = enet_host_create(
        &address,   // the address to bind the server host to
        32,         // allow up to 32 clients and/or outgoing connections
        2,          // allow up to 2 channels to be used, 0 and 1
        0,          // assume any amount of incoming bandwidth
        0           // assume any amount of outgoing bandwidth
    );

    if (server == NULL)
    {
        fprintf(stderr, "An error occurred while trying to create a server host.\n");
        goto finish;
    }


    enet_host_destroy(server);

finish:
    printf("Server thread finished\n");
}

int main(int argc, char* argv[])
{
    if (enet_initialize() != 0)
    {
        fprintf(stderr, "An error occurred while initializing ENet.\n");
        exit(EXIT_FAILURE);
    }

    atexit(enet_deinitialize);

    std::thread client(&client);
    server();
    client.join();

    return EXIT_SUCCESS;
}


