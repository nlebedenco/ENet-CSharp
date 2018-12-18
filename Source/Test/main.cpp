#include <cstdlib>
#include <cstdio>
#include <string>
#include <iostream>
#include <thread>

#include "enet.h"

void client()
{
    printf("Client thread started\n");

    ENetHost * client = enet_host_create(
        NULL,   // create a client host
        1,      // only allow 1 outgoing connection
        2,      // allow up 2 channels to be used, 0 and 1
        0,      // assume any amount of incoming bandwidth
        0       // assume any amount of incoming bandwidth
    );

    if (client == NULL)
    {
        fprintf(stderr, "An error occurred while trying to create a client host.\n");
        goto finish;
    }

    // TODO

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

    // TODO

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


