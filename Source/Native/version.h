#pragma once

#define STRX(s)     #s
#define STR(s)      STRX(s)
 
#define ENET_VERSION_MAJOR          3
#define ENET_VERSION_MINOR          0
#define ENET_VERSION_BUILD          0
#define ENET_VERSION_REVISION       0
 
#define ENET_FILE_VERSION           ENET_VERSION_MAJOR, ENET_VERSION_MINOR, ENET_VERSION_BUILD, ENET_VERSION_REVISION
#define ENET_FILE_VERSION_STR       STR(ENET_VERSION_MAJOR)        \
                                    "." STR(ENET_VERSION_MINOR)    \
                                    "." STR(ENET_VERSION_BUILD)    \
                                    "." STR(ENET_VERSION_REVISION) \
 
#define ENET_PRODUCT_VERSION        ENET_VERSION_MAJOR, ENET_VERSION_MINOR, 0, 0
#define ENET_PRODUCT_VERSION_STR    STR(ENET_VERSION_MAJOR)        \
                                    "." STR(ENET_VERSION_MINOR)    \

