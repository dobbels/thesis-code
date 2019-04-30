CONTIKI_PROJECT = hidra-r
all: $(CONTIKI_PROJECT)

UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL

CONTIKI_WITH_IPV6 = 1

PROJECT_SOURCEFILES += encoded_policy.c
#PROJECT_SOURCEFILES += policy.c

#TARGET_LIBFILES += tiny-AES-c/libaes.a  #-L./libaes #-laes
#TARGET_LIBFILES += aes.a

#CFLAGS += -Wall 
#CFLAGS += -Os 
#CFLAGS += -c
#LDFLAGS += -Wall
#LDFLAGS += -Os
#LDFLAGS += -Wl
#LDFLAGS += -Map
#LDFLAGS += test.map
#PROJECT_SOURCEFILES += tiny-AES-c/aes.c


CONTIKI = contiki
include $(CONTIKI)/Makefile.include

#AES = tiny-AES-c
#include $(AES)/Makefile
