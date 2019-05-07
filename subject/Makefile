CONTIKI_PROJECT = subject
all: $(CONTIKI_PROJECT)

UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL

CONTIKI_WITH_IPV6 = 1

PROJECT_SOURCEFILES += ../bit-operations.c

CONTIKI = ../contiki
include $(CONTIKI)/Makefile.include