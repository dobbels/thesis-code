CONTIKI_PROJECT = hidra-r
all: $(CONTIKI_PROJECT)

UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL

#APPS=servreg-hack
CONTIKI_WITH_IPV6 = 1

CONTIKI = contiki
include $(CONTIKI)/Makefile.include
