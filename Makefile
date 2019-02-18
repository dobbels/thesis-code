CONTIKI_PROJECT = hidra-r
all: $(CONTIKI_PROJECT)

UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL

#For some reason, without this line, motes do not receive UDP broadcast from eachother (which is not necessary at first, with only one HidraR mote, but maybe later on)
APPS=servreg-hack
CONTIKI_WITH_IPV6 = 1

CONTIKI = contiki
include $(CONTIKI)/Makefile.include
