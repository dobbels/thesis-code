CONTIKI_PROJECT = hidra-r
all: $(CONTIKI_PROJECT)

UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL
CFLAGS+= -DSICSLOWPAN_CONF_FRAG=0

CONTIKI_WITH_IPV6 = 1

PROJECT_SOURCEFILES += encoded-policy.c
PROJECT_SOURCEFILES += bit-operations.c
PROJECT_SOURCEFILES += md5.c

#PROJECT_SOURCEFILES += policy.c


CONTIKI = contiki
include $(CONTIKI)/Makefile.include
