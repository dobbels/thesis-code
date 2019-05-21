CONTIKI_PROJECT = hidra-r
all: $(CONTIKI_PROJECT)

#CONTIKI_NO_NET=1

UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL
CFLAGS+= -DSICSLOWPAN_CONF_FRAG=0
CFLAGS+= -Os
CFLAGS += -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

CONTIKI_WITH_IPV6 = 1

PROJECT_SOURCEFILES += encoded-policy.c
PROJECT_SOURCEFILES += bit-operations.c
PROJECT_SOURCEFILES += md5.c
#PROJECT_SOURCEFILES += hmac/hmac_sha2.c
#PROJECT_SOURCEFILES += hmac/sha2.c
#PROJECT_SOURCEFILES += hmac.c
#PROJECT_SOURCEFILES += sha224-256.c
#PROJECT_SOURCEFILES += usha.c

#PROJECT_SOURCEFILES += policy.c


CONTIKI = contiki
include $(CONTIKI)/Makefile.include
