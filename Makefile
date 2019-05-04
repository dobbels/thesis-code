CONTIKI_PROJECT = hidra-r
all: $(CONTIKI_PROJECT)

UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL

CONTIKI_WITH_IPV6 = 1

PROJECT_SOURCEFILES += encoded_policy.c
PROJECT_SOURCEFILES += byte_operations.c
PROJECT_SOURCEFILES += md5.c
#PROJECT_SOURCEFILES += hmac.c
#PROJECT_SOURCEFILES += sha1.c
#PROJECT_SOURCEFILES += usha.c
#PROJECT_SOURCEFILES += avr-crypto-lib/hmac-sha1/hmac-sha1.c
#PROJECT_SOURCEFILES += hmac-sha1/src/hmac/hmac-sha1.c
#PROJECT_SOURCEFILES += hmac-sha1.c

#PROJECT_SOURCEFILES += policy.c


CONTIKI = contiki
include $(CONTIKI)/Makefile.include
