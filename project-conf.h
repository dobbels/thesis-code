//No effect?? -> maybe all of these are disabled by default with this compiler?

#define PROCESS_CONF_NO_PROCESS_NAMES 0

#define UIP_CONF_TCP 0

#define SICSLOWPAN_CONF_FRAG 0

//TODO see biggest buffers in ramprof

//If you need to save RAM, you might consider reducing:
//QUEUEBUF_CONF_NUM: the number of packets in the link-layer queue. 4 is probably a lower bound for reasonable operation. As the traffic load increases, e.g. more frequent traffic or larger datagrams, you will need to increase this parameter.
#define QUEUEBUF_CONF_NUM 4
//NBR_TABLE_CONF_MAX_NEIGHBORS: the number of entries in the neighbor table. A value greater than the maximum network density is safe. A value lower than that will also work, as the neighbor table will automatically focus on relevant neighbors. But too low values will result in degraded performance.
//NETSTACK_MAX_ROUTE_ENTRIES: the number of routing entries, i.e., in RPL non-storing mode, the number of links in the routing graph, and in storing mode, the number of routing table elements. At the network root, this must be set to the maximum network size. In non-storing mode, other nodes can set this parameter to 0. In storing mode, it is recommended for all nodes to also provision enough entries for each node in the network.
//UIP_CONF_BUFFER_SIZE: the size of the IPv6 buffer. The minimum value for interoperability is 1280. In closed systems, where no large datagrams are used, lowering this to e.g. 140 may be sensible.
//SICSLOWPAN_CONF_FRAG: Enables/disables 6LoWPAN fragmentation. Disable this if all your traffic fits a single link-layer packet. Note that this will also save some significant ROM.

//#define UIP_CONF_UDP 0 // Useless: hidra protocol still works with this flag enabled
