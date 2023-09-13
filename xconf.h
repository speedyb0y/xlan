// CONFIG -> XCONF
#ifndef XCONF

#ifdef CONFIG_XLAN
#define XCONF_XLAN 1
#else
#define XCONF_XLAN 0
#endif

#define XCONF_XLAN_NET4               CONFIG_XLAN_NET4
#define XCONF_XLAN_NET6               CONFIG_XLAN_NET6
#define XCONF_XLAN_HOST               CONFIG_XLAN_HOST
#define XCONF_XLAN_GW                 CONFIG_XLAN_GW
#define XCONF_XLAN_ANNOUNCE_DELAY     CONFIG_XLAN_ANNOUNCE_DELAY
#define XCONF_XLAN_ANNOUNCE_INTERVAL  CONFIG_XLAN_ANNOUNCE_INTERVAL
#define XCONF_XLAN_ANNOUNCE_ROUNDS    CONFIG_XLAN_ANNOUNCE_ROUNDS

#endif
