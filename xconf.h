// CONFIG -> XCONF

#ifdef CONFIG_XLAN
#define XCONF_XLAN 1
#else
#define XCONF_XLAN 0
#endif

#ifdef CONFIG_XLAN_STRUCT
#define XCONF_XLAN_STRUCT 1
#else
#define XCONF_XLAN_STRUCT 0
#endif

#define XCONF_XLAN_VENDOR  CONFIG_XLAN_VENDOR
#define XCONF_XLAN_HOSTS_N CONFIG_XLAN_HOSTS_N
#define XCONF_XLAN_PORTS_N CONFIG_XLAN_PORTS_N
