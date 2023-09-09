/*

*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/ip.h>
#include <net/inet_common.h>
#include <net/addrconf.h>
#include <linux/module.h>

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef unsigned int uint;
typedef unsigned long long int uintll;

typedef struct sk_buff sk_buff_s;
typedef struct net_device net_device_s;
typedef struct net net_s;
typedef struct net_device_ops net_device_ops_s;
typedef struct notifier_block notifier_block_s;

#define SKB_HEAD(skb) PTR((skb)->head)
#define SKB_DATA(skb) PTR((skb)->data)
#define SKB_TAIL(skb) PTR(skb_tail_pointer(skb))
#define SKB_END(skb)  PTR(skb_end_pointer(skb))

#define SKB_MAC(skb)     PTR(skb_mac_header(skb))
#define SKB_NETWORK(skb) PTR(skb_network_header(skb))

#define PTR(p) ((void*)(p))

#define loop while (1)

#define elif(c) else if (c)

#define foreach(i, t) for (uint i = 0; i != (t); i++)

#ifdef __BIG_ENDIAN
#define BE16(x) (x)
#define BE32(x) (x)
#define BE64(x) (x)
#else
#define BE16(x) ((u16)__builtin_bswap16((u16)(x)))
#define BE32(x) ((u32)__builtin_bswap32((u32)(x)))
#define BE64(x) ((u64)__builtin_bswap64((u64)(x)))
#endif

#define HOSTS_N 256
#define PORTS_N 8
#define MTU     7600 // TODO: FIXME:

#define ETH_SIZE 14
#define IP4_SIZE 20
#define IP6_SIZE 40
#define UDP_SIZE  8
#define TCP_SIZE 20

#define VENDOR 0x5062

#define HP_ENCODE(hp) (((uint)(hp)) * 0x0101U)
#define HP_DECODE(hp) (((uint)(hp)) & 0x00FFU)

#ifdef CONFIG_XLAN_STRUCT
#define XCONF_XLAN_STRUCT 1
#else
#define XCONF_XLAN_STRUCT 0
#endif

#define __COMPACT __attribute__((packed))

typedef struct mac_s {
    u16 vendor;
    u16 host;
    u16 port;
} __COMPACT mac_s;

typedef struct addr4_s {
    u16 net;
    u16 host;
} addr4_s;

typedef struct addr6_s {
    u16 net;
    u16 _[6];
    u16 host;
} addr6_s;

#if XCONF_XLAN_STRUCT
#define PKT_SIZE 64

typedef struct pkt_s {
    u8 _align[6];
    mac_s src;
    mac_s dst;
    u16 type;
    union pkt_ip_s {
        struct pkt_ip_v4_s {
            u8 _x[9];
            u8 protocol;
            u8 _y[2];
            union { u64 addrs;
                struct {
                    addr4_s src;
                    addr4_s dst;
                };
            } __COMPACT;
            u32 ports;
            u8 _z[20];
        } __COMPACT v4;
        struct pkt_ip_v6_s {
            u8 _x[2];
            u16 flow;
            u8 _y[2];
            u8 protocol;
            u8 _z[1];
            union { u64 addrs[4];
                struct {
                    addr6_s src;
                    addr6_s dst;
                };
            } __COMPACT;
            u32 ports;
        } __COMPACT v6;
    } ip;
} __COMPACT pkt_s;
#else
typedef void pkt_s;
#endif

#if XCONF_XLAN_STRUCT
#define PKT_OFFSET_ETH offsetof(pkt_s, dst)
#define PKT_OFFSET_IP  offsetof(pkt_s, ip)
#define pkt_eth       (&pkt->dst)
#define pkt_src_vendor  pkt->src.vendor
#define pkt_dst_vendor  pkt->dst.vendor
#define pkt_src_host    pkt->src.host
#define pkt_dst_host    pkt->dst.host
#define pkt_src_port    pkt->src.port
#define pkt_dst_port    pkt->dst.port
#define pkt_type        pkt->type
#define pkt_flow6       pkt->ip.v6.flow
#define pkt_protocol4   pkt->ip.v4.protocol
#define pkt_protocol6   pkt->ip.v6.protocol
#define pkt_addrs4      pkt->ip.v4.addrs
#define pkt_addrs6      pkt->ip.v6.addrs
#define pkt_ports4      pkt->ip.v4.ports
#define pkt_ports6      pkt->ip.v6.ports
#define pkt_src_net4    pkt->ip.v4.src.net
#define pkt_src_net6    pkt->ip.v6.src.net
#define pkt_dst_net4    pkt->ip.v4.dst.net
#define pkt_dst_net6    pkt->ip.v6.dst.net
#define pkt_src_host4   pkt->ip.v4.src.host
#define pkt_src_host6   pkt->ip.v6.src.host
#define pkt_dst_host4   pkt->ip.v4.dst.host
#define pkt_dst_host6   pkt->ip.v6.dst.host
#else
#define PKT_OFFSET_ETH 0
#define PKT_OFFSET_IP  14
#define pkt_eth                pkt
#define pkt_dst_vendor  ((u16*)pkt)[0]
#define pkt_dst_host    ((u16*)pkt)[1]
#define pkt_dst_port    ((u16*)pkt)[2]
#define pkt_src_vendor  ((u16*)pkt)[3]
#define pkt_src_host    ((u16*)pkt)[4]
#define pkt_src_port    ((u16*)pkt)[5]
#define pkt_type        ((u16*)pkt)[6]
#define pkt_protocol4 (*(u8* )(pkt + 14 +  9))
#define pkt_addrs4    (*(u64*)(pkt + 14 + 12))
#define pkt_ports4    (*(u32*)(pkt + 14 + 20))
#define pkt_flow6     ((u16*)pkt)[8]
#define pkt_protocol6 (*(u8* )(pkt + 14 +  6))
#define pkt_addrs6    ( (u64*)(pkt + 14 +  8))
#define pkt_ports6    (*(u32*)(pkt + 14 + 40))
#define pkt_src_net4  ((u16*)pkt)[13]
#define pkt_src_host4 ((u16*)pkt)[14]
#define pkt_dst_net4  ((u16*)pkt)[15]
#define pkt_dst_host4 ((u16*)pkt)[16]
#define pkt_src_net6  ((u16*)pkt)[11]
#define pkt_src_host6 ((u16*)pkt)[18]
#define pkt_dst_net6  ((u16*)pkt)[19]
#define pkt_dst_host6 ((u16*)pkt)[26]
#endif

typedef struct xlan_stream_s {
    u32 ports;
    u32 last;
} xlan_stream_s;

// NETWORK, HOST
// NN.NN.HH.HH NNNN:?:HHHH
typedef struct xlan_s {
    u16 net4;   // NN.NN.
    u16 net6;   // NNNN::
    u16 host;   // .HH.HH ::HHHH LHOST
    u16 gw;     // .HH.HH ::HHHH RHOST, WHEN IT DOES NOT BELONG TO THE NET
    net_device_s* ports[PORTS_N];
    xlan_stream_s paths[HOSTS_N][64]; // POPCOUNT64()
    u32 seen[HOSTS_N][PORTS_N][PORTS_N]; // TODO: FIXME: ATOMIC
} xlan_s;

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;
    net_device_s* const phys = skb->dev;
    net_device_s* const virt = skb->dev->rx_handler_data;
    xlan_s* const xlan = netdev_priv(virt);

    const pkt_s* const pkt = SKB_MAC(skb) - PKT_OFFSET_ETH;

    // SO HANDLE O QUE FOR
    if (pkt_dst_vendor != BE16(VENDOR)
     || pkt_src_vendor != BE16(VENDOR))
        return RX_HANDLER_PASS;

    // ASSERT: skb->type PKT_HOST
    const uint lhost = HP_DECODE(pkt_dst_host);
    const uint lport = HP_DECODE(pkt_dst_port);
    const uint rhost = HP_DECODE(pkt_src_host);
    const uint rport = HP_DECODE(pkt_src_port);

    // DISCARD THOSE
    if (lhost >= HOSTS_N
     || rhost >= HOSTS_N
     || lport >= PORTS_N
     || rport >= PORTS_N
     || rhost == xlan->host
     || lhost != xlan->host // NOT TO ME (POIS PODE TER RECEBIDO DEVIDO AO MODO PROMISCUO)
     || phys  != xlan->ports[lport] // WRONG INTERFACE
     || virt->flags == 0) { // ->flags & UP
        kfree_skb(skb);
        return RX_HANDLER_CONSUMED;
    }

    //
    xlan->seen[rhost][rport][lport] = jiffies;

    skb->dev = virt;

    return RX_HANDLER_ANOTHER;
}

#define ROUNDS 5

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const dev) {

    xlan_s* const xlan = netdev_priv(dev);

    // ONLY LINEAR
    if (skb_linearize(skb))
        goto drop;

    pkt_s* const pkt = SKB_NETWORK(skb) - PKT_OFFSET_IP;

    // CONFIRMA ESPACO
    if (PTR(pkt_eth) < SKB_HEAD(skb))
        goto drop;

    // NOTE: ASSUME QUE NÃO TEM IP OPTIONS
    const int v4 = skb->protocol == BE16(ETH_P_IP);

    // IDENTIFY DESTINATION
    const uint rhost = v4 ?
        ( pkt_dst_net4 == xlan->net4 ? BE16(pkt_dst_host4) : xlan->gw ):
        ( pkt_dst_net6 == xlan->net6 ? BE16(pkt_dst_host6) : xlan->gw );

    if (rhost >= HOSTS_N
     || rhost == xlan->host)
        // É INVALIDO / ERA EXTERNO E NAO TEMOS GATEWAY / PARA SI MESMO
        goto drop;

    // SELECT A PATH
    // OK: TCP | UDP | UDPLITE | SCTP | DCCP
    // FAIL: ICMP
    xlan_stream_s* const path = &xlan->paths[rhost][__builtin_popcountll( (u64) ( v4
        ? pkt_protocol4 // IP PROTOCOL
        * pkt_ports4    // SRC PORT, DST PORT
        + pkt_addrs4    // SRC ADDR, DST ADDR
        : pkt_flow6     // FLOW
        * pkt_protocol6 // IP PROTOCOL
        * pkt_ports6    // SRC PORT, DST PORT
        + pkt_addrs6[0] // SRC ADDR
        + pkt_addrs6[1] // SRC ADDR
        + pkt_addrs6[2] // DST ADDR
        + pkt_addrs6[3] // DST ADDR
    ))];

    uint now   = jiffies;
    uint ports = path->ports;

    uint rport;
    uint lport;

    net_device_s* phys;

    uint c = 1 + ROUNDS * (PORTS_N * PORTS_N);

    foreach (r, ROUNDS) {

        // LIMIT
        if (c-- == 0)
            goto drop;

        // NOTE: MUDA A PORTA LOCAL COM MAIS FREQUENCIA, PARA QUE O SWITCH A DESCUBRA
        // for PORTS_N in range(7): assert len(set((_ // PORTS_N, _ % PORTS_N) for _ in range(PORTS_N*PORTS_N))) == PORTS_N*PORTS_N
        ports %= PORTS_N * PORTS_N;

        rport = ports / PORTS_N;
        lport = ports % PORTS_N;

        phys = xlan->ports[lport];

        if (phys && (phys->flags & IFF_UP) == IFF_UP && // IFF_RUNNING // IFF_LOWER_UP
            ( r == 4 || ( // NO ULTIMO ROUND FORCA MESMO ASSIM
                (r*1*HZ)/5 >= (now - path->last) && // SE DEU UMA PAUSA, TROCA DE PORTA
                (r*2*HZ)/1 >= (now - xlan->seen[rhost][rport][lport]) // KNOWN TO WORK
            ))) break;

        ports++;
    }

    path->ports = ports;
    path->last  = now;

    // INSERT ETHERNET HEADER
    pkt_dst_vendor = BE16(VENDOR);
    pkt_dst_host   = HP_ENCODE(rhost);
    pkt_dst_port   = HP_ENCODE(rport);
    pkt_src_vendor = BE16(VENDOR);
    pkt_src_host   = HP_ENCODE(xlan->host);
    pkt_src_port   = HP_ENCODE(lport);
    pkt_type       = skb->protocol;

    // UPDATE SKB
    skb->data       = PTR(pkt);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header = PTR(pkt) - SKB_HEAD(skb);
#else
    skb->mac_header = PTR(pkt);
#endif
    skb->len        = SKB_TAIL(skb) - PTR(pkt);
    skb->mac_len    = ETH_HLEN;

    skb->dev = phys;

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
    dev_queue_xmit(skb);

    return NETDEV_TX_OK;

drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int xlan_up (net_device_s* const dev) {

    printk("XLAN: %s: UP\n", dev->name);

    return 0;
}

static int xlan_down (net_device_s* const dev) {

    printk("XLAN: %s: DOWN\n", dev->name);

    return 0;
}

static int xlan_enslave (net_device_s* dev, net_device_s* phys, struct netlink_ext_ack* extack) {

    enum {
        _ENSL_SUCCESS,
        _ENSL_ITSELF,
        _ENSL_ALREADY,
        _ENSL_OCCUPIED,
        _ENSL_NOT_ETHERNET,
        _ENSL_VENDOR_WRONG,
        _ENSL_HOST_WRONG,
        _ENSL_PORT_INVALID,
        _ENSL_PORT_HIGH,
        _ENSL_ANOTHER_XLAN,
        _ENSL_ATTACH_FAILED,
        __N,
    };

    static const u16 codes [__N] = {
        [_ENSL_SUCCESS       ] = 0,
        [_ENSL_NOT_ETHERNET  ] = EINVAL,
        [_ENSL_ITSELF        ] = EINVAL,
        [_ENSL_ALREADY       ] = EISCONN,
        [_ENSL_OCCUPIED      ] = EBUSY,
        [_ENSL_VENDOR_WRONG  ] = EINVAL,
        [_ENSL_HOST_WRONG    ] = EINVAL,
        [_ENSL_PORT_INVALID  ] = EINVAL,
        [_ENSL_PORT_HIGH     ] = EINVAL,
        [_ENSL_ANOTHER_XLAN  ] = EINVAL,
        [_ENSL_ATTACH_FAILED ] = 1,
    };

    static const char* strs [__N] = {
        [_ENSL_SUCCESS       ] = "SUCCESS",
        [_ENSL_NOT_ETHERNET  ] = "FAILED: NOT ETHERNET",
        [_ENSL_ALREADY       ] = "FAILED: ALREADY",
        [_ENSL_OCCUPIED      ] = "FAILED: ANOTHER INTERFACE ON THE PORT",
        [_ENSL_ITSELF        ] = "FAILED: ITSELF",
        [_ENSL_VENDOR_WRONG  ] = "FAILED: WRONG VENDOR",
        [_ENSL_HOST_WRONG    ] = "FAILED: WRONG HOST",
        [_ENSL_PORT_INVALID  ] = "FAILED: INVALID PORT",
        [_ENSL_PORT_HIGH     ] = "FAILED: PORT TOO HIGH",
        [_ENSL_ANOTHER_XLAN  ] = "FAILED: ANOTHER XLAN AS PHYSICAL",
        [_ENSL_ATTACH_FAILED ] = "FAILED: COULD NOT ATTACH",
    };

    xlan_s* const xlan = netdev_priv(dev);

    const mac_s* const mac = (const void*)dev->dev_addr;

    const uint port = HP_DECODE(mac->port);

    uint ret;

    if (phys == dev)
        // ITSELF
        ret = _ENSL_ITSELF;
    elif (0)
        // TODO: CANNOT BE OF XLAN TYPE
        ret = _ENSL_ANOTHER_XLAN;
    elif (xlan->ports[port] == dev)
        // ALREADY
        ret = _ENSL_ALREADY;
    elif (xlan->ports[port])
        // SOMETHING ELSE IS ON THAT SLOT
        ret = _ENSL_OCCUPIED;
    elif (phys->flags & IFF_LOOPBACK)
        // LOOPBACK
        ret = _ENSL_NOT_ETHERNET;
    elif (phys->addr_len != ETH_ALEN)
        // NOT ETHERNET
        ret = _ENSL_NOT_ETHERNET;
    elif (mac->vendor != BE16(VENDOR))
        // WRONG VENDOR
        ret = _ENSL_VENDOR_WRONG;
    elif (mac->host != HP_ENCODE(xlan->host))
        // WRONG HOST
        ret = _ENSL_HOST_WRONG;
    elif (mac->port != HP_ENCODE(port))
        // BAD PORT - MISMATCH
        ret = _ENSL_PORT_INVALID;
    elif (port >= PORTS_N)
        // BAD PORT - TOO HIGH
        ret = _ENSL_PORT_HIGH;
    elif (rtnl_dereference(phys->rx_handler) == xlan_in)
        // TODO: WTF?
        ret = _ENSL_ATTACH_FAILED;
    elif (netdev_rx_handler_register(phys, xlan_in, dev) != 0)
        // FAILED TO ATTACH
        ret = _ENSL_ATTACH_FAILED;
    else {
        // HOOKED
        phys->rx_handler_data = dev;
        // HOLD IT
        dev_hold(phys);
        // REGISTER IT
        xlan->ports[port] = phys;
        // SUCCESS
        ret = _ENSL_SUCCESS;
    }

    printk("XLAN: %s: ENSLAVE ITFC %s: PORT %u: %s\n",
        dev->name, phys->name, port, strs[ret]);

    return -(int)codes[ret];
}

static int xlan_unslave (net_device_s* dev, net_device_s* phys) {

    xlan_s* const xlan = netdev_priv(dev);

    foreach (port, PORTS_N) {
        if (xlan->ports[port] == phys) {
            // UNHOOK (IF ITS STILL HOOKED)
            if (rtnl_dereference(phys->rx_handler) == xlan_in) {
                                 phys->rx_handler_data = NULL;
                netdev_rx_handler_unregister(phys);
            }
            // DROP IT
            dev_put(phys);
            // UNREGISTER IT
            xlan->ports[port] = NULL;
            printk("XLAN: %s: DETACHED ITFC %s FROM PORT %u\n",
                dev->name, phys->name, port);
            return 0;
        }
    }

    printk("XLAN: %s: CANNOT DETACHED ITFC %s FROM ANY PORT\n",
        dev->name, phys->name);

    return -ENOTCONN;
}

// ip link set dev xlan addr N4:N4:N6:N6:HH:GG
#define XLAN_INFO_LEN 6
typedef struct xlan_info_s {
    u16 net4;
    u16 net6;
    u8 host;
    u8 gw;
    u16 _pad;
} xlan_info_s;

static int xlan_cfg (net_device_s* const dev, void* const addr) {

    if(netif_running(dev))
        return -EBUSY;

    const xlan_info_s* const info = addr;

    // READ
    const uint net4   = BE16(info->net4);
    const uint net6   = BE16(info->net6);
    const uint host   =      info->host;
    const uint gw     =      info->gw;

    printk("XLAN: %s: CONFIGURING: HOST %u GW %u NET4 0x%04X NET6 0x%04X\n",
        dev->name, host, gw, net4, net6);

    // VERIFY
    if (net4 && net6 && host && host < HOSTS_N && gw < HOSTS_N && gw != host) {

        xlan_s* const xlan = netdev_priv(dev);

        // COMMIT
        xlan->net4   = BE16(net4);
        xlan->net6   = BE16(net6);
        xlan->host   = host;
        xlan->gw     = gw ?: HOSTS_N;

        return 0;
    }

    return -EINVAL;
}

static const net_device_ops_s xlanDevOps = {
    .ndo_init             = NULL,
    .ndo_open             = xlan_up,
    .ndo_stop             = xlan_down,
    .ndo_start_xmit       = xlan_out,
    .ndo_set_mac_address  = xlan_cfg,
    .ndo_add_slave        = xlan_enslave,
    .ndo_del_slave        = xlan_unslave,
    // TODO: SET MTU - NAO EH PARA SETAR AQUI E SIM NO ROUTE
};

static void xlan_setup (net_device_s* const dev) {

    dev->netdev_ops      = &xlanDevOps;
    dev->header_ops      = NULL;
    dev->type            = ARPHRD_NONE;
    dev->addr_len        = XLAN_INFO_LEN;
    dev->hard_header_len = ETH_HLEN;
    dev->min_header_len  = ETH_HLEN;
    //dev->needed_headroom = ;
    //dev->needed_tailroom = ;
    dev->min_mtu         = ETH_MIN_MTU;
    dev->max_mtu         = ETH_MAX_MTU;
    dev->mtu             = MTU; // NOTE: TEM QUE SER O DA MENOR INTERFACE
    dev->tx_queue_len    = 0; // DEFAULT_TX_QUEUE_LEN
    dev->flags           = IFF_POINTOPOINT
                         | IFF_NOARP; // IFF_BROADCAST | IFF_MULTICAST
    dev->priv_flags      = IFF_NO_QUEUE
                         | IFF_NO_RX_HANDLER
                         //| IFF_LIVE_ADDR_CHANGE
                         //| IFF_LIVE_RENAME_OK
        ;
    dev->features        = // TODO: TEM QUE TER AS MESMAS FEATURES DAS INTERFACES
    dev->hw_features     = 0
        // | NETIF_F_HW_CSUM
        // | NETIF_F_RXCSUM
        // | NETIF_F_SG
        // | NETIF_F_TSO
        // | NETIF_F_TSO6
        // | NETIF_F_RXALL
        ;

    // INITIALIZE
    memset(netdev_priv(dev), 0, sizeof(xlan_s));
}

static int __init xlan_init (void) {

    // CREATE THE VIRTUAL INTERFACE
    // MAKE IT VISIBLE IN THE SYSTEM
    printk("XLAN: INIT\n");

    BUILD_BUG_ON( sizeof(mac_s) != ETH_ALEN );
    BUILD_BUG_ON( sizeof(addr4_s) != 4 );
    BUILD_BUG_ON( sizeof(addr6_s) != 16 );
    BUILD_BUG_ON( sizeof(pkt_s) != PKT_SIZE );
    BUILD_BUG_ON( offsetof(xlan_info_s, _pad) != XLAN_INFO_LEN );

    register_netdev(alloc_netdev(sizeof(xlan_s), "xlan", NET_NAME_USER, xlan_setup));

    return 0;
}

static void __exit xlan_exit (void) {

    printk("XLAN: EXIT\n");

    // TODO: REFUSE TO EXIT IF WE HAVE INTERFACES
}

module_init(xlan_init);
module_exit(xlan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XLAN");
MODULE_VERSION("0.1");
