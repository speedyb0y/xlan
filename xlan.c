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

#ifndef CONFIG_XLAN
#include "config.h"
#endif

// FROM CONFIG
#define VENDOR  CONFIG_XLAN_VENDOR
#define PREFIX4 CONFIG_XLAN_PREFIX4
#define PREFIX6 CONFIG_XLAN_PREFIX6
#define HOSTS_N CONFIG_XLAN_HOSTS_N
#define PORTS_N CONFIG_XLAN_PORTS_N // MMC DAS QUANTIDADES DE PORTAS DOS HOSTS DA REDE
#define MTU     CONFIG_XLAN_MTU

#define ETH_SIZE 14
#define IP4_SIZE 20
#define IP6_SIZE 40
#define UDP_SIZE  8
#define TCP_SIZE 20

#define PKT_SIZE 64

#define __COMPACT __attribute__((packed))

typedef union v4_addr_s {
    u8  w8[4];
    u16 w16[2];
    u32 w32[1];
    struct {
        u16 prefix;
        u16 host;
    };
} v4_addr_s;

typedef union v6_addr_s {
    u8  w8[16];
    u16 w16[8];
    u32 w32[4];
    u64 w64[2];
    struct {
        u16 prefix;
        u16 _addr[6];
        u16 host;
    };
} v6_addr_s;

typedef union eth_addr_s {
    u8  addr[6];
    u16 addr16[3];
    struct {
        u16 vendor;
        u16 host;
        u16 port;
    };
} __COMPACT eth_addr_s;

typedef struct pkt_s {
    u16 _align[3];
    eth_addr_s src;
    eth_addr_s dst;
    u16 type;
    union {
        struct {
            u8  version;
            u8  tos;
            u16 size;
            u16 id;
            u16 frag;
            u8  ttl;
            u8  protocol;
            u16 cksum;
            v4_addr_s src;
            v4_addr_s dst;
            u16 sport;
            u16 dport;
            u16 _pad[10];
        } __COMPACT v4;
        struct {
            u8 version;
            u8 flow8;
            u16 flow16;
            u16 psize;
            u8 protocol;
            u8 ttl;
            v6_addr_s src;
            v6_addr_s dst;
            u16 sport;
            u16 dport;
        } __COMPACT v6;
    };
} __COMPACT pkt_s;

typedef struct xlan_path_s {
    u64 ports;
    u64 last;
} xlan_path_s;

typedef struct xlan_s {
    u16 vendor;
    u16 host;
    u16 gw;
    u16 prefix4;
    u16 prefix6;
    u16 physN; // PHYSICAL INTERFACES
    u16 portsN; // NA REDE
    net_device_s* physs[PORTS_N];
    xlan_path_s paths[HOSTS_N][64];
    u64 seen[HOSTS_N][PORTS_N]; // ULTIMA VEZ QUE RECEBEU ALGO COM SRC HOST:PORT; DAI TODA VEZ QUE TENTAR mandar pra ele, se ja faz tempo que nao o ve, muda
} xlan_s;

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;
    net_device_s* const phys = skb->dev;
    net_device_s* const virt = skb->dev->rx_handler_data;
    xlan_s* const xlan = netdev_priv(virt);

    const pkt_s* const pkt = SKB_MAC(skb) - offsetof(pkt_s, dst);

    // SO HANDLE O QUE FOR
    if (pkt->dst.vendor != xlan->vendor
     || pkt->src.vendor != xlan->vendor)
        return RX_HANDLER_PASS;

    // DROP CASES
    if (pkt->dst.host != xlan->host // NOT TO ME
     || pkt->src.host == xlan->host // FROM ME
     || phys != xlan->physs[BE16(pkt->dst.port) % PORTS_N] // WRONG INTERFACE
     || virt->flags == 0) { // ->flags & UP
        kfree_skb(skb);
        return RX_HANDLER_CONSUMED;
    }

    //
    xlan->seen
        [BE16(pkt->src.host) % HOSTS_N]
        [BE16(pkt->src.port) % PORTS_N]
            = jiffies;

#if 0 // PULA O ETHERNET HEADER
    // NOTE: skb->network_header JA ESTA CORRETO
    skb->data       = SKB_NETWORK(ip);
    skb->len        = SKB_TAIL(skb) - SKB_NETWORK(ip);
    skb->mac_header = skb->network_header;
    skb->mac_len    = 0;
#endif
    skb->pkt_type   = PACKET_HOST;
    skb->dev        = virt;

    return RX_HANDLER_ANOTHER;
}

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const dev) {

    BUILD_BUG_ON( sizeof(eth_addr_s) != ETH_ALEN );
    BUILD_BUG_ON( sizeof(v4_addr_s) != 4 );
    BUILD_BUG_ON( sizeof(v6_addr_s) != 16 );
    BUILD_BUG_ON( sizeof(pkt_s) != PKT_SIZE );

    xlan_s* const xlan = netdev_priv(dev);

    // ONLY LINEAR
    if (skb_linearize(skb))
        goto drop;

    pkt_s* const pkt = SKB_NETWORK(skb) - offsetof(pkt_s, v4);

    // CONFIRMA ESPACO
    if (PTR(&pkt->dst) < SKB_HEAD(skb))
        goto drop;

    // NOTE: ASSUME QUE NÃO TEM IP OPTIONS
    const int v4 = pkt->type == BE16(ETH_P_IP);

    // IDENTIFY DESTINATION
    const uint rhost = v4 ?
        ( pkt->v4.dst.prefix  == xlan->prefix4 ?
          pkt->v4.dst.host    :  xlan->gw ) :
        ( pkt->v6.dst.prefix  == xlan->prefix6 ?
          pkt->v6.dst.host    :  xlan->gw ) ;

    if (rhost >= HOSTS_N)
        goto drop;

    // SELECT A PATH
    // OK: TCP | UDP | UDPLITE | SCTP | DCCP
    // FAIL: ICMP
    xlan_path_s* const path = &xlan->paths[rhost][__builtin_popcountll( (u64) ( v4
        ? pkt->v4.protocol      // IP PROTOCOL
        + pkt->v4.src.w32[0]    // SRC ADDR
        * pkt->v4.dst.w32[0]    // DST ADDR
        + pkt->v4.sport         // SRC PORT
        * pkt->v4.dport         // DST PORT
        : pkt->v6.protocol      // IP PROTOCOL
        + pkt->v6.flow8         // FLOW
        + pkt->v6.flow16        // FLOW
        + pkt->v6.src.w64[0]    // SRC ADDR
        + pkt->v6.src.w64[1]    // SRC ADDR
        + pkt->v6.dst.w64[0]    // DST ADDR
        + pkt->v6.dst.w64[1]    // DST ADDR
        + pkt->v6.sport         // SRC PORT
        * pkt->v6.dport         // DST PORT
    ))];

    const uint portsN = xlan->portsN;

    u64 now   = jiffies;
    u64 last  = path->last;
    uint ports = path->ports;

    ports += (now - last) > HZ/5 // SE DEU UMA PAUSA, TROCA DE PORTA
        || (now - xlan->seen[rhost][ports/portsN]) > 2*HZ;

    uint rport;
    uint lport;

    net_device_s* phys;

    uint c = portsN * portsN + 1;

    while (1) {

        if (c-- == 0)
            // NO PHYS FOUND
            goto drop;

        // NOTE: MUDA A PORTA LOCAL COM MAIS FREQUENCIA, PARA QUE O SWITCH A DESCUBRA
        // for PORTS_N in range(7): assert len(set((_ // PORTS_N, _ % PORTS_N) for _ in range(PORTS_N*PORTS_N))) == PORTS_N*PORTS_N
        ports %= portsN * portsN;
        rport = ports / portsN;
        lport = ports % portsN;

        // SOMENTE SE ELA ESTIVER ATIVA E OK
        if ((phys = xlan->physs[lport])) // IFF_RUNNING // IFF_LOWER_UP
            if ((phys->flags & IFF_UP) == IFF_UP)
                break;

        ports++;
    }

    path->ports = ports;
    path->last  = now;

    // INSERT ETHERNET HEADER
    pkt->dst.vendor =      xlan->vendor;
    pkt->dst.host   = BE16(rhost);
    pkt->dst.port   = BE16(rport);
    pkt->src.vendor =      xlan->vendor;
    pkt->src.host   =      xlan->host;
    pkt->src.port   = BE16(lport);
    pkt->type       = skb->protocol;

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

    xlan_s* const xlan = netdev_priv(dev);
    net_device_s** const physs = xlan->physs;
    // TODO: XLAN MUST BE DOWN
    const uint physN  = xlan->physN;
    const uint portsN = xlan->portsN;

    if (physN) {

        // FILL UP THE REMAINING
        for (uint i = physN; i != portsN; i++)
            physs[i] =
            physs[i % physN];

        printk("XLAN: %s: UP WITH MTU %d VENDOR %04X V4 %04X V6 %04X PORTS %u INTERFACES %u\n",
            dev->name,
            dev->mtu,
            BE16(xlan->vendor),
            BE16(xlan->prefix4),
            BE16(xlan->prefix6),
                 xlan->portsN,
                 xlan->physN
        );

        foreach (i, portsN)
            printk("XLAN: %s: PORT %u PHYS %s\n", dev->name, i, physs[i]->name);

        foreach (i, physN)
            dev_set_promiscuity(physs[i], 1);

    } else
        printk("XLAN: %s: UP WITHOUT INTERFACES\n", dev->name);

    return 0;
}

static int xlan_down (net_device_s* const dev) {

    xlan_s* const xlan = netdev_priv(dev);

    printk("XLAN: %s: DOWN\n", dev->name);

    // TODO: XLAN MUST BE UP
    const uint physN = xlan->physN;

    net_device_s* const* const physs = xlan->physs;

    foreach (i, physN)
        dev_set_promiscuity(physs[i], -1);

    return 0;
}

static int xlan_enslave (net_device_s* dev, net_device_s* phys, struct netlink_ext_ack* extack) {

    (void)extack;

    // TODO: XLAN MUST BE DOWN
    xlan_s* const xlan = netdev_priv(dev);

    //
    if (rtnl_dereference(phys->rx_handler) == xlan_in) {
        printk("XLAN: ALREADY ATTACHED\n");
        return -EISCONN;
    }

    //
    if (xlan->physN
     == xlan->portsN) {
        printk("XLAN: TOO MANY\n");
        return -ENOSPC;
    }

    // NEGA ELA MESMA
    if (phys == dev) {
        printk("XLAN: SAME\n");
        return -ELOOP;
    }

    // NEGA LOOPBACK
    if (phys->flags & IFF_LOOPBACK) {
        printk("XLAN: LOOPBACK\n");
        return -EINVAL;
    }

    // SOMENTE ETHERNET
    if (phys->addr_len != ETH_ALEN) {
        printk("XLAN: NOT ETHERNET\n");
        return -EINVAL;
    }

    //
    if (netdev_rx_handler_register(phys, xlan_in, dev) != 0) {
        printk("XLAN: ATTACH FAILED\n");
        return -EBUSY;
    }

    phys->rx_handler_data = dev;

    dev_hold(phys);

    //
    xlan->physs [
    xlan->physN++
        ] = phys;

    return 0;
}

static int xlan_unslave (net_device_s* dev, net_device_s* phys) {

    xlan_s* const xlan = netdev_priv(dev);

    net_device_s** const physs = xlan->physs;

    // TODO: XLAN MUST BE DOWN

    if (rtnl_dereference(phys->rx_handler) != xlan_in)
        // NOT USING IT
        return -EINVAL;

    phys->rx_handler_data = NULL;

    // TODO:
    foreach (i, xlan->portsN)
        if (physs[i] == phys)
            physs[i] = NULL;

    //
    netdev_rx_handler_unregister(phys);

    dev_put(phys);

    return 0;
}

// struct net_device*  (*ndo_get_xmit_slave)(struct net_device *dev,                              struct sk_buff *skb,                              bool all_slaves);
//  struct net_device*  (*ndo_sk_get_lower_dev)(struct net_device *dev,                            struct sock *sk);

static const net_device_ops_s xlanDevOps = {
    .ndo_init             = NULL,
    .ndo_open             = xlan_up,
    .ndo_stop             = xlan_down,
    .ndo_start_xmit       = xlan_out,
    .ndo_set_mac_address  = NULL,
    .ndo_add_slave        = xlan_enslave,
    .ndo_del_slave        = xlan_unslave,
    // TODO: SET MTU - NAO EH PARA SETAR AQUI E SIM NO ROUTE
};

static void xlan_setup (net_device_s* const dev) {

    dev->netdev_ops      = &xlanDevOps;
    dev->header_ops      = NULL;
    dev->type            = ARPHRD_NONE;
    dev->addr_len        = 0;
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
    xlan_s* const xlan = netdev_priv(dev);

    memset(xlan, 0, sizeof(*xlan));

    xlan->vendor  = BE16(VENDOR);
    xlan->prefix4 = BE16(PREFIX4);
    xlan->prefix6 = BE16(PREFIX6);
    xlan->physN   = 0;
    xlan->portsN  = PORTS_N;
    xlan->host    = BE16(20);
    xlan->gw      = BE16(50);
}

static int __init xlan_init (void) {

    // CREATE THE VIRTUAL INTERFACE
    // MAKE IT VISIBLE IN THE SYSTEM
    printk("XLAN: INIT\n");

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
