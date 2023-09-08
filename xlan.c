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

#define ETH_SIZE 14
#define IP4_SIZE 20
#define IP6_SIZE 40
#define UDP_SIZE  8
#define TCP_SIZE 20

#define IP4_O_PROTO   9
#define IP4_O_SRC     12
#define IP4_O_DST     16
#define IP4_O_PAYLOAD 20

#define IP6_O_PROTO   5
#define IP6_O_SRC     8
#define IP6_O_SRC1    8
#define IP6_O_SRC2    16
#define IP6_O_DST     24
#define IP6_O_DST1    24
#define IP6_O_DST2    32
#define IP6_O_PAYLOAD 40

#define ETH_IDX_DST_VENDOR 0
#define ETH_IDX_DST_HOST   1
#define ETH_IDX_DST_PORT   2
#define ETH_IDX_SRC_VENDOR 3
#define ETH_IDX_SRC_HOST   4
#define ETH_IDX_SRC_PORT   5
#define ETH_IDX_TYPE       6

#ifndef CONFIG_XLAN
#include "config.h"
#endif

//
#define VENDOR  CONFIG_XLAN_VENDOR
#define PREFIX4 CONFIG_XLAN_PREFIX4
#define PREFIX6 CONFIG_XLAN_PREFIX6
#define HOSTS_N CONFIG_XLAN_HOSTS_N
#define PORTS_N CONFIG_XLAN_PORTS_N // MMC DAS QUANTIDADES DE PORTAS DOS HOSTS DA REDE
#define MTU     CONFIG_XLAN_MTU

typedef struct xlan_path_s {
    u64 last;
    u64 ports;
} xlan_path_s;

typedef struct xlan_s {
    u16 vendor;
    u16 prefix4;
    u16 prefix6;
    u8 physN; // PHYSICAL INTERFACES
    u8 portsN; // NA REDE
    net_device_s* physs[PORTS_N];
    xlan_path_s paths[HOSTS_N][64];
} xlan_s;

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    net_device_s* const virt = skb->dev->rx_handler_data;

    const xlan_s* const xlan = netdev_priv(virt);

    const u16* const eth = SKB_MAC(skb);

    if (eth[ETH_IDX_DST_VENDOR] == xlan->vendor
     || eth[ETH_IDX_SRC_VENDOR] == xlan->vendor) {
        if (virt) { // ->flags & UP
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
        // DONT LET THE REAL INTERFACES SEE THEM UNLESS THEY'RE IN PROMISCUOUS MODE
        if (0) {
            // free skb
            return RX_HANDLER_CONSUMED;
        }
    }

    return RX_HANDLER_PASS;
}

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const dev) {

    xlan_s* const xlan = netdev_priv(dev);

    // ONLY LINEAR
    if (skb_linearize(skb))
        goto drop;

    void* const ip = SKB_NETWORK(skb);

    // NOTE: ASSUME QUE NÃO TEM IP OPTIONS
    const int v4 = *(u8*)ip == 0x45;

    // IDENTIFY HOSTS
    const uint lHost = v4 ? // ORIGIN
        (*(u16*)(ip + IP4_O_SRC) == xlan->prefix4) * BE16(*(u16*)(ip + IP4_O_SRC+2 )) :
        (*(u16*)(ip + IP6_O_SRC) == xlan->prefix6) * BE16(*(u16*)(ip + IP6_O_SRC+14)) ;
    const uint rHost = v4 ? // DESTINATION
        (*(u16*)(ip + IP4_O_DST) == xlan->prefix4) * BE16(*(u16*)(ip + IP4_O_DST+2 )) :
        (*(u16*)(ip + IP6_O_DST) == xlan->prefix6) * BE16(*(u16*)(ip + IP6_O_DST+14)) ;

    // SELECT A PATH
    // OK: TCP | UDP | UDPLITE | SCTP | DCCP
    // FAIL: ICMP
    xlan_path_s* const path = &xlan->paths[rHost % HOSTS_N][__builtin_popcountll( (u64) ( v4
        ? *(u8 *)(ip + IP4_O_PROTO)    // IP PROTOCOL
        + *(u64*)(ip + IP4_O_SRC)      // SRC ADDR, DST ADDR
        + *(u32*)(ip + IP4_O_PAYLOAD)  // SRC PORT, DST PORT
        : *(u8 *)(ip + IP6_O_PROTO)    // IP PROTOCOL
        + *(u64*)(ip + IP6_O_SRC1)     // SRC ADDR
        + *(u64*)(ip + IP6_O_SRC2)     // SRC ADDR
        + *(u64*)(ip + IP6_O_DST1)     // DST ADDR
        + *(u64*)(ip + IP6_O_DST2)     // DST ADDR
        + *(u32*)(ip + IP6_O_PAYLOAD)  // SRC PORT, DST PORT
    ))];

    u64 now   = jiffies;
    u64 last  = path->last;
    u64 ports = path->ports + (now - last) > HZ/5; // SE DEU UMA PAUSA, TROCA DE PORTA

    const uint portsN = xlan->portsN;

    uint rPort;
    uint lPort;
    
    net_device_s* phys;

    uint c = portsN * portsN + 1;

    while (1) {

        if (c-- == 0)
            // NO PHYS FOUND
            goto drop;
        
        // NOTE: MUDA A PORTA LOCAL COM MAIS FREQUENCIA, PARA QUE O SWITCH A DESCUBRA
        // for PORTS_N in range(7): assert len(set((_ // PORTS_N, _ % PORTS_N) for _ in range(PORTS_N*PORTS_N))) == PORTS_N*PORTS_N
        ports %= portsN * portsN;
        rPort = ports / portsN;
        lPort = ports % portsN;

        // SOMENTE SE ELA ESTIVER ATIVA E OK
        if ((phys = xlan->physs[lPort])) // IFF_RUNNING // IFF_LOWER_UP
            if ((phys->flags & IFF_UP) == IFF_UP)
                break;

        ports++;
    }

    path->ports = ports;
    path->last  = now;

    // INSERT ETHERNET HEADER
    u16* const eth = PTR(ip) - ETH_HLEN;

    // CONFIRMA ESPACO
    if (PTR(eth) < SKB_HEAD(skb))
        goto drop;

    // BUILD HEADER
    eth[ETH_IDX_DST_VENDOR] = xlan->vendor;
    eth[ETH_IDX_DST_HOST  ] = BE16(rHost);
    eth[ETH_IDX_DST_PORT  ] = BE16(rPort);
    eth[ETH_IDX_SRC_VENDOR] = xlan->vendor;
    eth[ETH_IDX_SRC_HOST  ] = BE16(lHost);
    eth[ETH_IDX_SRC_PORT  ] = BE16(lPort);
    eth[ETH_IDX_TYPE      ] = skb->protocol;

    // UPDATE SKB
    skb->data       = PTR(eth);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header = PTR(eth) - SKB_HEAD(skb);
#else
    skb->mac_header = PTR(eth);
#endif
    skb->len        = SKB_TAIL(skb) - PTR(eth);
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

    // TODO: XLAN MUST BE DOWN
    const uint physN  = xlan->physN;
    const uint portsN = xlan->portsN;

    if (physN) {
    
        printk("XLAN: %s: UP WITH MTU %d VENDOR %04X V4 %04X V6 %04X PORTS %u INTERFACES %u",
            dev->name,
            dev->mtu,
            BE16(xlan->vendor),
            BE16(xlan->prefix4),
            BE16(xlan->prefix6),
                 xlan->portsN,
                 xlan->physN
        );

        net_device_s** const physs = xlan->physs;

        uint i = 0;

        while (i != physN) {
            printk(" %s", physs[i]->name);
            dev_set_promiscuity(physs[i], 1);
            i++;
        }

        // FILL UP THE REMAINING
        while (i != portsN) {
            physs[i] =
            physs[i % physN];
                  i++;
        }

        printk("\n");

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
        return -EBUSY;
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
}

static int __init xlan_init (void) {

    // CREATE THE VIRTUAL INTERFACE
    // MAKE IT VISIBLE IN THE SYSTEM
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
