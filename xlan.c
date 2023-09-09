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
#define NET4 CONFIG_XLAN_PREFIX4
#define NET6 CONFIG_XLAN_PREFIX6
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
    u32 ports;
    u32 last;
} xlan_path_s;

// NETWORK, HOST
// NN.NN.HH.HH NNNN:?:HHHH
typedef struct xlan_s {
    u16 vendor;
    u16 net4;   // NN.NN.
    u16 net6;   // NNNN::
    u16 host;   // .HH.HH ::HHHH LHOST
    u16 gw;     // .HH.HH ::HHHH RHOST, WHEN IT DOES NOT BELONG TO THE NET
    u16 lportsN;  // PHYSICAL INTERFACES
    u16 rportsN[HOSTS_N];
    net_device_s* physs[PORTS_N];
    xlan_path_s paths[HOSTS_N][64]; // POPCOUNT64()
    u64 seen[HOSTS_N][PORTS_N][PORTS_N]; // TODO: FIXME: ATOMIC
} xlan_s;

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;
    net_device_s* const phys = skb->dev;
    net_device_s* const virt = skb->dev->rx_handler_data;
    xlan_s* const xlan = netdev_priv(virt);

    const pkt_s* const pkt = SKB_MAC(skb) - offsetof(pkt_s, dst);

    // SO HANDLE O QUE FOR
    if (pkt->type != BE16(0x2562))
        return RX_HANDLER_PASS;

    // ASSERT: skb->type PKT_HOST
    const uint lhost = BE16(pkt->dst.host) % HOSTS_N;
    const uint lport = BE16(pkt->dst.port) % PORTS_N;
    const uint rhost = BE16(pkt->src.host) % HOSTS_N;
    const uint rport = BE16(pkt->src.port) % PORTS_N;

    // DISCARD THOSE
    if (xlan->host != lhost // NOT TO ME (POIS PODE TER RECEBIDO DEVIDO AO MODO PROMISCUO)
     || xlan->host == rhost
     || xlan->physs[lport] != phys // WRONG INTERFACE
     || virt->flags == 0) { // ->flags & UP
        kfree_skb(skb);
        return RX_HANDLER_CONSUMED;
    }

    //
    xlan->seen[rhost][rport][lport] = jiffies;

    skb->protocol = pkt->v4.version == 0x45 ?
        BE16(ETH_P_IP) :
        BE16(ETH_P_IPV6);
    skb->dev = virt;

    return RX_HANDLER_ANOTHER;
}

#define ROUNDS 5

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
        ( pkt->v4.dst.prefix  == xlan->net4 ?
          pkt->v4.dst.host    :  xlan->gw ) :
        ( pkt->v6.dst.prefix  == xlan->net6 ?
          pkt->v6.dst.host    :  xlan->gw ) ;

    if (rhost >= HOSTS_N)
        goto drop;

    // SELECT A PATH
    // OK: TCP | UDP | UDPLITE | SCTP | DCCP
    // FAIL: ICMP
    xlan_path_s* const path = &xlan->paths[rhost][__builtin_popcountll( (u64) ( v4
        ? pkt->v4.protocol      // IP PROTOCOL
        + (pkt->v4.src.w32[0]   // SRC ADDR
         * pkt->v4.dst.w32[0])  // DST ADDR
        + (pkt->v4.sport        // SRC PORT
         * pkt->v4.dport)       // DST PORT
        : (pkt->v6.protocol     // IP PROTOCOL
         * pkt->v6.flow8        // FLOW
         * pkt->v6.flow16)      // FLOW
        + (pkt->v6.src.w64[0]   // SRC ADDR
         ^ pkt->v6.src.w64[1])  // SRC ADDR
        + (pkt->v6.dst.w64[0]   // DST ADDR
         ^ pkt->v6.dst.w64[1])  // DST ADDR
        + (pkt->v6.sport        // SRC PORT
         * pkt->v6.dport)       // DST PORT
    ))];

    const uint lportsN = xlan->lportsN;
    const uint rportsN = xlan->rportsN[rhost];

    uint now   = jiffies;
    uint ports = path->ports;

    uint rport;
    uint lport;

    net_device_s* phys;

    uint c = 1 + ROUNDS * (lportsN * rportsN);

    foreach (r, ROUNDS) {

        // LIMIT
        if (c-- == 0)
            goto drop;

        // NOTE: MUDA A PORTA LOCAL COM MAIS FREQUENCIA, PARA QUE O SWITCH A DESCUBRA
        // for PORTS_N in range(7): assert len(set((_ // PORTS_N, _ % PORTS_N) for _ in range(PORTS_N*PORTS_N))) == PORTS_N*PORTS_N
        ports %= lportsN * rportsN;

        rport = ports / lportsN;
        lport = ports % lportsN;

        phys = xlan->physs[lport];

        if (phys && (phys->flags & IFF_UP) == IFF_UP) // IFF_RUNNING // IFF_LOWER_UP
            if (   ((now - path->last) <= (r*HZ)/5 || r == 4) // SE DEU UMA PAUSA, TROCA DE PORTA
                && ((now - xlan->seen[rhost][rport][lport]) <= (r*1*HZ)/1 || r == 4) // KNOWN TO WORK
            ) break;

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
    pkt->type       = BE16(0x2562);

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

    (void)extack;

    int ret;

    // TODO: XLAN MUST BE DOWN
    xlan_s* const xlan = netdev_priv(dev);

    const uint lport = 0; // TODO: FROM MAC ADDRESS

    if (phys == dev) 
        // ITSELF
        ret = -ELOOP;
    elif (0)
        // TODO: CANNOT BE OF XLAN TYPE
        ret = -EINVAL;
    elif (rtnl_dereference(phys->rx_handler) == xlan_in)
        // ALREADY
        ret = -EISCONN;    
    elif (xlan->physs[lport])
        // ALREADY
        ret = -EISCONN;    
    elif (phys->flags & IFF_LOOPBACK)
        // LOOPBACK
        ret = -EINVAL;    
    elif (phys->addr_len != ETH_ALEN)
        // NOT ETHERNET
        ret = -EINVAL;
    elif (xlan->lportsN == PORTS_N)
        // ALL SLOTS USED
        ret = -ENOSPC;
    elif (netdev_rx_handler_register(phys, xlan_in, dev) != 0)
        // FAILED TO ATTACH
        ret = -EBUSY;
    else {
        // HOOKED
        phys->rx_handler_data = dev;
        // HOLD IT
        dev_hold(phys);
        // REGISTER IT
        xlan->physs[lport] = phys;
        //
        if (xlan->lportsN <= lport)
            xlan->lportsN =  lport + 1;
        // SUCCESS
        ret = 0;
    }

    return ret;
}

static int xlan_unslave (net_device_s* dev, net_device_s* phys) {

    xlan_s* const xlan = netdev_priv(dev);

    net_device_s** const physs = xlan->physs;

    // TODO: XLAN MUST BE DOWN
    const uint lport = 0; // TODO: FROM MAC ADDRESS

    // MATCHES?
    if (physs[lport] != phys)
        return -ENOTCONN;

    // UNHOOK (IF ITS STILL HOOKED)
    if (rtnl_dereference(phys->rx_handler) == xlan_in) {
        phys->rx_handler_data = NULL;        
        netdev_rx_handler_unregister(phys);
    }

    // DROP IT
    dev_put(phys);

    // UNREGISTER IT
    physs[lport] = NULL;

    // RESET
    uint last = 0;

    foreach (i, PORTS_N)
        if (physs[i])
            last = i;

    xlan->lportsN = last + 1; 

    return 0;
}

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

    xlan->vendor  = BE16(VENDOR); // TODO: ip link set dev xlan addr 50:62:N4:N4:N6:N6
    xlan->net4    = BE16(NET4);
    xlan->net6    = BE16(NET6);
    xlan->host    = BE16(20);
    xlan->gw      = BE16(50);
    xlan->lportsN = 1;
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
