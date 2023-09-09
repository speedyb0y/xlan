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
        u16 net;
        u16 host;
    };
} v4_addr_s;

typedef union v6_addr_s {
    u8  w8[16];
    u16 w16[8];
    u32 w32[4];
    u64 w64[2];
    struct {
        u16 net;
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

typedef struct xlan_stream_s {
    u32 ports;
    u32 last;
} xlan_stream_s;

typedef struct xlan_rh_s {
    u16 portsN;
    u32 rseen[PORTS_N];
    u32 lseen[PORTS_N][PORTS_N]; // TODO: FIXME: ATOMIC
    xlan_stream_s paths[64]; // POPCOUNT64()
} xlan_rh_s;

// NETWORK, HOST
// NN.NN.HH.HH NNNN:?:HHHH
typedef struct xlan_s {
    u16 vendor;
    u16 net4;   // NN.NN.
    u16 net6;   // NNNN::
    u16 host;   // .HH.HH ::HHHH LHOST
    u16 gw;     // .HH.HH ::HHHH RHOST, WHEN IT DOES NOT BELONG TO THE NET
    u16 portsN;  // PHYSICAL INTERFACES
    net_device_s* ports[PORTS_N];
    xlan_rh_s hosts[HOSTS_N];
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
     || xlan->ports[lport] != phys // WRONG INTERFACE
     || virt->flags == 0) { // ->flags & UP
        kfree_skb(skb);
        return RX_HANDLER_CONSUMED;
    }

    //
    xlan_rh_s* const rh = &xlan->hosts[rhost];
    
    rh->lseen[rport][lport] = jiffies;
    rh->rseen[rport]        = jiffies;

    // KEEP REMOTE PORTS NUMBER FRESH
    const u64 expired = jiffies - 30*HZ;

    if (rh->rseen[rh->portsN - 1] < expired) {
        uint last = 0;
        foreach (i, PORTS_N) {
            if (rh->rseen[i] >= expired)
                last = i;
        }   rh->portsN =  last + 1;
    } elif (rh->portsN <= rport)
            rh->portsN =  rport + 1;

    skb->protocol = pkt->v4.version == 0x45 ?
        BE16(ETH_P_IP) :
        BE16(ETH_P_IPV6);
    skb->dev = virt;

    return RX_HANDLER_ANOTHER;
}

#define ROUNDS 5

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const dev) {

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
        ( pkt->v4.dst.net == xlan->net4 ? BE16(pkt->v4.dst.host) : xlan->gw ):
        ( pkt->v6.dst.net == xlan->net6 ? BE16(pkt->v6.dst.host) : xlan->gw );

    if (rhost >= HOSTS_N)
        goto drop;

    xlan_rh_s* const rh = &xlan->hosts[rhost];

    // SELECT A PATH
    // OK: TCP | UDP | UDPLITE | SCTP | DCCP
    // FAIL: ICMP
    xlan_stream_s* const path = &rh->paths[__builtin_popcountll( (u64) ( v4
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

    const uint lportsN = xlan->portsN;
    const uint rportsN =   rh->portsN;

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

        phys = xlan->ports[lport];

        if (phys && (phys->flags & IFF_UP) == IFF_UP && // IFF_RUNNING // IFF_LOWER_UP
            ( r == 4 || ( // NO ULTIMO ROUND FORCA MESMO ASSIM
                (r*1*HZ)/5 >= (now - path->last) && // SE DEU UMA PAUSA, TROCA DE PORTA
                (r*2*HZ)/1 >= (now - rh->lseen[rport][lport]) // KNOWN TO WORK
            ))) break;

        ports++;
    }

    path->ports = ports;
    path->last  = now;

    // INSERT ETHERNET HEADER
    pkt->dst.vendor =      xlan->vendor;
    pkt->dst.host   = BE16(rhost);
    pkt->dst.port   = BE16(rport);
    pkt->src.vendor =      xlan->vendor;
    pkt->src.host   = BE16(xlan->host);
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

    enum {
        __X_SUCCESS,
        __X_ITSELF,
        __X_ALREADY,
        __X_ATTACH_FAILED,
        __X_NOT_ETHERNET,
        __X_WRONG_MAC,
        __X_INVALID_PORT,
        __X_ANOTHER_XLAN,
        __X_PORT_HIGHER,
        __N,
    };

    static const u16 codes[__N] ={
        [__X_SUCCESS] = 0,
        [__X_NOT_ETHERNET] = -EINVAL,
        [__X_ITSELF] = -ELOOP,
        [__X_ALREADY] = -1,
        [__X_WRONG_MAC] = -EINVAL,
        [__X_INVALID_PORT]  = -EINVAL,
        [__X_ATTACH_FAILED] = -EBUSY,
        [__X_ANOTHER_XLAN] = -EINVAL,
        [__X_PORT_HIGHER] = -ENOSPC,
    };

    static const char* strs[__N] = {
        [__X_SUCCESS] = "SUCCESS",
        [__X_NOT_ETHERNET] = "FAILED: NOT ETHERNET",
        [__X_ALREADY] = "FAILED: ALREADY",
        [__X_ITSELF] = "FAILED: ITSELF",
        [__X_WRONG_MAC] = "FAILED: WRONG MAC",
        [__X_ATTACH_FAILED] = "FAILED: COULD NOT ATTACH",
        [__X_INVALID_PORT] = "FAILED: INVALID PORT",
        [__X_ANOTHER_XLAN] = "",
        [__X_PORT_HIGHER] = "__X_PORT_HIGHER",
    };

    (void)extack;

    uint ret;

    xlan_s* const xlan = netdev_priv(dev);

    const u8* const mac = dev->dev_addr;

    const uint vendor = BE16(((const eth_addr_s*)mac)->vendor);
    const uint host   = BE16(((const eth_addr_s*)mac)->host);
    const uint port   = BE16(((const eth_addr_s*)mac)->port);

    printk("XLAN: %s: ENSLAVE ITFC %s: VENDOR 0x%04X HOST %u PORT %u MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
        dev->name, phys->name, vendor, host, port,
        mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5]);

    if (phys == dev) 
        // ITSELF
        ret = __X_ITSELF;
    elif (0)
        // TODO: CANNOT BE OF XLAN TYPE
        ret = __X_ANOTHER_XLAN;
    elif (rtnl_dereference(phys->rx_handler) == xlan_in)
        // ALREADY
        ret = __X_ALREADY;    
    elif (xlan->ports[port])
        // ALREADY
        ret = __X_ALREADY;    
    elif (phys->flags & IFF_LOOPBACK)
        // LOOPBACK
        ret = __X_NOT_ETHERNET;    
    elif (phys->addr_len != ETH_ALEN)
        // NOT ETHERNET
        ret = __X_NOT_ETHERNET;
    elif (port >= PORTS_N)
        // INVALID
        ret = __X_INVALID_PORT;
    elif (vendor != BE16(xlan->vendor)
       || host   !=      xlan->host)
        // WRONG MAC
        ret = __X_WRONG_MAC;
    elif (port >= xlan->portsN)
        // NOT CONFIGURED FOR IT
        ret = __X_PORT_HIGHER;
    elif (netdev_rx_handler_register(phys, xlan_in, dev) != 0)
        // FAILED TO ATTACH
        ret = __X_ATTACH_FAILED;
    else {
        // HOOKED
        phys->rx_handler_data = dev;
        // HOLD IT
        dev_hold(phys);
        // REGISTER IT
        xlan->ports[port] = phys;
        // SUCCESS
        ret = __X_SUCCESS;
    }

    printk("XLAN: %s\n", strs[ret]);
    return -(int)codes[ret];
}

static int xlan_unslave (net_device_s* dev, net_device_s* phys) {

    xlan_s* const xlan = netdev_priv(dev);

    const uint port = BE16(((const eth_addr_s*)dev->dev_addr)->port);
    
    printk("XLAN: %s: UNSLAVE ITFC %s: PORT %u\n",
        dev->name, phys->name, port);

    // MATCHES?
    if (xlan->ports[port] != phys) {
        printk("XLAN: ITFC IS NOT PORT\n");
        return -ENOTCONN;
    }

    // UNHOOK (IF ITS STILL HOOKED)
    if (rtnl_dereference(phys->rx_handler) == xlan_in) {
                         phys->rx_handler_data = NULL;        
        netdev_rx_handler_unregister(phys);
    }

    // DROP IT
    dev_put(phys);

    // UNREGISTER IT
    xlan->ports[port] = NULL;

    return 0;
}

// ip link set dev xlan addr 50:62:N4:N4:N6:N6:HH:HH:GG:GG
#define XLAN_INFO_LEN 12
typedef struct xlan_info_s {
    u16 vendor;
    u16 net4;
    u16 net6;
    u16 host;
    u16 gw;    
    u16 portsN;
    u16 _pad[2];
} xlan_info_s;

static int xlan_cfg (net_device_s* const dev, void* const addr) {

	if(netif_running(dev))
		return -EBUSY;

    const xlan_info_s* const info = addr;

    // READ
    const uint vendor = BE16(info->vendor);
    const uint net4   = BE16(info->net4);
    const uint net6   = BE16(info->net6);
    const uint host   = BE16(info->host);
    const uint gw     = BE16(info->gw);
    const uint portsN = BE16(info->portsN);

    printk("XLAN: %s: CONFIGURING: VENDOR 0x%04X HOST %u GW %u PORTS %u NET4 0x%04X NET6 0x%04X\n",
        dev->name, vendor, host, gw, portsN, net4, net6);

    // VERIFY
    if ((vendor & 0x0100) == 0
      && vendor != 0
      && net4 != 0
      && net6 != 0
      && host != 0
      && gw != host
      && portsN >= 1
      && portsN <= PORTS_N) {

        xlan_s* const xlan = netdev_priv(dev);

        // COMMIT
        xlan->vendor = BE16(vendor);
        xlan->net4   = BE16(net4);
        xlan->net6   = BE16(net6);
        xlan->host   = host;
        xlan->gw     = gw;
        xlan->portsN = portsN;

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
    xlan_s* const xlan = netdev_priv(dev);

    memset(xlan, 0, sizeof(*xlan));

    xlan->portsN = 1;
}

static int __init xlan_init (void) {

    // CREATE THE VIRTUAL INTERFACE
    // MAKE IT VISIBLE IN THE SYSTEM
    printk("XLAN: INIT\n");

    BUILD_BUG_ON( sizeof(eth_addr_s) != ETH_ALEN );
    BUILD_BUG_ON( sizeof(v4_addr_s) != 4 );
    BUILD_BUG_ON( sizeof(v6_addr_s) != 16 );
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
