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

#define __f_hot __attribute__((hot))
#define __f_cold __attribute__((cold))

#ifndef __packed
#define __packed __attribute__((packed))
#endif

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

#define MTU     7600 // TODO: FIXME:

#define ETH_SIZE 14
#define IP4_SIZE 20
#define IP6_SIZE 40
#define UDP_SIZE  8
#define TCP_SIZE 20

#define ETH_O_DST      0
#define ETH_O_SRC      6
#define ETH_O_TYPE    12
#define ETH_O_IP      14

#define IP4_O_PROTO   9
#define IP4_O_SRC     12
#define IP4_O_DST     16
#define IP4_O_PORTS 20

#define IP6_O_VERSION  0
#define IP6_O_FLOW     2
#define IP6_O_PROTO    5
#define IP6_O_SRC      8
#define IP6_O_SRC_N    8
#define IP6_O_SRC_H   23
#define IP6_O_DST     24
#define IP6_O_DST_N   24
#define IP6_O_DST_H   39
#define IP6_O_PORTS   40

#include "xconf.h"

#define VENDOR  XCONF_XLAN_VENDOR
#define HOSTS_N XCONF_XLAN_HOSTS_N
#define PORTS_N XCONF_XLAN_PORTS_N

#define _NET4 0xC0000000
#define _NET6 0xFC00000000000000

#define NET4 ((u32)_NET4)
#define NET6 ((u64)_NET6)

#if !(VENDOR && VENDOR <= 0xFFFFFFFF && !(VENDOR & 0x01000000))
#error "BAD VENDOR"
#endif

#if !(2 <= HOSTS_N && HOSTS_N < 0xFF)
#error "BAD HOSTS N"
#endif

#if !(2 <= PORTS_N && PORTS_N < 0xFF)
#error "BAD PORTS N"
#endif

#if !(_NET4 && !(NET4 % HOSTS_N))
#error "BAD NET4"
#endif

#if !(NET6)
#error "BAD NET6"
#endif

#define MAC_VENDOR(mac) ((u32*)mac)[0]
#define MAC_HOST(mac)    ((u8*)mac)[4]
#define MAC_PORT(mac)    ((u8*)mac)[5]

#define dst_vendor  (*(u32*)(pkt + ETH_O_DST_V))
#define dst_host    (*(u8 *)(pkt + ETH_O_DST_H))
#define dst_port    (*(u8 *)(pkt + ETH_O_DST_P))
#define src_vendor  (*(u32*)(pkt + ETH_O_SRC_V))
#define src_host    (*(u8 *)(pkt + ETH_O_SRC_H))
#define src_port    (*(u8 *)(pkt + ETH_O_SRC_P))
#define pkt_type    (*(u16*)(pkt + ETH_O_TYPE))

#define proto4      (*(u8 *)(pkt + ETH_O_IP + IP4_O_PROTO))
#define addrs4      (*(u64*)(pkt + ETH_O_IP + IP4_O_SRC))
#define src4_net    (*(u32*)(pkt + ETH_O_IP + IP4_O_SRC_N))
#define src4_host   (*(u8 *)(pkt + ETH_O_IP + IP4_O_SRC_H))
#define dst4_net    (*(u32*)(pkt + ETH_O_IP + IP4_O_DST_N))
#define dst4_host   (*(u8 *)(pkt + ETH_O_IP + IP4_O_DST_H))
#define ports4      (*(u32*)(pkt + ETH_O_IP + IP4_O_PORTS))

#define flow6       (*(u16*)(pkt + ETH_O_IP + IP6_O_FLOW))
#define proto6      (*(u8 *)(pkt + ETH_O_IP + IP6_O_PROTO))
#define addrs6      ( (u64*)(pkt + ETH_O_IP + IP6_O_SRC))
#define src6_net    (*(u64*)(pkt + ETH_O_IP + IP6_O_SRC_N))
#define src6_host   (*(u8 *)(pkt + ETH_O_IP + IP6_O_SRC_H))
#define dst6_net    (*(u64*)(pkt + ETH_O_IP + IP6_O_DST_N))
#define dst6_host   (*(u8 *)(pkt + ETH_O_IP + IP6_O_DST_H))
#define ports6      (*(u32*)(pkt + ETH_O_IP + IP6_O_PORTS))

typedef struct xlan_stream_s {
    u32 ports;
    u32 last;
} xlan_stream_s;

typedef struct xlan_s {
    uint host;
    uint gw;
    net_device_s* ports[PORTS_N];
    xlan_stream_s paths[HOSTS_N][64]; // POPCOUNT64()
    u32 seen[HOSTS_N][PORTS_N][PORTS_N]; // TODO: FIXME: ATOMIC
} xlan_s;

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;
    net_device_s* const phys = skb->dev;
    net_device_s* const virt = skb->dev->rx_handler_data;
    xlan_s* const xlan = netdev_priv(virt);

    const void* const pkt = SKB_MAC(skb);

    // SO HANDLE O QUE FOR
    if (dst_vendor != BE32(VENDOR)
     || src_vendor != BE32(VENDOR))
        return RX_HANDLER_PASS;

    // ASSERT: skb->type PKT_HOST
    const uint lhost = dst_host;
    const uint lport = dst_port;
    const uint rhost = src_host;
    const uint rport = src_port;

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

    void* const pkt = SKB_NETWORK(skb) - ETH_SIZE;

    // CONFIRMA ESPACO
    if (PTR(pkt_eth) < SKB_HEAD(skb))
        goto drop;

    // NOTE: ASSUME QUE NÃO TEM IP OPTIONS
    const int v4 = skb->protocol == BE16(ETH_P_IP);

    // IDENTIFY DESTINATION
    const uint rhost = v4 ?
        ( (dst4_net & BE32(0xFFFFFF00U)) == BE32(NET4) ? dst4_host : xlan->gw ):
        (  dst6_net                      == BE64(NET6) ? dst6_host : xlan->gw );

    // É INVALIDO / ERA EXTERNO E NAO TEMOS GATEWAY / PARA SI MESMO
    if (rhost >= HOSTS_N
     || rhost == xlan->host)
        goto drop;

    // SELECT A PATH
    // OK: TCP | UDP | UDPLITE | SCTP | DCCP
    // FAIL: ICMP
    xlan_stream_s* const path = &xlan->paths[rhost][__builtin_popcountll( (u64) ( v4
        ? proto4 * ports4 + addrs4
        : proto6 * ports6 * flow6
        + addrs6[0] + addrs6[1]        
        + addrs6[2] + addrs6[3]        
    ))];

    uint now   = jiffies;
    uint ports = path->ports;

    foreach (r, ROUNDS) {

        // NOTE: MUDA A PORTA LOCAL COM MAIS FREQUENCIA, PARA QUE O SWITCH A DESCUBRA
        // for PORTS_N in range(7): assert len(set((_ // PORTS_N, _ % PORTS_N) for _ in range(PORTS_N*PORTS_N))) == PORTS_N*PORTS_N
        foreach (c, (PORTS_N * PORTS_N)) {
            ports %= PORTS_N * PORTS_N;

            const uint rport = ports / PORTS_N;
            const uint lport = ports % PORTS_N;

            net_device_s* const phys = xlan->ports[lport];

            if (phys && (phys->flags & IFF_UP) == IFF_UP && // IFF_RUNNING // IFF_LOWER_UP
                ( r == 4 || ( // NO ULTIMO ROUND FORCA MESMO ASSIM
                    (r*1*HZ)/5 >= (now - path->last) && // SE DEU UMA PAUSA, TROCA DE PORTA
                    (r*2*HZ)/1 >= (now - xlan->seen[rhost][rport][lport]) // KNOWN TO WORK
            ))) {
                //
                path->ports = ports;
                path->last  = now;

                // FILL ETHERNET HEADER
                dst_vendor = BE32(VENDOR);
                dst_host   = rhost;
                dst_port   = rport;
                src_vendor = BE32(VENDOR);
                src_host   = xlan->host;
                src_port   = lport;
                pkt_type   = skb->protocol;

                // UPDATE SKB
                skb->data       = PTR(pkt);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
                skb->mac_header = PTR(pkt) - SKB_HEAD(skb);
#else
                skb->mac_header = PTR(pkt);
#endif
                skb->len        = SKB_TAIL(skb) - PTR(pkt);
                skb->mac_len    = ETH_HLEN;
                skb->dev        = phys;

                // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
                // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
                // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
                dev_queue_xmit(skb);

                return NETDEV_TX_OK;
            }

            ports++;
        }
    }

drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int __f_cold xlan_up (net_device_s* const dev) {

    printk("XLAN: %s: UP\n", dev->name);

    return 0;
}

static int __f_cold xlan_down (net_device_s* const dev) {

    printk("XLAN: %s: DOWN\n", dev->name);

    return 0;
}

static int __f_cold xlan_enslave (net_device_s* dev, net_device_s* phys, struct netlink_ext_ack* extack) {

    enum {
        _ENSL_SUCCESS,
        _ENSL_ITSELF,
        _ENSL_ALREADY,
        _ENSL_OCCUPIED,
        _ENSL_NOT_ETHERNET,
        _ENSL_BAD_VENDOR,
        _ENSL_BAD_HOST,
        _ENSL_BAD_PORT,
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
        [_ENSL_BAD_VENDOR    ] = EINVAL,
        [_ENSL_BAD_HOST      ] = EINVAL,
        [_ENSL_BAD_PORT      ] = EINVAL,
        [_ENSL_ANOTHER_XLAN  ] = EINVAL,
        [_ENSL_ATTACH_FAILED ] = 1,
    };

    static const char* strs [__N] = {
        [_ENSL_SUCCESS       ] = "SUCCESS",
        [_ENSL_NOT_ETHERNET  ] = "FAILED: BAD PHYS - NOT ETHERNET",
        [_ENSL_ITSELF        ] = "FAILED: BAD PHYS - ITSELF",
        [_ENSL_ANOTHER_XLAN  ] = "FAILED: BAD PHYS - XLAN",
        [_ENSL_ALREADY       ] = "FAILED: PHYS IS ALREADY A PORT",
        [_ENSL_OCCUPIED      ] = "FAILED: PORT ALREADY HAS A PHYS",
        [_ENSL_BAD_VENDOR    ] = "FAILED: BAD MAC VENDOR",
        [_ENSL_BAD_HOST      ] = "FAILED: BAD MAC HOST",
        [_ENSL_BAD_PORT      ] = "FAILED: BAD MAC PORT",
        [_ENSL_ATTACH_FAILED ] = "FAILED: COULD NOT ATTACH",
    };

    xlan_s* const xlan = netdev_priv(dev);

    const void* const mac = PTR(dev->dev_addr);

    const uint port = MAC_PORT(mac);

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
    elif (MAC_VENDOR(mac) != BE32(VENDOR))
        // WRONG VENDOR
        ret = _ENSL_BAD_VENDOR;
    elif (MAC_HOST(host) != xlan->host)
        // WRONG HOST
        ret = _ENSL_BAD_HOST;
    elif (port >= PORTS_N)
        // BAD PORT
        ret = _ENSL_BAD_PORT;
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

static int __f_cold xlan_unslave (net_device_s* dev, net_device_s* phys) {

    xlan_s* const xlan = netdev_priv(dev);

    foreach (port, PORTS_N) {
        if (xlan->ports[port] == phys) {
            // UNREGISTER IT
            xlan->ports[port] = NULL;
            // UNHOOK (IF ITS STILL HOOKED)
            if (rtnl_dereference(phys->rx_handler) == xlan_in) {
                                 phys->rx_handler_data = NULL;
                netdev_rx_handler_unregister(phys);
            }
            // DROP IT
            dev_put(phys);
            printk("XLAN: %s: DETACHED ITFC %s FROM PORT %u\n",
                dev->name, phys->name, port);
            return 0;
        }
    }

    printk("XLAN: %s: CANNOT DETACHED ITFC %s FROM ANY PORT\n",
        dev->name, phys->name);

    return -ENOTCONN;
}

// ip link set dev xlan addr HH:GG
#define XLAN_INFO_LEN 2

static int __f_cold xlan_cfg (net_device_s* const dev, void* const addr) {

    if(netif_running(dev))
        return -EBUSY;

    // READ
    const uint host = ((const u8*)addr)[0];
    const uint gw   = ((const u8*)addr)[1];

    printk("XLAN: %s: CONFIGURE: HOST %u 0x%02x GW %u 0x%02x\n",
        dev->name, host, host, gw, gw);

    // VERIFY
    if (net4 && !(net4 % HOSTS_N) && net6 && host && host < HOSTS_N && gw < HOSTS_N && gw != host) {

        xlan_s* const xlan = netdev_priv(dev);

        // COMMIT
        xlan->host = host;
        xlan->gw   = gw ?: host;

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

static void __f_cold xlan_setup (net_device_s* const dev) {

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
    printk("XLAN: INIT - VENDOR 0x%04x NET4 0x%08x NET6 0x%016llX\n",
        VENDOR, NET4, (unsigned long long int)NET6);

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
