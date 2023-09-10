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

#include "xconf.h"

#define VENDOR  XCONF_XLAN_VENDOR
#define HOSTS_N XCONF_XLAN_HOSTS_N
#define PORTS_N XCONF_XLAN_PORTS_N
#define _NET4   XCONF_XLAN_NET4
#define _NET6   XCONF_XLAN_NET6
#define HOST    XCONF_XLAN_HOST
#define GW      XCONF_XLAN_GW

#if !(VENDOR && VENDOR <= 0xFFFFFFFF && !(VENDOR & 0x01000000))
#error "BAD VENDOR"
#endif

#if !(2 <= HOSTS_N && HOSTS_N < 0xFF)
#error "BAD HOSTS N"
#endif

#if !(2 <= PORTS_N && PORTS_N < 0xFF)
#error "BAD PORTS N"
#endif

#if !(_NET4 && !(_NET4 % HOSTS_N))
#error "BAD NET4"
#endif

#if !(_NET6)
#error "BAD NET6"
#endif

#if !(HOST && HOST < HOSTS_N)
#error "BAD HOST"
#endif

#if !(GW != HOST && GW < HOSTS_N)
#error "BAD GW"
#endif

#if GW == 0
#undef GW
#define GW HOST
#endif

#define ETH_O_DST      0
#define ETH_O_DST_V    0
#define ETH_O_DST_H    4
#define ETH_O_DST_P    5
#define ETH_O_SRC      6
#define ETH_O_SRC_V    6
#define ETH_O_SRC_H   10
#define ETH_O_SRC_P   11
#define ETH_O_TYPE    12
#define ETH_SIZE      14

#define IP4_O_PROTO   9
#define IP4_O_SRC     12
#define IP4_O_SRC_N   12
#define IP4_O_SRC_H   15
#define IP4_O_DST     16
#define IP4_O_DST_N   16
#define IP4_O_DST_H   19
#define IP4_SIZE      20

#define IP6_O_VERSION  0
#define IP6_O_FLOW     2
#define IP6_O_PROTO    5
#define IP6_O_SRC      8
#define IP6_O_SRC_N    8
#define IP6_O_SRC_H   23
#define IP6_O_DST     24
#define IP6_O_DST_N   24
#define IP6_O_DST_H   39
#define IP6_SIZE      40

#define NET4 ((u32)_NET4)
#define NET6 ((u64)_NET6)

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

#define proto4      (*(u8 *)(pkt + ETH_SIZE + IP4_O_PROTO))
#define addrs4      (*(u64*)(pkt + ETH_SIZE + IP4_O_SRC))
#define src4_net    (*(u32*)(pkt + ETH_SIZE + IP4_O_SRC_N))
#define src4_host   (*(u8 *)(pkt + ETH_SIZE + IP4_O_SRC_H))
#define dst4_net    (*(u32*)(pkt + ETH_SIZE + IP4_O_DST_N))
#define dst4_host   (*(u8 *)(pkt + ETH_SIZE + IP4_O_DST_H))
#define ports4      (*(u32*)(pkt + ETH_SIZE + IP4_SIZE))

#define flow6       (*(u16*)(pkt + ETH_SIZE + IP6_O_FLOW))
#define proto6      (*(u8 *)(pkt + ETH_SIZE + IP6_O_PROTO))
#define addrs6      ( (u64*)(pkt + ETH_SIZE + IP6_O_SRC))
#define src6_net    (*(u64*)(pkt + ETH_SIZE + IP6_O_SRC_N))
#define src6_host   (*(u8 *)(pkt + ETH_SIZE + IP6_O_SRC_H))
#define dst6_net    (*(u64*)(pkt + ETH_SIZE + IP6_O_DST_N))
#define dst6_host   (*(u8 *)(pkt + ETH_SIZE + IP6_O_DST_H))
#define ports6      (*(u32*)(pkt + ETH_SIZE + IP6_SIZE))

typedef struct xlan_stream_s {
    u32 ports;
    u32 last;
} xlan_stream_s;

static net_device_s* xlan;
static net_device_s* physs[PORTS_N];
static xlan_stream_s paths[HOSTS_N][64]; // POPCOUNT64()
static u32 seen[HOSTS_N][PORTS_N][PORTS_N]; // TODO: FIXME: ATOMIC

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

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
    if (rhost == HOST
     || rhost >= HOSTS_N
     || lhost != HOST // NOT TO ME (POIS PODE TER RECEBIDO DEVIDO AO MODO PROMISCUO)
     || lport >= PORTS_N
     || rport >= PORTS_N
     || skb->dev != physs[lport] // WRONG INTERFACE
     || xlan->flags == 0) { // ->flags & UP
        kfree_skb(skb);
        return RX_HANDLER_CONSUMED;
    }

    //
    seen[rhost][rport][lport] = jiffies;

    skb->dev = xlan;

    return RX_HANDLER_ANOTHER;
}

#define ROUNDS 5

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const xlan) {

    // ONLY LINEAR
    if (skb_linearize(skb))
        goto drop;

    void* const pkt = SKB_NETWORK(skb) - ETH_SIZE;

    // CONFIRMA ESPACO
    if (PTR(pkt) < SKB_HEAD(skb))
        goto drop;

    // NOTE: ASSUME QUE NÃO TEM IP OPTIONS
    const int v4 = skb->protocol == BE16(ETH_P_IP);

    // IDENTIFY DESTINATION
    const uint rhost = v4 ?
        ( (dst4_net & BE32(0xFFFFFF00U)) == BE32(NET4) ? dst4_host : GW ):
        (  dst6_net                      == BE64(NET6) ? dst6_host : GW );

    // É INVALIDO / ERA EXTERNO E NAO TEMOS GATEWAY / PARA SI MESMO
    if (rhost >= HOSTS_N
     || rhost == HOST)
        goto drop;

    // SELECT A PATH
    // OK: TCP | UDP | UDPLITE | SCTP | DCCP
    // FAIL: ICMP
    xlan_stream_s* const path = &paths[rhost][__builtin_popcountll( (u64) ( v4
        ? proto4 * ports4 + addrs4
        : proto6 * ports6 * flow6
        + addrs6[0] + addrs6[1]        
        + addrs6[2] + addrs6[3]        
    ))];

    uint now   = jiffies;
    uint last  = path->last;
    uint ports = path->ports;

    foreach (r, ROUNDS) {

        // NOTE: MUDA A PORTA LOCAL COM MAIS FREQUENCIA, PARA QUE O SWITCH A DESCUBRA
        // for PORTS_N in range(7): assert len(set((_ // PORTS_N, _ % PORTS_N) for _ in range(PORTS_N*PORTS_N))) == PORTS_N*PORTS_N
        foreach (c, (PORTS_N * PORTS_N)) {
            ports %= PORTS_N * PORTS_N;

            const uint rport = ports / PORTS_N;
            const uint lport = ports % PORTS_N;

            net_device_s* const phys = physs[lport];

            if (phys && (phys->flags & IFF_UP) == IFF_UP && // IFF_RUNNING // IFF_LOWER_UP
                ( r == 4 || ( // NO ULTIMO ROUND FORCA MESMO ASSIM
                    (r*1*HZ)/5 >= (now - last) && // SE DEU UMA PAUSA, TROCA DE PORTA
                    (r*2*HZ)/1 >= (now - seen[rhost][rport][lport]) // KNOWN TO WORK
            ))) {
                //
                path->ports = ports;
                path->last  = now;

                // FILL ETHERNET HEADER
                dst_vendor = BE32(VENDOR);
                dst_host   = rhost;
                dst_port   = rport;
                src_vendor = BE32(VENDOR);
                src_host   = HOST;
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

static int __f_cold xlan_down (net_device_s* const xlan) {

    printk("XLAN: %s DOWN\n", xlan->name);

    return 0;
}

static int __f_cold xlan_up (net_device_s* const xlan) {

    printk("XLAN: %s UP\n", xlan->name);

    return 0;
}

static int __f_cold xlan_enslave (net_device_s* xlan, net_device_s* phys, struct netlink_ext_ack* extack) {

    const u8* const mac = PTR(phys->dev_addr);

    const uint vendor = MAC_VENDOR(mac);
    const uint host   = MAC_HOST(mac);
    const uint port   = MAC_PORT(mac);

    printk("XLAN: %s: ENSLAVE PHYS %s: VENDOR 0x%04X HOST %u PORT %u MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
        xlan->name, phys->name, vendor, host, port,
        mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5]);

    if (vendor != VENDOR)
        printk("XLAN: WARNING: WRONG VENDOR\n");

    if (mac != HOST)
        printk("XLAN: WARNING: WRONG HOST\n");

    if (port >= PORTS_N) {
        printk("XLAN: FAILED: BAD PORT\n");
        return -EINVAL;
    }

    if (physs[port] == phys) {
        printk("XLAN: FAILED: PHYS ALREADY ATTACHED AS THIS PORT\n");
        return -EISCONN;
    }

    if (physs[port]) {
        printk("XLAN: FAILED: OTHER PHYS ATTACHED AS THIS PORT\n");
        return -EEXIST;
    }
    
    if (phys == xlan
     || phys->flags & IFF_LOOPBACK
     || phys->addr_len != ETH_ALEN) {
        printk("XLAN: FAILED: BAD PHYS (ITSELF / LOOPBACK / NOT ETHERNET)\n");
        return -EINVAL;
    }

    if (netdev_is_rx_handler_busy(phys)) {
        printk("XLAN: FAILED: PHYS ALREADY HAS A HANDLER\n");
        return -EBUSY;
    }

    if (netdev_rx_handler_register(phys, xlan_in, NULL) != 0) {
        printk("XLAN: FAILED: FAILED TO ATTACH HANDLER\n");
        return -1;
    }

    // HOLD IT
    dev_hold(phys);
    
    // REGISTER IT
    physs[port] = phys;

    return 0;
}

static int __f_cold xlan_unslave (net_device_s* xlan, net_device_s* phys) {

    foreach (p, PORTS_N) {
        if (physs[p] == phys) {            
            physs[p] = NULL; // UNREGISTER
            netdev_rx_handler_unregister(phys); // UNHOOK
            dev_put(phys); // DROP
            printk("XLAN: DETACHED PHYS %s FROM PORT %u\n", phys->name, p);
            return 0;
        }
    }

    printk("XLAN: CANNOT DETACH PHYS %s FROM ANY PORT\n", phys->name);

    return -ENOTCONN;
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

static void __f_cold xlan_setup (net_device_s* const dev) {

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
    dev->mtu             = ETH_DATA_LEN;
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
}

static int __init xlan_init (void) {

    // CREATE THE VIRTUAL INTERFACE
    // MAKE IT VISIBLE IN THE SYSTEM
    printk("XLAN: INIT - VENDOR 0x%04x HOST %u %02X GW %u %02X NET4 0x%08x NET6 0x%016llX\n",
        VENDOR, HOST, HOST, GW, GW, NET4, (unsigned long long int)NET6);

    memset(physs, 0, sizeof(physs));
    memset(paths, 0, sizeof(paths));
    memset(seen,  0, sizeof(seen));

    //
    xlan = alloc_netdev(0, "xlan", NET_NAME_USER, xlan_setup);
    //
    register_netdev(xlan);

    return 0;
}

static void __exit xlan_exit (void) {

}

module_init(xlan_init);
module_exit(xlan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XLAN");
MODULE_VERSION("0.1");
