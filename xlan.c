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
#include <linux/timer.h>
#include <net/ip.h>
#include <net/inet_common.h>
#include <net/addrconf.h>

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

// TODO: FIXME:
typedef typeof(jiffies) jiffies_t;

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

#define HOSTS_N 256 // 0xFF + 1
#define PORTS_N 4

#define _NET4 XCONF_XLAN_NET4
#define _NET6 XCONF_XLAN_NET6
#define HOST  XCONF_XLAN_HOST
#define GW    XCONF_XLAN_GW

#define XLAN_ANNOUNCE_DELAY    (XCONF_XLAN_ANNOUNCE_DELAY    * HZ) // AFTER SYSTEM BOOT
#define XLAN_ANNOUNCE_INTERVAL (XCONF_XLAN_ANNOUNCE_INTERVAL * HZ)

#if !(_NET4 && _NET4 <= 0xFFFFFFFF && !(_NET4 & 0xFF))
#error "BAD NET4"
#endif

#if !(_NET6)
#error "BAD NET6"
#endif

#if !(HOST < HOSTS_N && HOST)
#error "BAD HOST"
#endif

#if !(GW < HOSTS_N)
#error "BAD GW"
#endif

#define ETH_O_DST      0
#define ETH_O_DST_V    0
#define ETH_O_DST_H    4
#define ETH_O_DST_P    5
#define ETH_O_SRC      6
#define ETH_O_SRC_V    6
#define ETH_O_SRC_H   10
#define ETH_O_SRC_P   11
#define ETH_O_PROTO   12
#define ETH_SIZE      14

#define CNTL_TOTAL_SIZE (ETH_SIZE + CNTL_SIZE_)

#define CNTL_O_HOST  0
#define CNTL_O_PORT  1
#define CNTL_SIZE_   2 // YOU MOSTLY WON'T USE IT

#define IP4_O_VERSION  0
#define IP4_O_PROTO    9
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
#define NET6 ((u64)_NET6) // TODO: U64 SUFFIX?

#define ETH_P_XLAN 0x2562

#define eth_dst     ( (u8 *)(pkt + ETH_O_DST_V))
#define eth_src     ( (u8 *)(pkt + ETH_O_SRC_V))
#define eth_proto   (*(u16*)(pkt + ETH_O_PROTO))

#define cntl_host   (*(u8 *)(pkt + ETH_SIZE))
#define cntl_port   (*(u8 *)(pkt + ETH_SIZE + 1))

// NOTE: ASSUME QUE NÃO TEM IP OPTIONS
#define version4    (*(u8 *)(pkt + ETH_SIZE + IP4_O_VERSION))
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

#define PHYS_ADDR64(phys) (*(u64*)((phys)->dev_addr ?: (typeof((phys)->dev_addr))"\x00\x00\x00\x00\x00\x00\x00\x00"))
#define HOST_ADDR64(h, p) atomic64_read(&macs[h][p])

static net_device_s* xlan;
static net_device_s* physs[PORTS_N];
static atomic64_t macs[HOSTS_N][PORTS_N];
static atomic_t seens[HOSTS_N][PORTS_N]; // CADA WORD É UM COUNTDOWN (SHIFTED)
static atomic64_t streams[HOSTS_N][64]; // POPCOUNT64()

static void xlan_announce (struct timer_list*);
static DEFINE_TIMER(doTimer, xlan_announce);

static inline bool xlan_is_up (void) {

    return xlan->operstate == IF_OPER_UP // netif_oper_up()
        || xlan->operstate == IF_OPER_UNKNOWN;
}

static void xlan_announce (struct timer_list* const timer) {

    const jiffies_t now = jiffies;

    if (xlan_is_up()) {

        // SELECIONA UMA INTERFACE DA QUAL ENVIAR
        foreach (p, PORTS_N) {

            net_device_s* const phys = physs[p];

            if (phys && phys->flags & IFF_UP) {

                atomic_set ((atomic_t*)phys->rx_handler_data,
                atomic_read((atomic_t*)phys->rx_handler_data) >> 1);

                sk_buff_s* const skb = alloc_skb(128, GFP_ATOMIC);

                if (skb) {

                    void* const pkt = SKB_DATA(skb);

                    // BROADCAST
             *(u64*)eth_dst   = 0xFFFFFFFFFFFFFFFFULL;
             *(u64*)eth_src   = PHYS_ADDR64(phys);
                    eth_proto = BE16(ETH_P_XLAN);
                    cntl_host = HOST;
                    cntl_port = p;

                    //
                    skb->transport_header = PTR(pkt) - SKB_HEAD(skb);
                    skb->network_header   = PTR(pkt) - SKB_HEAD(skb);
                    skb->mac_header       = PTR(pkt) - SKB_HEAD(skb);
                    skb->data             = PTR(pkt);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
                    skb->tail             = PTR(pkt) + ETH_ZLEN - SKB_HEAD(skb);
#else
                    skb->tail             = PTR(pkt) + ETH_ZLEN;
#endif
                    skb->mac_len          = ETH_HLEN;
                    skb->len              = ETH_ZLEN;
                    skb->ip_summed        = CHECKSUM_NONE;
                    skb->protocol         = BE16(ETH_P_XLAN); // TODO: FIXME:
                    skb->dev              = phys;

                    // SEND IT
                    dev_queue_xmit(skb);
                }
            }
        }
    }

    // REINSTALL TIMER
    doTimer.expires = now + XLAN_ANNOUNCE_INTERVAL;
    add_timer(&doTimer);
}

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    if (skb->len >= CNTL_TOTAL_SIZE) {
        // IS COMPLETE
        const uint proto = skb->protocol;

        if (proto == BE16(ETH_P_XLAN)) {
            // CONTROL
            const void* const pkt = SKB_MAC(skb);
            const uint h = cntl_host;
            const uint p = cntl_port;

            if (h == HOST)
                // MARCA ESTA INTERFACE COMO RECEBENDO
                atomic_set((atomic_t*)skb->dev->rx_handler_data, 1U << 4);
            elif (p < PORTS_N) { // ASSERT: h < HOSTS_N
                atomic64_set(&macs [h][p], *(u64*)eth_src);
                  atomic_set(&seens[h][p], 1U << 4); // XLAN_ANNOUNCE_INTERVAL
            }
        } elif (proto == BE16(ETH_P_IP)
             || proto == BE16(ETH_P_IPV6)) {
            // NORMAL
            if (xlan_is_up()) {
                // RECEIVING
                skb->dev = xlan;
                return RX_HANDLER_ANOTHER;
            }
        }
    }

    kfree_skb(skb);

    return RX_HANDLER_CONSUMED;
}

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const xlan) {

    // ONLY LINEAR
    if (skb_linearize(skb))
        goto drop;

    void* const pkt = SKB_NETWORK(skb) - ETH_SIZE;

    // CONFIRMA ESPACO
    if (PTR(pkt) < SKB_HEAD(skb))
        goto drop;

    const int v4 = skb->protocol == BE16(ETH_P_IP);

    // IDENTIFY DESTINATION
    const uint rhost = v4 ?
        ( (dst4_net & BE32(0xFFFFFF00U)) == BE32(NET4) ? dst4_host : GW ):
        (  dst6_net                      == BE64(NET6) ? dst6_host : GW );

    const u64 now = jiffies;

    // SELECT A PATH
    // OK: TCP | UDP | UDPLITE | SCTP | DCCP
    // FAIL: ICMP
    atomic64_t* const stream = &streams[rhost][__builtin_popcountll( (u64) ( v4
        ? proto4 * ports4 + addrs4
        : proto6 * ports6 * flow6 // TODO: AQUELES DEMAIS BITS DO FLOW
        + addrs6[0] + addrs6[1]
        + addrs6[2] + addrs6[3]
    ))];

    u64 last  =  atomic64_read(stream);
    uint ports = last & 0xFF; // 16x16 ports
    last >>= 8;

    // FORCA A MUDANCA DA PORTA ATUAL SE O ULTIMO ENVIADO JA DEU TEMPO DE SER PROCESSADO
    ports += (now - last) >= HZ/5;

    foreach (c, (PORTS_N * PORTS_N)) {
        ports %= PORTS_N * PORTS_N;

        const uint rport = ports / PORTS_N;
        const uint lport = ports % PORTS_N; // <- MUDA A PORTA LOCAL COM MAIS FREQUENCIA,
                // PARA QUE O SWITCH A DESCUBRA
                // E PORQUE NOS TEMOS MAIS CONTROLE SE ESSA NOSSA PORTA ESTA EXAUSTA OU NAO

        net_device_s* const phys = physs[lport];

        if (phys && (phys->flags & IFF_UP) == IFF_UP && atomic_read((atomic_t*)phys->rx_handler_data)) { // IFF_RUNNING // IFF_LOWER_UP

            atomic64_set(stream, ((u64)now << 8) | ports);

            // INSERT ETHERNET HEADER
     *(u64*)eth_dst   = HOST_ADDR64(rhost, rport);
     *(u64*)eth_src   = PHYS_ADDR64(phys);
            eth_proto = skb->protocol;

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

drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int __f_cold xlan_down (net_device_s* const xlan) {

    printk("XLAN: %s DOWN\n", xlan->name);

    // TODO: DON'T EXECUTE TIMER

    return 0;
}

static int __f_cold xlan_up (net_device_s* const xlan) {

    printk("XLAN: %s UP\n", xlan->name);

    // TODO: REARM TIMER

    return 0;
}

static int __f_cold xlan_enslave (net_device_s* xlan, net_device_s* phys, struct netlink_ext_ack* extack) {

    if (phys == xlan || phys->flags & IFF_LOOPBACK || phys->addr_len != ETH_ALEN)
        //
        return -EINVAL;

    if (netdev_is_rx_handler_busy(phys))
        //
        return -EBUSY;

    foreach (p, PORTS_N) {

        if (physs[p] == phys)
            //
            return -EEXIST;

        if (physs[p] == NULL) {
            // FREE PORT

            if (netdev_rx_handler_register(phys, xlan_in, &seens[HOST][p]) != 0) {
                printk("XLAN: FAILED TO ATTACH HANDLER ON PHYS %s\n", phys->name);
                return -1;
            }

            // HOLD IT
            dev_hold(phys);

            // REGISTER IT
            physs[p] = phys;

            printk("XLAN: PORT %u: ATTACHED PHYS %s\n", p, phys->name);

            return 0;
        }
    }

   // ALL PORTS IN USE
   return -ENOSPC;
}

static int __f_cold xlan_unslave (net_device_s* xlan, net_device_s* phys) {

    foreach (p, PORTS_N) {
        if (physs[p] == phys) {
            physs[p] = NULL; // UNREGISTER
            netdev_rx_handler_unregister(phys); // UNHOOK
            dev_put(phys); // DROP
            printk("XLAN: PORT %u: DETACHED PHYS %s\n", p, phys->name);
            return 0;
        }
    }

    //
    return -ENOENT;
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
    printk("XLAN: INIT - HOST %u 0x%02X GW %u 0x%02X NET4 0x%08X NET6 0x%016llX\n",
        HOST, HOST, GW, GW, NET4, (unsigned long long int)NET6);

    memset(physs, 0, sizeof(physs));
    memset(streams, 0, sizeof(streams)); // NOTE: ATOMIC_INIT(0)
    memset(seens, 0, sizeof(seens)); // NOTE: ATOMIC_INIT(0)
    memset(macs, 0, sizeof(macs)); // NOTE: ATOMIC_INIT(0)

    //
    if ((xlan = alloc_netdev(0, "xlan", NET_NAME_USER, xlan_setup)) == NULL) {
        printk("XLAN: FAILED\n");
        return -1;
    }

    //
    register_netdev(xlan);

    // INSTALL TIMER
    doTimer.expires = jiffies + XLAN_ANNOUNCE_DELAY;
    add_timer(&doTimer);

    return 0;
}

late_initcall(xlan_init);
