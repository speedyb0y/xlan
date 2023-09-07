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
#define IP6_O_SRC1    8
#define IP6_O_SRC2    16
#define IP6_O_DST1    24
#define IP6_O_DST2    32
#define IP6_O_PAYLOAD 40

#define MTU 7600

#define PORTS_N 6 // MMC DAS QUANTIDADES DE PORTAS DOS HOSTS DA REDE

static net_device_s* virt; // VIRTUAL INTERFACE
static net_device_s* phys[PORTS_N]; // PHYSICAL INTERFACES

static rx_handler_result_t xnic_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

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

static netdev_tx_t xnic_out (sk_buff_s* const skb, net_device_s* dev) {

    // ONLY LINEAR
    if (skb_linearize(skb))
        goto drop;

    if (skb->len < 28)
        goto drop;

    void* const ip = SKB_NETWORK(skb);

    if (PTR(ip) < SKB_HEAD(skb)
     || PTR(ip) > SKB_TAIL(skb))
        goto drop;

    // TODO: ENDIANESS?
    uint rHost = *(u16*)(ip + (*(u8*)ip == 0x45 ? IP4_O_DST+2 : IP6_O_DST+14));

    uint rPort = hash / PORTS_N;
    uint lPort = hash % PORTS_N;

    // A CADA HZ/4 INATIVO, MUDA DE PORTA
    if (inativo) {
        portID++;
        portID %= PORTS_N;
        portCOunt = 0;
    }

    //
    if (portCOunt >= 20000) {
        portCOunt = 0;
        portID = (portID + 1) % PORTS_N;        
    } else
        portCOunt++;
        
    if (++(dessaporta[lPort]) >= MAXIMUM) {
         foreach (c, PORTS_N) {
           dessaporta[++lPort] -= MAXIMUM/4;
            ;
         }
    }

    // SOMENTE SE ELA ESTIVER ATIVA E OK
    if ((dev = phys[lPort]) == NULL)
        goto drop;

    if (dev->flags & (IFF_UP ) != (IFF_UP )) // IFF_RUNNING // IFF_LOWER_UP
        goto drop;

    // INSERT ETHERNET HEADER
    void* const eth = PTR(ip) - ETH_HLEN;

    // CONFIRMA ESPACO
    if (PTR(eth) < SKB_HEAD(skb))
        goto drop;

    // BUILD HEADER
    // TODO: ACCORDING TO ENDIANESS
    *(u16*)(eth     ) = 0;
    *(u32*)(eth +  2) = (rHost << 8) | rPort;
    *(u16*)(eth +  6) = 0;
    *(u32*)(eth +  8) = (lHost << 8) | lPort;
    *(u16*)(eth + 12) = skb->protocol;

    // UPDATE SKB
    skb->data       = PTR(eth);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header = PTR(eth) - SKB_HEAD(skb);
#else
    skb->mac_header = PTR(eth);
#endif
    skb->len        = SKB_TAIL(skb) - PTR(eth);
    skb->mac_len    = ETH_HLEN;
    skb->dev        = dev;

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
    dev_queue_xmit(skb);

    return NETDEV_TX_OK;

drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int xnic_up (net_device_s* const dev) {

    printk("XNIC: %s UP\n", dev->name);

    return 0;
}

static int xnic_down (net_device_s* const dev) {

    printk("XNIC: %s DOWN\n", dev->name);

    return 0;
}

static int xnic_enslave (net_device_s* dev, net_device_s* phys, struct netlink_ext_ack* extack) {

    printk("XNIC: %s: ADD PHYSICAL %s AS PORT %u\n",
        dev->name, phys->name, PORTS_N);

    //
    if (physN == PORTS_N) {
        printk("XNIC: TOO MANY\n");
        goto failed;
    }

    // NEGA ELA MESMA
    if (phys == dev) {
        printk("XNIC: SAME\n");
        goto failed;
    }

    // NEGA LOOPBACK
    if (phys->flags & IFF_LOOPBACK) {
        printk("XNIC: LOOPBACK\n");
        goto failed;
    }

    // SOMENTE ETHERNET
    if (phys->addr_len != ETH_ALEN) {
        printk("XNIC: NOT ETHERNET\n");
        goto failed;
    }

    //
    if (netdev_rx_handler_register(phys, xnic_in, dev) != 0) {
        printk("XNIC: ATTACH FAILED\n");
        goto failed;
    }

    //
    dev_hold((phys[physN++] = phys));

    (void)extack;

//    return 0; TODO: !!!!!!!!!!!!!

failed:
    return -1;
}

static int xnic_unslave (net_device_s* dev, net_device_s* phys) {
    
    printk("XNIC: %s: DEL PHYSICAL %s\n",
        dev->name, phys->name);

    return 1;
}

// struct net_device*  (*ndo_get_xmit_slave)(struct net_device *dev,                              struct sk_buff *skb,                              bool all_slaves);
//  struct net_device*  (*ndo_sk_get_lower_dev)(struct net_device *dev,                            struct sock *sk);

static const net_device_ops_s xispDevOps = {
    .ndo_init             = NULL,
    .ndo_open             = xnic_up,
    .ndo_stop             = xnic_down,
    .ndo_start_xmit       = xnic_out,
    .ndo_set_mac_address  = NULL,
    .ndo_add_slave        = xnic_enslave,
    .ndo_del_slave        = xnic_unslave,
    // TODO: SET MTU - NAO EH PARA SETAR AQUI E SIM NO ROUTE
};

static void xnic_setup (net_device_s* const dev) {

    dev->netdev_ops      = &xispDevOps;
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

    printk("XNIC: %s: CREATED WITH MTU %d\n",
        dev->name, dev->mtu);
}

static int __init xnic_init (void) {

    // CREATE THE VIRTUAL INTERFACE
    // MAKE IT VISIBLE IN THE SYSTEM
    register_netdev((
        virt = alloc_netdev(0, "xnic", NET_NAME_USER, xnic_setup)
    ));

    return 0;
}

static void __exit xnic_exit (void) {

    printk("XNIC: EXIT\n");

    // UNHOOK PHYSICAL INTERFACES
    rtnl_lock();

    foreach (i, PORTS_N)
        netdev_rx_handler_unregister(phys[i]);

    rtnl_unlock();

    // FORGET THEM
    // TODO: FIXME: MUST HOLD LOCK??
    foreach (i, PORTS_N)
        dev_put(phys[i]);

    // DESTROY VIRTUAL INTERFACE
    unregister_netdev(virt);

    free_netdev(virt);
}

module_init(xnic_init);
module_exit(xnic_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XNIC");
MODULE_VERSION("0.1");
