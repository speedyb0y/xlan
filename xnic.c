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

#define IP6_O_PROTO  5
#define IP6_O_SRC1   8
#define IP6_O_SRC2  16
#define IP6_O_DST1  24
#define IP6_O_DST2  32
            
#define IP4_O_PROTO 9
#define IP4_O_SRC 12
#define IP4_O_DST 16

#define MTU 7600

static net_device_s* virt; // VIRTUAL INTERFACE

#define XNIC_PHYS_N 7

typedef struct xnic_s {
    uint n;
    net_device_s* phys[XNIC_PHYS_N]; // PHYSICAL INTERFACES    
} xnic_s;

static rx_handler_result_t xnic_in (sk_buff_s** const pskb) {

    // SO SE A INTERFACE XNIC ESTIVER UP
    if (virt->flags & IFF_UP)
        return RX_HANDLER_PASS;

    sk_buff_s* const skb = *pskb;

    if (skb_linearize(skb))
        goto drop;

    if (skb->protocol != BE16(ETH_P_IP)
     && skb->protocol != BE16(ETH_P_IPV6))
        goto drop;

    // PULA O ETHERNET HEADER
    // NOTE: skb->network_header JA ESTA CORRETO
    skb->data           = SKB_NETWORK(skb);
    skb->len            = SKB_TAIL(skb) - SKB_NETWORK(skb);
    skb->mac_header     = skb->network_header;
    skb->mac_len        = 0;
    skb->pkt_type       = PACKET_HOST;
    skb->dev            = rcu_dereference(skb->dev);
    // rcu_dereference
    // rcu_dereference_bh(dev->rx_handler_data)
	// rtnl_dereference(dev->rx_handler_data)

    return RX_HANDLER_ANOTHER;

drop: // TODO: dev_kfree_skb ?

    kfree_skb(skb);

    return RX_HANDLER_CONSUMED;
}

static netdev_tx_t xnic_out (sk_buff_s* const skb, net_device_s* const dev) {

    xnic_s* const xnic = netdev_priv(dev);

    // ONLY LINEAR
    if (skb_linearize(skb))
        goto drop;

    void* const ip = SKB_NETWORK(skb);

    if (PTR(ip) < SKB_HEAD(skb)
     || PTR(ip) > SKB_TAIL(skb))
        goto drop;

    // COMPUTE HASH
    uintll hash;

    // IP VERSION
    switch (*(u8*)ip >> 4) {

        case 4: // TODO: VER DENTRO DAS MENSAGENS ICMP E GERAR O MESMO HASH DESSES AQUI
            // NOTE: ASSUME QUE NÃO TEM IP OPTIONS
            
            // IP PROTOCOL
            switch ((hash = *(u8*)(ip + IP4_O_PROTO))) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_UDPLITE:
                case IPPROTO_SCTP:
                case IPPROTO_DCCP:
                    hash += *(u32*)(ip + IP4_SIZE); // SRC PORT, DST PORT
                default:
                    hash += *(u64*)(ip + IP4_O_SRC); // SRC ADDR, DST ADDR
            }

            break;

        case 6:

            // IP PROTOCOL
            switch ((hash = *(u8*)(ip + IP6_O_PROTO))) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_UDPLITE:
                case IPPROTO_SCTP: // TODO: CONSIDER IPV6 FLOW?
                case IPPROTO_DCCP:
                    hash += *(u32*)(ip + IP6_SIZE); // SRC PORT, DST PORT
                default:
                    hash += *(u64*)(ip + IP6_O_SRC1); // SRC ADDR
                    hash += *(u64*)(ip + IP6_O_SRC2); // SRC ADDR
                    hash += *(u64*)(ip + IP6_O_DST1); // DST ADDR
                    hash += *(u64*)(ip + IP6_O_DST2); // DST ADDR
            }

            break;

        default: // UNSUPORTED
            hash = 0;
    }

    hash = __builtin_popcountll(hash);

    // CHOOSE PORT
    foreach (c, xnic->n) {

        net_device_s* const this = xnic->phys[hash = (hash + 1) % xnic->n];

        // SOMENTE SE ELA ESTIVER ATIVA E OK
        if ((this->flags & (IFF_UP | IFF_RUNNIG | IFF_LOWER_UP))
                        == (IFF_UP | IFF_RUNNIG | IFF_LOWER_UP)) {

            skb->dev = this;

            // INSERT ETHERNET HEADER
            void* const eth = PTR(ip) - ETH_HLEN;

            // CONFIRMA ESPACO
            if (PTR(eth) < SKB_HEAD(skb))
                goto drop;

            // BUILD HEADER
            // TODO: ACCORDING TO ENDIANESS
            *(u64*)(eth     ) = 0x0000FFFFFFFFFFFFULL;
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

            // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
            // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
            // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
            dev_queue_xmit(skb);

            return NETDEV_TX_OK;
        }
    }

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

    xnic_s* const xnic = netdev_priv(dev);

    printk("XNIC: %s: ADD PHYSICAL %s AS PORT %u\n",
        dev->name, phys->name, xnic->n);

    //
    if (xnic->n == XNIC_PHYS_N) {
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
    xnic->phys[xnic->n++] = phys;

    dev_hold(phys);

    (void)extack;
    
done:
    return 0;

failed:
    return -1;
}

static const net_device_ops_s xispDevOps = {
    .ndo_init             = NULL,
    .ndo_open             = xnic_up,
    .ndo_stop             = xnic_down,
    .ndo_start_xmit       = xnic_out,
    .ndo_set_mac_address  = NULL,
    .ndo_add_slave        = xnic_enslave,
    .ndo_del_slave        = NULL,
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

    // WILL YET ADD THE PHYSICAL INTERFACES
    memset(netdev_priv(dev), 0, sizeof(xnic_s));

    printk("XNIC: %s: CREATED WITH MTU %d\n",
        dev->name, dev->mtu);
}

static int __init xnic_init (void) {

    // CREATE THE VIRTUAL INTERFACE
    // MAKE IT VISIBLE IN THE SYSTEM
    register_netdev(alloc_netdev(sizeof(xnic_s), "xnic", NET_NAME_USER, xnic_setup));

    return 0;
}

static void __exit xnic_exit (void) {

    printk("XNIC: EXIT\n");

    const xnic_s* const xnic = netdev_priv(virt);

    // UNHOOK PHYSICAL INTERFACES
    rtnl_lock();

    foreach (i, xnic->n)
        netdev_rx_handler_unregister(xnic->phys[i]);

    rtnl_unlock();

    // FORGET THEM
    // TODO: FIXME: MUST HOLD LOCK??
    foreach (i, xnic->n)
        dev_put(xnic->phys[i]);

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
