/*

*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/notifier.h>
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

typedef unsigned long long int uintll;

typedef struct sk_buff sk_buff_s;
typedef struct net_device net_device_s;
typedef struct net net_s;
typedef struct header_ops header_ops_s;
typedef struct net_device_ops net_device_ops_s;

#define SKB_HEAD(skb) PTR((skb)->head)
#define SKB_DATA(skb) PTR((skb)->data)
#define SKB_TAIL(skb) PTR(skb_tail_pointer(skb))
#define SKB_END(skb)  PTR(skb_end_pointer(skb))

#define PTR(p) ((void*)(p))

#define loop while(1)

#define elif(c) else if(c)

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

// MAX
#define XLAN_PATHS_N 4

#define HOST HOST_GW

#define HOSTS_N 80

#define HOST_GW          1
#define HOST_SWITCH      5
#define HOST_WIFI       10
#define HOST_SPEEDYB0Y  20
#define HOST_PC2        30
#define HOST_XTRADER    40
#define HOST_XQUOTES    50
#define HOST_TEST       70

// PHYSICAL INTERFACES
// TODO: IDENTIFY THEM BY MAC
#define pathsN (sizeof(pathsDev)/sizeof(*pathsDev))

static net_device_s* pathsDev = {
#if HOST == HOST_GW || HOST_XQUOTES
    (net_device_s*)"lan-a",
    (net_device_s*)"lan-b",
#else
#error
#endif
};

#define ETH_MAC_CODE 0x0025

// PARA COLOCAR NO HEADER
// hid = 20 ; pid = 2 ; '0x%04X' % ((0x0101 * ((hid // 10) << 4 | (hid % 10)) )) , hex(0xAAAA + 0x1111 * pid )
typedef struct eth_s {  // 00:00:HH:HH:PP:PP
    u16 _align;
    u16 dstCode; 
    u16 dstID;
    u16 dstP;
    u16 srcCode; // ETH_MAC_CODE
    u16 srcID;
    u16 srcP;
    u16 protocol;
} eth_s;

// NUMBER OF PATHS OF EACH HOST
static const u8 hostN[HOSTS_N] = {
    [HOST_SWITCH]    = 1,
    [HOST_GW]        = 2,
    [HOST_SPEEDYB0Y] = 2,
    [HOST_XTRADER]   = 2,
    [HOST_PC2]       = 2,
};

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    // SE FOR ARP, PASS
    // SE NAO FOR IPV6 E NEM V4, PASS
    if (skb->protocol != BE16(ETH_P_IP)
     && skb->protocol != BE16(ETH_P_IPV6))
        goto pass;

    // TODO: FIXME: DESCOBRIR O QUE CAUSA TANTOS SKBS NAO LINEARES AQUI
    // TODO: FIXME: pskb vs skb??? sera que vai te rque fazer skb_copy() e depois *pskb = skb ?
    // e aí faz ou não kfree_skb()?
    if (skb_linearize(skb))
        goto pass;

#ifdef NET_SKBUFF_DATA_USES_OFFSET
    eth_s* const eth = SKB_HEAD(skb) + skb->mac_header - offsetof(eth_s, dstCode);
#else
    eth_s* const eth =                 skb->mac_header - offsetof(eth_s, dstCode);
#endif

    if ((PTR(eth) + offsetof(eth_s, dstCode)) < SKB_HEAD(skb)
     || (PTR(eth) + offsetof(eth_s, dstCode)) > SKB_TAIL(skb))
        goto pass;

    // IDENTIFY
    if (eth->srcCode != BE16(ETH_MAC_CODE))
        goto pass;
    
    // TODO: SE A INTERFACE XLAN ESTIVER DOWN, PASS OU DROP?
    if (0)
        goto pass;

    // RETIRA O ETHERNET HEADER
    void* const ip = PTR(eth) + sizeof(*eth);

    skb->mac_len          = 0;
    skb->data             = PTR(ip);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header       = PTR(ip) - SKB_HEAD(skb);
    skb->network_header   = PTR(ip) - SKB_HEAD(skb);
#else
    skb->mac_header       = PTR(ip);
    skb->network_header   = PTR(ip);
#endif
    skb->len              = SKB_TAIL(skb) - PTR(ip);
    skb->dev              = itfc->dev;

    return RX_HANDLER_ANOTHER;

pass:
    return RX_HANDLER_PASS;
}

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const dev) {

    if (skb_linearize(skb))
        // NON LINEAR
        goto drop;

#ifdef NET_SKBUFF_DATA_USES_OFFSET
    void* const ip = SKB_HEAD(skb) + skb->network_header;
#else
    void* const ip =                 skb->network_header;
#endif

    if (PTR(ip) < SKB_HEAD(skb)
     || PTR(ip) > SKB_TAIL(skb))
        goto drop;

    // IP VERSION
    const int v4 = (*(u8*)ip & 0xF0) == 0x40;

    // COMPUTE HASH
    u64 hash;

    if (v4) {
        if (skb->len >= (IP4_SIZE + 4)) {
            hash  = *(u64*)(ip + 12); // SRC ADDR, DST ADDR
            hash += *(u32*)(ip + 20); // SRC PORT, DST PORT
            hash += *( u8*)(ip +  9); //  PROTOCOL
        } else
            hash = 0;
    } elif (skb->len >= (IP6_SIZE + 4)) {
        hash  = *(u64*)(ip +  8); // SRC ADDR
        hash += *(u64*)(ip + 16); // SRC ADDR
        hash += *(u64*)(ip + 24); // DST ADDR
        hash += *(u64*)(ip + 32); // DST ADDR
        hash += *(u32*)(ip + 40); // SRC PORT, DST PORT
        hash += *( u8*)(ip +  5); //  PROTOCOL
    } else
        hash = 0;

    hash += hash >> 32;
    hash += hash >> 16;
    hash += hash >> 8;

    // THIS VIRTUAL INTERFACE
    const xlan_itfc_s* const itfc = *(xlan_itfc_s**)netdev_priv(dev);

    

    // CHOOSE A PATH
    const xlan_path_s* const path = &hostMACs[hash % hostMACsN[hid];

    // TODO: SOMENTE SE ELA ESTIVER ATIVA
    if (path->dev == NULL)
        goto drop;

    // COLOCA O CABECALHO
    ethhdr_s* const eth = ip - sizeof(*eth);

    if (PTR(eth) < SKB_HEAD(skb))
        // SEM ESPACO PARA COLOCAR O MAC HEADER
        goto drop;

    eth->h_dest = ;
    eth->h_source = ;
    eth->h_proto = v4 ? 
        BE16(ETH_P_IP) :
        BE16(ETH_P_IPV6);
    
    skb->mac_len          = sizeof(*eth);
    skb->data             = PTR(eth);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header       = PTR(eth) - SKB_HEAD(skb);
#else
    skb->mac_header       = PTR(eth);
#endif
    skb->len              = SKB_TAIL(skb) - PTR(eth);
    skb->dev              = path->dev;

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

    printk("XLAN: %s UP\n", dev->name);

    return 0;
}

static int xlan_down (net_device_s* const dev) {

    printk("XLAN: %s DOWN\n", dev->name);

    return 0;
}

static const net_device_ops_s xlanDevOps = {
    .ndo_init             =  NULL,
    .ndo_open             =  xlan_up,
    .ndo_stop             =  xlan_down,
    .ndo_start_xmit       =  xlan_out,
    .ndo_set_mac_address  =  NULL,
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
    dev->mtu             = ETH_MAX_MTU; // NOTE: TEM QUE SER O DA MENOR INTERFACE
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

    printk("XLAN: INIT\n");

    foreach (i, itfcsN) {

        xlan_itfc_s* const itfc = &itfcs[i];

        // CREATE THE VIRTUAL INTERFACE
        net_device_s* dev = alloc_netdev(sizeof(xlan_itfc_s*), (const char*)itfc->dev, NET_NAME_USER, xlan_setup);

        if (dev) {

            // MAKE IT VISIBLE IN THE SYSTEM
            if (register_netdev(dev)) {
                free_netdev(dev);
                dev = NULL;
            }
        }

        if ((itfc->dev = dev) == NULL)
            continue;

        //
        *(xlan_itfc_s**)netdev_priv(dev) = itfc;

        // INITIALIZE PATHS
        uint i = 0; 
        
        do {

            xlan_path_s* const path = &itfc->paths[i];

            if (path->dev == NULL)
                break;

            net_device_s* dev = dev_get_by_name(&init_net, (const char*)path->dev);

            // TODO: PODE USAR O rx_handler_data COMO REF COUNT
            if (dev) {

                rtnl_lock();

                const int ok =
                        // JÁ ESTA HOOKADA
                        rcu_dereference(dev->rx_handler) == xlan_in
                        // ...OU CONSEGUIU HOOKAR
                    || netdev_rx_handler_register(dev, xlan_in, NULL) ==  0
                ;

                rtnl_unlock();

                if (!ok) {
                    dev_put(dev);
                    dev = NULL;
                }
            }

            path->dev = dev;
            path->eth.h_proto = BE16(ETH_P_IP);

        } while (++i != XLAN_PATHS_N);

        itfc->pathsN = i;
    }

    return 0;
}

static void __exit xlan_exit (void) {

    printk("XLAN: EXIT\n");

    foreach (i, itfcsN) {

        xlan_itfc_s* const itfc = &itfcs[i];

        if (itfc->dev) {

            // UNHOOK PHYSICAL INTERFACES
            foreach (i, itfc->pathsN) {

                net_device_s* const dev = itfc->paths[i].dev;

                if (dev) {

                    rtnl_lock();

                    if (rcu_dereference(dev->rx_handler) == xlan_in)
                        netdev_rx_handler_unregister(dev);

                    rtnl_unlock();

                    dev_put(dev);
                }
            }

            // DESTROY VIRTUAL INTERFACE
            unregister_netdev(itfc->dev);

            free_netdev(itfc->dev);
        }
    }
}

module_init(xlan_init);
module_exit(xlan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XLAN");
MODULE_VERSION("0.1");
