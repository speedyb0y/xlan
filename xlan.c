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
typedef struct ethhdr ethhdr_s;

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

// MAX
#define XLAN_PATHS_N 4

typedef struct xlan_path_s {
    void* dev; // REAL INTERFACE
    ethhdr_s eth;
} xlan_path_s;

// TODO: TEM QUE ENTRAR NA PARADA PRIVATE
typedef struct xlan_itfc_s {
    void* dev; // VIRTUAL INTERFACE
    u32 hash; // PARA IDENTIFICAR AO ENTRAR
    uint pathsN;
    xlan_path_s paths[XLAN_PATHS_N];
} xlan_itfc_s;

static uint itfcsN = 1;

#define GW 0x01016225U
#define GW_A "\x25\x62\x01\x01\xAA\xAA"
#define GW_B "\x25\x62\x01\x01\xBB\xBB"

#define SPEEDYB0Y 0x20206225U
#define SPEEDYB0Y_A "\x25\x62\x20\x20\xAA\xAA"
#define SPEEDYB0Y_B "\x25\x62\x20\x20\xBB\xBB"

static xlan_itfc_s itfcs[] = {
    {
        .name = "speedyb0y",
        .hash = SPEEDYB0Y,
        .pathsN = 2,
        .paths = {
            { .itfc = "lan-a",
                .eth = {
                    .h_dest   = SPEEDYB0Y_A,
                    .h_source = GW_A,
                    .h_proto  = 0x0080 // BE16(ETH_P_IP)
                },
            },
            { .itfc = "lan-b",
                .eth = {
                    .h_dest   = SPEEDYB0Y_B,
                    .h_source = GW_B,
                    .h_proto  = 0x0080 // BE16(ETH_P_IP)
                },
            }
        },
    },
};

// TODO: FIXME: PROTECT THE REAL SERVER TCP PORTS SO WE DON'T NEED TO BIND TO THE FAKE INTERFACE
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
    ethhdr_s* const eth = SKB_HEAD(skb) + skb->mac_header;
#else
    ethhdr_s* const eth = skb->mac_header;
#endif

    if (PTR(eth) < SKB_HEAD(skb)
     || PTR(eth) > SKB_TAIL(skb))
        goto pass;

    // IDENTIFY
    const u32 hash = *(u32*)eth->h_source;

    foreach (i, itfcsN) {

        xlan_itfc_s* const itfc = &itfcs[i];

        if (itfc->hash == hash) {

            // RETIRA O ETHERNET HEADER
            void* const ip = PTR(eth) + sizeof(*eth);

            skb->mac_len          = 0;
            skb->data             = ip;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
            skb->mac_header       = ip - SKB_HEAD(skb);
            skb->network_header   = ip - SKB_HEAD(skb);
#else
            skb->mac_header       = ip;
            skb->network_header   = ip;
#endif
            skb->len              = SKB_TAIL(skb) - ip;
            skb->dev              = itfc->dev;

            break;
        }
    }

pass:
    return RX_HANDLER_ANOTHER;
}

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const dev) {

    if (skb_linearize(skb))
        // NON LINEAR
        goto drop;

    void* const ip = SKB_DATA(skb);

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
    xlan_itfc_s* const itfc = *(xlan_itfc_s**)netdev_priv(dev);

    // CHOOSE A PATH
    xlan_path_s* const path = &itfc->paths[hash % itfc->pathsN];

    // COLOCA O CABECALHO
    ethhdr_s* const eth = ip - sizeof(eth);

    if (PTR(eth) < SKB_HEAD(skb))
        // SEM ESPACO PARA COLOCAR O MAC HEADER
        goto drop;

    memcpy(eth, path->eth, sizeof(path->eth));

    if (!v4)
        eth->h_proto = BE16(ETH_P_IPV6);

    skb->data            -= sizeof(eth);
    skb->len             += sizeof(eth);
    skb->mac_len          = sizeof(eth);
    skb->mac_header       = PTR(eth) - SKB_HEAD(skb);
    skb->dev              = path->itfc;

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
    dev->flags           = IFF_NOARP; // IFF_BROADCAST | IFF_MULTICAST
    dev->priv_flags      = IFF_NO_QUEUE
                         | IFF_NO_RX_HANDLER
                         | IFF_LIVE_ADDR_CHANGE
                         | IFF_LIVE_RENAME_OK
        ;
    dev->features        = // TODO: TEM QUE TER AS MESMAS FEATURES DAS INTERFACES
    dev->hw_features     = NETIF_F_RXCSUM
                         | NETIF_F_HW_CSUM
        ;
}

static int __init xlan_init (void) {

    printk("XLAN: INIT\n");

    foreach (i, itfcsN) {

        xlan_itfc_s* const itfc = &itfcs[i];

        net_device_s* dev;

        // CREATE THE VIRTUAL INTERFACE
        if ((dev = alloc_netdev(sizeof(xlan_itfc_s*), itfc->dev, NET_NAME_USER, xlan_setup))) {

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
        foreach (i, itfc->pathsN) {

            xlan_path_s* const path = &itfc->paths[i];

            net_device_s* dev = path->dev;

            if ((dev = dev_get_by_name(&init_net, dev))) { // TODO: FIXME: VAI TER QUE USAR O rx_handler_data COMO USAGE COUNT

                rtnl_lock();

                const int failed = rcu_dereference(dev->rx_handler) != xlan_in && !netdev_rx_handler_register(dev, xlan_in, NULL);

                rtnl_unlock();

                if (failed) {
                    dev_put(dev);
                    dev = NULL;
                }
            }

            path->dev = dev;
        }
    }

    return 0;
}

static void __exit xlan_exit (void) {

    printk("XLAN: EXIT\n");

    foreach (i, itfcsN) {

        xlan_itfc_s* const itfc = &itfcs[i];

        if (itfc->dev) {

            // UNHOOK INTERFACES
            foreach (i, itfc->pathsN) {

                xlan_path_s* const path = &itfc->paths[i];

                net_device_s* const dev = path->dev;

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
