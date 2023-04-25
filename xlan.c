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
#define UDP_SIZE  8
#define TCP_SIZE 20

#define DEV_FLAGS_UP (IFF_UP | IFF_RUNNIG | IFF_LOWER_UP)

#define DEV_IS_USABLE(dev) ((dev) && ((dev)->flags & DEV_FLAGS_UP) == DEV_FLAGS_UP)

#define IS_A 1 // speedyb0y
#define MTU 7600

#define MAC_A_0 "\xbc\x5f\xf4\xf9\xe6\x66"
#define MAC_A_1 "\xbc\x5f\xf4\xf9\xe6\x66"
#define MAC_B_0 "\x88\xc9\xb3\xb0\xf1\xeb"
#define MAC_B_1 "\x88\xc9\xb3\xb0\xf1\xea"

#if IS_A
#define XNIC_0 "gw-0"
#define XNIC_1 "gw-1"
#else
#define XNIC_0 "speedyb0y-0"
#define XNIC_1 "speedyb0y-1"
#endif

#if IS_A
#define MAC_SRC_0 MAC_A_0
#define MAC_SRC_1 MAC_A_1
#define MAC_DST_0 MAC_B_0
#define MAC_DST_1 MAC_B_1
#else
#define MAC_SRC_0 MAC_B_0
#define MAC_SRC_1 MAC_B_1
#define MAC_DST_0 MAC_A_0
#define MAC_DST_1 MAC_A_1
#endif

static net_device_s* virt; // VIRTUAL INTERFACE
static net_device_s* phys[2]; // PHYSICAL INTERFACES    

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
    skb->dev            = virt;

    return RX_HANDLER_ANOTHER;

drop: // TODO: dev_kfree_skb ?

    kfree_skb(skb);

    return RX_HANDLER_CONSUMED;
}

static netdev_tx_t xnic_out (sk_buff_s* const skb, net_device_s* const xdev) {

    // ONLY LINEAR
    if (skb_linearize(skb))
        goto drop;

    void* const ip = SKB_NETWORK(skb);

    if (PTR(ip) < SKB_HEAD(skb)
     || PTR(ip) > SKB_TAIL(skb))
        goto drop;

    uint hsize; // MINIMUM SIZE    
    uintll hash; // COMPUTE HASH    

    // IP VERSION
    switch (*(u8*)ip >> 4) {

        case 4: // TODO: VER DENTRO DAS MENSAGENS ICMP E GERAR O MESMO HASH DESSES AQUI
            
            // IP PROTOCOL
            switch ((hash = *(u8*)(ip + IP4_O_PROTO))) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_UDPLITE:
                case IPPROTO_SCTP:
                case IPPROTO_DCCP:
                    hash += *(u64*)(ip + IP4_O_SRC); // SRC ADDR, DST ADDR
                    hash += *(u32*)(ip + IP4_SIZE); // SRC PORT, DST PORT
                    hsize = IP4_SIZE + UDP_SIZE;
                    break;
                default:
                    hash += *(u64*)(ip + IP4_O_SRC); // SRC ADDR, DST ADDR
                    hsize = IP4_SIZE;
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
                    hash += *(u64*)(ip + IP6_O_SRC1); // SRC ADDR
                    hash += *(u64*)(ip + IP6_O_SRC2); // SRC ADDR
                    hash += *(u64*)(ip + IP6_O_DST1); // DST ADDR
                    hash += *(u64*)(ip + IP6_O_DST2); // DST ADDR
                    hash += *(u32*)(ip + IP6_SIZE); // SRC PORT, DST PORT
                    hsize = IP6_SIZE + UDP_SIZE;
                    break;
                default:
                    hash += *(u64*)(ip + IP6_O_SRC1); // SRC ADDR
                    hash += *(u64*)(ip + IP6_O_SRC2); // SRC ADDR
                    hash += *(u64*)(ip + IP6_O_DST1); // DST ADDR
                    hash += *(u64*)(ip + IP6_O_DST2); // DST ADDR
                    hsize = IP6_SIZE;
            }

            break;

        default:
            // UNSUPORTED
            goto drop;
    }

    if (skb->len < hsize)
        goto drop;

    // INSERT ETHERNET HEADER
    void* const eth = PTR(ip) - ETH_HLEN;

    // CONFIRMA ESPACO
    if (PTR(eth) < SKB_HEAD(skb)
     || PTR(eth) > SKB_TAIL(skb))
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

    // CHOOSE PORT
    hash += hash >> 32;
    hash += hash >> 16;
    hash += hash >> 8;
    hash &= 1U;

    net_device_s* x = phys[ hash];
    net_device_s* y = phys[!hash];

    // SOMENTE SE ELA ESTIVER ATIVA E OK
    if (!DEV_IS_USABLE(x)) {
        if (!DEV_IS_USABLE(y))
            goto drop;
        x = y;
    }

    skb->dev = x;

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

    printk("XNIC: UP\n");

    return 0;
}

static int xnic_down (net_device_s* const dev) {

    printk("XNIC: DOWN\n");

    return 0;
}

static const net_device_ops_s xispDevOps = {
    .ndo_init             =  NULL,
    .ndo_open             =  xnic_up,
    .ndo_stop             =  xnic_down,
    .ndo_start_xmit       =  xnic_out,
    .ndo_set_mac_address  =  NULL,
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
}

static int xnic_notify_phys (struct notifier_block* const nb, const unsigned long event, void* const info) {

    // ASSERT: rtnl_is_locked()

    // CONSIDERA SOMENTE ESTES EVENTOS
    if (event != NETDEV_REGISTER
     && event != NETDEV_CHANGENAME)
        goto done;

    net_device_s* const dev = netdev_notifier_info_to_dev(info);

    // IGNORA EVENTOS DELA MESMA
    if (dev == virt
     || dev == phys[0]
     || dev == phys[1])
        goto done;

    // FILTRAR LOOPBACK
    // FILTRAR ETHERNET
    if (dev->flags & IFF_LOOPBACK
     || dev->addr_len != ETH_ALEN)
        goto done;

    uint p;
    //
    if (phys[0] == NULL && strcmp(XNIC_0, dev->name) == 0)
        p = 0;
    elif (phys[1] == NULL && strcmp(XNIC_1, dev->name) == 0)
        p = 1;
    else
        goto done;

    printk("XNIC: ATTACHING TO PHYSICAL #%u NAME %s\n", p, dev->name);

    if (netdev_rx_handler_register(dev, xnic_in, NULL) == 0) {
        dev_hold((phys[p] = dev));
        dev_set_promiscuity(dev, 1);        
    } else
        printk("XNIC: ATTACH FAILED\n");

done:
    return NOTIFY_OK;
}

static notifier_block_s notifyDevs = {
    .notifier_call = xnic_notify_phys
};

static int __init xnic_init (void) {

    printk("XNIC: INIT WITH SIDE A %u MTU %d\n", IS_A, MTU);

    // WILL YET DISCOVER THE PHYSICAL INTERFACES
    phys[0] = NULL;
    phys[1] = NULL;

    // CREATE THE VIRTUAL INTERFACE
    virt = alloc_netdev(0, "xnic", NET_NAME_USER, xnic_setup);

    // MAKE IT VISIBLE IN THE SYSTEM
    register_netdev(virt);

    // COLOCA A PARADA DE EVENTOS
    if (register_netdevice_notifier(&notifyDevs) >= 0)
        return 0;

    printk("XNIC: FAILED TO REGISTER NETWORK DEVICES NOTIFIER\n");

    unregister_netdev(virt);

    free_netdev(virt);

    return -1;
}

static void __exit xnic_exit (void) {

    printk("XNIC: EXIT\n");

    // PARA DE MONITORAR OS EVENTOS
    unregister_netdevice_notifier(&notifyDevs);

    // UNHOOK PHYSICAL INTERFACES
    rtnl_lock();

    if (phys[0]) netdev_rx_handler_unregister(phys[0]);
    if (phys[1]) netdev_rx_handler_unregister(phys[1]);

    rtnl_unlock();

    // TODO: FIXME: MUST HOLD LOCK??
    if (phys[0]) { dev_set_promiscuity(phys[0], 0); dev_put(phys[0]); }
    if (phys[1]) { dev_set_promiscuity(phys[1], 0); dev_put(phys[1]); }

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
