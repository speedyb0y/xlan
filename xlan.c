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

static net_device_s* xdev;
static net_device_s* devs[XLAN_PORTS_N]; // PHYSICAL INTERFACES    

static rx_handler_result_t xisp_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    if (skb->protocol != ETH_P_8021Q)
        goto pass;

    if (skb_linearize(skb))
        goto drop;

    // PULA O ETHERNET HEADER
    void* const ip = SKB_MAC(skb);

    if (PTR(ip) < SKB_HEAD(skb)
     || PTR(ip) > SKB_TAIL(skb))
        goto drop;

    memmove(ip + 2, ip, 12);

    skb->data       = PTR(ip);
    skb->len        = SKB_TAIL(skb) - PTR(ip);
    // NOTE: skb->network_header JA ESTA CORRETO
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header = ;
#else
    skb->mac_header = skb->network_header;
#endif
    skb->network_header = skb->mac_header;
    skb->mac_len    = ETH_HLEN;
   
    // SO SE A INTERFACE XLAN ESTIVER UP
    if ((skb->dev = xdev)->flags & IFF_UP)
        return RX_HANDLER_ANOTHER;

drop: // TODO: dev_kfree_skb ?

    kfree_skb(skb);

    return RX_HANDLER_CONSUMED;
}

static netdev_tx_t xisp_out (sk_buff_s* const skb, net_device_s* const xdev) {

    if (skb_linearize(skb))
        // NON LINEAR
        goto drop;

    void* const ip = SKB_NETWORK(skb);

    if (PTR(ip) < SKB_HEAD(skb)
     || PTR(ip) > SKB_TAIL(skb))
        goto drop;


    const uint srcPortsN = portsQ[HOST];
    const uint dstPortsN = portsQ[dstHost];

    // CONFIRM DESTINATION HOST HAS PORTS
    if (dstPortsN == 0)
        goto drop;

    const uint dstPort = hash %  dstPortsN; // CHOOSE THEIR INTERFACE
                         hash /= dstPortsN;
    const uint srcPort = hash %  srcPortsN; // CHOOSE MY INTERFACE

    // INSERT ETHERNET HEADER
    ethhdr_s* const eth = PTR(ip) - ETH_HLEN;

    // CONFIRMA ESPACO
    if (PTR(eth) < SKB_HEAD(skb))
        goto drop;

    memcpy(eth->h_dest,   macs[dstHost][dstPort], ETH_ALEN);
    memcpy(eth->h_source, macs[HOST]   [srcPort], ETH_ALEN);
           eth->h_proto = skb->protocol;

    skb->data       = PTR(eth);
    skb->len        = SKB_TAIL(skb) - PTR(eth);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header = PTR(eth) - SKB_HEAD(skb);
#else
    skb->mac_header = PTR(eth);
#endif
    skb->mac_len    = ETH_HLEN;

    //
    net_device_s* const dev = devs[srcPort];

    // SOMENTE SE ELA ESTIVER ATIVA
    if (dev && dev->flags & IFF_UP) {

        skb->dev = dev;

        // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
        // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
        // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
        dev_queue_xmit(skb);

        return NETDEV_TX_OK;
    }

drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int xisp_up (net_device_s* const xdev) {

    printk("XLAN: UP\n");

    return 0;
}

static int xisp_down (net_device_s* const xdev) {

    printk("XLAN: DOWN\n");

    return 0;
}

static const net_device_ops_s xispDevOps = {
    .ndo_init             =  NULL,
    .ndo_open             =  xisp_up,
    .ndo_stop             =  xisp_down,
    .ndo_start_xmit       =  xisp_out,
    .ndo_set_mac_address  =  NULL,
    // TODO: SET MTU - NAO EH PARA SETAR AQUI E SIM NO ROUTE
};

static void xisp_setup (net_device_s* const dev) {

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

static int xisp_notify_phys (struct notifier_block* const nb, const unsigned long event, void* const info) {

    // ASSERT: rtnl_is_locked()

    // CONSIDERA SOMENTE ESTES EVENTOS
    if (event != NETDEV_REGISTER
     && event != NETDEV_CHANGEADDR)
        goto done;

    net_device_s* dev = netdev_notifier_info_to_dev(info);

    // IGNORA EVENTOS DELA MESMA
    if (dev == isp1v
     || dev == isp2v
     || dev == isp1
     || dev == isp2)
        goto done;

    // FILTRAR LOOPBACK
    if (dev->flags & IFF_LOOPBACK)
        goto done;

    // FILTRAR ETHERNET
    if (dev->addr_len != ETH_ALEN)
        goto done;

    //
    const u8* const mac =
        (event == NETDEV_REGISTER) ?
            PTR(dev->perm_addr) :
            PTR(dev->dev_addr);

    //
    if (mac == NULL)
        goto done;
    
    //
    if (*(u32*)mac == 0)
        goto done;

    if (isp1 == NULL && memcmp("\x00\x00\x00\x00\x00\x01", mac, ETH_ALEN) == 0) {
        if (netdev_rx_handler_register(dev, xisp_in, NULL) == 0)
            dev_hold((isp1 = dev));
    } elif (isp2 == NULL && memcmp("\x00\x00\x00\x00\x00\x02", mac, ETH_ALEN) == 0) {
        if (netdev_rx_handler_register(dev, xisp_in, NULL) == 0)
            dev_hold((isp2 = dev));
    }

done:
    return NOTIFY_OK;
}

static notifier_block_s notifyDevs = {
    .notifier_call = xisp_notify_phys
};

static int __init xisp_init (void) {

    printk("XLAN: INIT\n");

    // WILL YET DISCOVER THE PHYSICAL INTERFACES
    isp1 = NULL;
    isp2 = NULL;

    // CREATE THE VIRTUAL INTERFACE
    isp1v = alloc_netdev(0, "isp-1-v", NET_NAME_USER, xisp_setup);
    isp2v = alloc_netdev(0, "isp-2-v", NET_NAME_USER, xisp_setup);

    // MAKE IT VISIBLE IN THE SYSTEM
    register_netdev(isp1v);
    register_netdev(isp2v);

    // COLOCA A PARADA DE EVENTOS
    if (register_netdevice_notifier(&notifyDevs) >= 0)
        return 0;

    printk("XLAN: FAILED TO REGISTER NETWORK DEVICES NOTIFIER\n");

    unregister_netdev(isp1v);
    unregister_netdev(isp2v);

    free_netdev(isp1v);
    free_netdev(isp2v);

    return -1;
}

static void __exit xisp_exit (void) {

    printk("XLAN: EXIT\n");

    // PARA DE MONITORAR OS EVENTOS
    unregister_netdevice_notifier(&notifyDevs);

    // UNHOOK PHYSICAL INTERFACES
    rtnl_lock();

    if (isp1v) netdev_rx_handler_unregister(isp1v);
    if (isp2v) netdev_rx_handler_unregister(isp2v);

    rtnl_unlock();

    if (isp1v) dev_put(isp1v);
    if (isp2v) dev_put(isp2v);

    // DESTROY VIRTUAL INTERFACE
    unregister_netdev(isp1v);
    unregister_netdev(isp2v);

    free_netdev(isp1v);
    free_netdev(isp2v);
}

module_init(xisp_init);
module_exit(xisp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XISP");
MODULE_VERSION("0.1");
