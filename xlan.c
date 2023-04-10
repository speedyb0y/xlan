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

#define ETH_SIZE 14
#define IP4_SIZE 20
#define IP6_SIZE 40

// MAX
#define XLAN_PORTS_N 4

#define HOST HOST_GW

enum HOSTS {
    HOST_GW         = 1,
    HOST_SWITCH     = 2,
    HOST_WIFI       = 3,
    HOST_PC2        = 4,
    HOST_SPEEDYB0Y  = 5,
    HOST_XTRADER    = 6,
    HOST_XQUOTES    = 7,
    HOST_TEST       = 8,
    HOSTS_N
};

// PHYSICAL INTERFACES
// TODO: IDENTIFY THEM BY MAC
static uint portsN;
static net_device_s* ports[XLAN_PORTS_N];

#define XLAN_MAC_CODE 0x00256200U

#define XLAN_ETH_ALIGN ???

// PARA COLOCAR NO HEADER
// hid = 20 ; pid = 2 ; '0x%04X' % ((0x0101 * ((hid // 10) << 4 | (hid % 10)) )) , hex(0xAAAA + 0x1111 * pid )
typedef struct eth_s {  // 00:00:HH:HH:PP:PP
    u8 _align[XLAN_ETH_ALIGN];
    u32 dstCode; // XLAN_MAC_CODE
     u8 dstHost;
     u8 dstPort;
    u32 srcCode; // XLAN_MAC_CODE
     u8 srcHost;
     u8 srcPort;
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
    eth_s* const eth = SKB_HEAD(skb) + skb->mac_header - XLAN_ETH_ALIGN;
#else
    eth_s* const eth =                 skb->mac_header - XLAN_ETH_ALIGN;
#endif

    if ((PTR(eth) + XLAN_ETH_ALIGN) < SKB_HEAD(skb)
     || (PTR(eth) +   sizeof(*eth)) > SKB_TAIL(skb))
        goto pass;

    // IDENTIFY
    if (eth->srcCode != BE32(XLAN_MAC_CODE))
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

    // IDENTIFY HID BY IP DESTINATION
    // TOOD: o caso do ipv6, vai ter que transformar o valor de volta pois esta em hexadecimal
    uint hid;
    
    if (v4)
        hid = *(u8*)(ip + 19);
    else {
        hid = *(u8*)(ip + 39);

        (hid >> 4) | (hid & 0x0F) // 16
pid = 2 ; '0x%012X' % ((0x000101010100 * ((20 // 10) << 4 | (20 % 10)) ) | (0xAA + 0x11 * pid ))
        ??
    }

    // CHOSE MY INTERFACE
    net_device_s* const dev = &hostMACs[hash % hostMACsN[hid];

    // TODO: SOMENTE SE ELA ESTIVER ATIVA
    if (dev == NULL)
        goto drop;

    // TODO: CHOSE THEIR INTERFACE

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
    skb->dev              = dev;

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

static int evento () {

    // REGISTER / CHANGE ADDR
    // TODO: UNREGISTER
    // TODO: CHANGE ADDR FROM OUR TO SOMETHING ELSE

    const void* const addr = dev->;

    const uint code = *(u32*)addr;
    const uint hid  = *(u8*)(addr + sizeof(u32));
    const uint pid  = *(u8*)(addr + sizeof(u32) + sizeof(u8));

    if (code != BE32(XLAN_MAC_CODE))
        // NÃO É NOSSO MAC
        goto done;

    if (hid != HOST) {
        printk("XLAN: HOST MISMATCH\n");
        goto done;
    }

    if (pid >= XLAN_PORTS_N) {
        printk("XLAN: BAD PORT\n");
        goto done;
    }

    int hook;

    rtnl_lock();

    if (rcu_dereference(dev->rx_handler) == xlan_in)
        hook =  0; // JÁ ESTA HOOKADA
    elif (netdev_rx_handler_register(dev, xlan_in, NULL) == 0)
        hook =  1; // HOOKOU
    else // NÃO CONSEGUIU HOOKAR
        hook = -1;

    rtnl_unlock();

    switch (hook) {
        
        case 0:
            // NOTE: ASSUME
            
            break;

        case 1:
            break;

        case -1:
            // DEIXA COMO ESTÁ
            break;
    }

    net_device_s* const old = ports[pid];

    if (old != dev) {
        
        if (old)
            dev_put(old);

        if ((ports[pid] = dev)) {            
            if (portsN <= pid)
                portsN = pid + 1;            
            dev_get(dev);
        }
    }
}

done:
    return 0;
}

static int __init xlan_init (void) {

    printk("XLAN: INIT\n");

    ASSERT(sizeof(eth_s) == (XLAN_ETH_ALIGN + ETH_SIZE));

    // CREATE THE VIRTUAL INTERFACE
    if ((xlan = alloc_netdev(0, "xlan", NET_NAME_USER, xlan_setup)))
        return -1;

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(xlan)) {
        free_netdev(xlan);
        return -1;
    }

    // ENCONTRARÁ PELOS NOSSOS MACS
    portsN = 0;

    // TODO: COLOCA A PARADA DE EVENTOS

    return 0;
}

static void __exit xlan_exit (void) {

    printk("XLAN: EXIT\n");

    // PARA DE MONITORAR OS EVENTOS

    // UNHOOK PHYSICAL INTERFACES
    foreach (i, portsN) {

        net_device_s* const dev = ports[i];

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

module_init(xlan_init);
module_exit(xlan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XLAN");
MODULE_VERSION("0.1");
