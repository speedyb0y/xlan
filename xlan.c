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

// THIS HOST
#define HOST GW

#define __HOST2(a, h) a ## h
#define __HOST(a, h) __HOST2(a, h)

#define HOST_ID         __HOST(HOST_ID_, HOST)
#define HOST_PORTS_Q    __HOST(HOST_PORTS_Q_, HOST)

enum HOSTS_IDS {
    HOST_ID_GW         =  1,
    HOST_ID_XQUOTES    =  1,
    HOST_ID_WIFI       = 10,
    HOST_ID_SPEEDYB0Y  = 20,
    HOST_ID_PC2        = 30,
    HOST_ID_XTRADER    = 40,
    HOST_ID_TEST       = 70,
    HOSTS_N
};

// QUANTITY OF PORTS OF EACH HOST
enum HOSTS_PORTS_Q {
    HOST_PORTS_Q_GW        = 2,
    HOST_PORTS_Q_WIFI      = 1,
    HOST_PORTS_Q_PC2       = 1,
    HOST_PORTS_Q_SPEEDYB0Y = 2,
    HOST_PORTS_Q_XTRADER   = 1,
    HOST_PORTS_Q_TEST      = 1,
};

// VIRTUAL INTERFACE
static net_device_s* xdev;
// PHYSICAL INTERFACES
static net_device_s* ports[HOST_PORTS_Q];

static const u8 hostPortsQ[HOSTS_N] = {
    [HOST_ID_GW]        = HOST_PORTS_Q_GW,
    [HOST_ID_WIFI]      = HOST_PORTS_Q_WIFI,
    [HOST_ID_PC2]       = HOST_PORTS_Q_PC2,
    [HOST_ID_SPEEDYB0Y] = HOST_PORTS_Q_SPEEDYB0Y,
    [HOST_ID_XTRADER]   = HOST_PORTS_Q_XTRADER,
    [HOST_ID_TEST]      = HOST_PORTS_Q_TEST,
};

//
#define XLAN_MAC_CODE 0x00256200U

typedef u32 eth_code_t;
typedef u8  eth_host_t;
typedef u8  eth_port_t;
typedef u16 eth_proto_t;

// ETHERNET HEADER
typedef struct eth_s {
    eth_code_t dstCode; // XLAN_MAC_CODE
    eth_host_t dstHost;
    eth_port_t dstPort;
    eth_code_t srcCode; // XLAN_MAC_CODE
    eth_host_t srcHost;
    eth_port_t srcPort;
    eth_proto_t protocol;
    u16 _align;
} __attribute__((packed)) eth_s;

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

    eth_s* const eth = SKB_MAC(skb);

    if (PTR(eth) < SKB_HEAD(skb)
    || (PTR(eth) + ETH_SIZE) >= SKB_TAIL(skb))
        goto pass;

    if (eth->srcCode != BE32(XLAN_MAC_CODE))
        // NOT FROM XVLAN
        goto pass;
    
    if (eth->srcPort == 0)
        // NOT A SWITCH PORT
        goto pass;

    // TODO: SE A INTERFACE XLAN ESTIVER DOWN, PASS OU DROP?
    if (0)
        goto pass;

    // PULA O ETHERNET HEADER
    void* const ip = PTR(eth) + ETH_SIZE;

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
    skb->dev              = xdev;

    return RX_HANDLER_ANOTHER;

pass:
    return RX_HANDLER_PASS;
}

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const dev) {

    if (skb_linearize(skb))
        // NON LINEAR
        goto drop;

    void* const ip = SKB_NETWORK(skb);

    if (PTR(ip) < SKB_HEAD(skb)
     || PTR(ip) > SKB_TAIL(skb))
        goto drop;

    // MINIMUM SIZE
    uint hsize;
    // COMPUTE HASH
    u64 hash;
    // IDENTIFY HOST BY IP DESTINATION
    uint dstHost; 

    // IP VERSION
    switch (*(u8*)ip >> 4) {

        case 4: // TODO: VER DENTRO DAS MENSAGENS ICMP E GERAR O MESMO HASH DESSES AQUI

            dstHost = *(u8*)(ip + IP4_SIZE - 1);
            
            // IP PROTOCOL
            switch ((hash = *(u8*)(ip + 9))) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_UDPLITE:
                case IPPROTO_SCTP:
                case IPPROTO_DCCP:
                    hash += *(u64*)(ip + 12); // SRC ADDR, DST ADDR
                    hash += *(u32*)(ip + 20); // SRC PORT, DST PORT
                    hsize = IP4_SIZE + UDP_SIZE;
                    break;
                default:
                    hash += *(u64*)(ip + 12); // SRC ADDR, DST ADDR
                    hsize = IP4_SIZE;
            }

            break;

        case 6:

            dstHost = *(u8*)(ip + IP6_SIZE - 1);
            dstHost = (dstHost >> 4)*10 + (dstHost & 0xF);

            // IP PROTOCOL
            switch ((hash = *(u8*)(ip + 5))) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_UDPLITE:
                case IPPROTO_SCTP:
                case IPPROTO_DCCP:
                    hash += *(u64*)(ip +  8); // SRC ADDR
                    hash += *(u64*)(ip + 16); // SRC ADDR
                    hash += *(u64*)(ip + 24); // DST ADDR
                    hash += *(u64*)(ip + 32); // DST ADDR
                    hash += *(u32*)(ip + 40); // SRC PORT, DST PORT
                    hsize = IP6_SIZE + UDP_SIZE;
                    break;
                default:
                    hash += *(u64*)(ip +  8); // SRC ADDR
                    hash += *(u64*)(ip + 16); // SRC ADDR
                    hash += *(u64*)(ip + 24); // DST ADDR
                    hash += *(u64*)(ip + 32); // DST ADDR
                    hsize = IP6_SIZE;
            }

            break;

        default:
            // UNSUPORTED
            goto drop;
    }

    if (skb->len < hsize)
        goto drop;

    hash += hash >> 32;
    hash += hash >> 16;
    hash += hash >> 8;

    // CHOOSE MY INTERFACE
    // CHOOSE THEIR INTERFACE
    // TOOD: o caso do ipv6, vai ter que transformar o valor de volta pois esta em hexadecimal
    const uint srcPort = hash %  HOST_PORTS_Q;
                         hash /= HOST_PORTS_Q;
    const uint dstPort = hash % hostPortsQ[dstHost];

    // INSERT ETHERNET HEADER
    eth_s* const eth = PTR(ip) - ETH_SIZE;

    if (PTR(eth) < SKB_HEAD(skb))
        // SEM ESPACO PARA COLOCAR O MAC HEADER
        goto drop;

    eth->dstCode  = BE32(XLAN_MAC_CODE); // XLAN_MAC_CODE
    eth->dstHost  = dstHost;
    eth->dstPort  = dstPort;
    eth->srcCode  = BE32(XLAN_MAC_CODE); // XLAN_MAC_CODE
    eth->srcHost  = HOST_ID;
    eth->srcPort  = srcPort;
    eth->protocol = skb->protocol;

    skb->mac_len          = ETH_SIZE;
    skb->data             = PTR(eth);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header       = PTR(eth) - SKB_HEAD(skb);
#else
    skb->mac_header       = PTR(eth);
#endif
    skb->len              = SKB_TAIL(skb) - PTR(eth);

    //
    net_device_s* const dev2 = ports[srcPort];

    // TODO: SOMENTE SE ELA ESTIVER ATIVA
    if (dev2 == NULL)
        goto drop;

    skb->dev = dev2;

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

static int xlan_notify_phys (struct notifier_block* const nb, const unsigned long event, void* const info) {

    net_device_s* dev = netdev_notifier_info_to_dev(info);

    if (dev == xdev)
        // IGNORA EVENTOS DELA MESMA
        goto done;

    if (event != NETDEV_REGISTER
     && event != NETDEV_CHANGEADDR)
        //
        goto done;

    const void* const addr = dev->dev_addr;

    const uint code = *(eth_code_t*) addr;
    const uint host = *(eth_host_t*)(addr + sizeof(eth_code_t));
    const uint port = *(eth_port_t*)(addr + sizeof(eth_code_t) + sizeof(eth_host_t));

    if (code != BE32(XLAN_MAC_CODE))
        // NÃO É NOSSO MAC
        goto done;

    if (host != HOST_ID) {
        printk("XLAN: HOST MISMATCH\n");
        goto done;
    }

    if (port >= HOST_PORTS_Q) {
        printk("XLAN: BAD PORT\n");
        goto done;
    }

    net_device_s* const old = ports[port];

    if (old != dev) {
        
        rtnl_lock();

        if (rcu_dereference(dev->rx_handler) != xlan_in        
            && netdev_rx_handler_register(dev, xlan_in, NULL) != 0)
            // NÃO ESTÁ HOOKADA
            // E NEM CONSEGUIU HOOKAR    
            dev = NULL;

        rtnl_unlock();

        if (old)
            dev_put(old);

        if ((ports[port] = dev))
            dev_hold(dev);
    }

done:
    return NOTIFY_OK;
}

static notifier_block_s notifyDevs = {
    .notifier_call = xlan_notify_phys
};

static int __init xlan_init (void) {

    printk("XLAN: INIT\n");

    BUILD_BUG_ON(offsetof(eth_s, _align) != ETH_SIZE);

    // CREATE THE VIRTUAL INTERFACE
    if ((xdev = alloc_netdev(0, "xlan", NET_NAME_USER, xlan_setup)))
        return -1;

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(xdev)) {
        free_netdev(xdev);
        return -1;
    }

    // COLOCA A PARADA DE EVENTOS
    register_netdevice_notifier(&notifyDevs);

    return 0;
}

static void __exit xlan_exit (void) {

    printk("XLAN: EXIT\n");

    // PARA DE MONITORAR OS EVENTOS
    unregister_netdevice_notifier(&notifyDevs);

    // UNHOOK PHYSICAL INTERFACES
    foreach (i, HOST_PORTS_Q) {

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
    unregister_netdev(xdev);

    free_netdev(xdev);
}

module_init(xlan_init);
module_exit(xlan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XLAN");
MODULE_VERSION("0.1");
