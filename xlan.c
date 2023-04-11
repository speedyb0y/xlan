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
#define HOST 1

// MAX HOSTS IN A LAN
#define XLAN_LAN_HOSTS_MAX 128
// MAX PORTS ON A HOST
#define XLAN_HOST_PORTS_MAX 4

typedef struct xlan_s {    
    const char* const name; // NAME
    const u8 id; // LAN ID    
    const u8 hostsN; // TODO: IMPLEMENTAR ISSO
    const u8 host; // HOST ID
    u8 portsN; // HOW MANY PORTS THIS HOST HAS | lan->portsQ[THIS_HOST]    
    net_device_s* dev; // VIRTUAL INTERFACE    
    net_device_s* portsDevs[XLAN_HOST_PORTS_MAX]; // PHYSICAL INTERFACES    
    u8 portsQ[XLAN_LAN_HOSTS_MAX]; // HOW MANY PORTS EACH HOST HAS | CALCULATED FROM lan->portsMACs[HOST]
    const u8 portsMACs // MAC OF EACH PORT OF EACH HOST
        [XLAN_LAN_HOSTS_MAX]
        [XLAN_HOST_PORTS_MAX]
        [ETH_ALEN];
} xlan_s;

//
#define DEV_LAN(dev) (*(xlan_s**)netdev_priv(dev))

//
#define XLAN_OUI 0x2652U

typedef u16 eth_oui_t;
typedef u16 eth_lid_t;
typedef u8  eth_hid_t;
typedef u8  eth_pid_t;
typedef u16 eth_proto_t;

// ETHERNET HEADER
typedef struct eth_s {
    eth_oui_t dstOUI; // XLAN_OUI
    eth_lid_t dstLan;
    eth_hid_t dstHost;
    eth_pid_t dstPort;
    eth_oui_t srcOUI; // XLAN_OUI
    eth_lid_t srcLan;
    eth_hid_t srcHost;
    eth_pid_t srcPort;
    eth_proto_t protocol;
    u16 _align;
} __attribute__((packed)) eth_s;

#define HOST_LANS_N (sizeof(lans)/sizeof(*lans))

static xlan_s lans[] = {  // TODO: MOSTLY READ
    { .name = "lan",
        .hostsN = 64,
        .host = HOST,
        .portsMACs = {
            [ 1] = { "\x88\xC9\xB3\xB0\xF1\xEB", "\x88\xC9\xB3\xB0\xF1\xEA" },
            [10] = { "\x00\x00\x00\x00\x00\x00" },
            [20] = { "\xBC\x5F\xF4\xF9\xE6\x66", "\xBC\x5F\xF4\xF9\xE6\x67" },
            [30] = { "\x00\x00\x00\x00\x00\x00" },
            [40] = { "\x00\x00\x00\x00\x00\x00" },
            [70] = { "\x00\x00\x00\x00\x00\x00" },
        }
    }
};

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    eth_s* eth = SKB_MAC(skb);

    if (PTR(eth) < SKB_HEAD(skb)
    || (PTR(eth) + ETH_SIZE) > SKB_TAIL(skb)) {
        // TENTAR NOVAMENTE, MAS APÓS LINEARIZAR
        // TODO: FIXME: pskb vs skb??? sera que vai te rque fazer skb_copy() e depois *pskb = skb ?
        // e aí faz ou não kfree_skb()?
        if (skb_linearize(skb))
            goto pass;
        eth = SKB_MAC(skb);
        if (PTR(eth) < SKB_HEAD(skb)
        || (PTR(eth) + ETH_SIZE) > SKB_TAIL(skb))
            goto pass;
    }

    const uint oui = BE16(eth->dstOUI);
    const uint lid = BE16(eth->dstLan);
    const uint hid =      eth->dstHost;
    const uint pid =      eth->dstPort;

    // CONFIRM ITS XLAN
    if (oui != XLAN_OUI)
        goto pass;

    // VALIDATE LAN
    if (lid >= HOST_LANS_N)
        goto drop;

    xlan_s* const lan = &lans[lid];

    // CONFIRM ITS OURS
    if (hid != lan->host)
        goto drop;

    // VALIDATE PORT
    if (pid >= lan->portsN)
        goto drop;

    // CONFIRM IT CAME ON THE PHYSICAL
    if (skb->dev != lan->portsDevs[pid])
        goto drop;

    net_device_s* const dev = lan->dev;

    if (dev == NULL)
        goto drop;

    // SE A INTERFACE XLAN ESTIVER DOWN, PASS
    if (dev->flags & IFF_UP)
        goto drop;

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
    skb->dev              = dev;

    return RX_HANDLER_ANOTHER;

pass:
    return RX_HANDLER_PASS;

drop: // TODO: dev_kfree_skb ?

    kfree_skb(skb);

    return RX_HANDLER_CONSUMED;
}

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const dev) {

    xlan_s* const lan = DEV_LAN(dev);

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
                case IPPROTO_SCTP: // TODO: CONSIDER IPV6 FLOW?
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
    const uint srcPort = hash %  lan->portsN;
                         hash /= lan->portsN;
    const uint dstPort = hash %  lan->portsQ[dstHost];

    // INSERT ETHERNET HEADER
    eth_s* const eth = PTR(ip) - ETH_SIZE;

    if (PTR(eth) < SKB_HEAD(skb))
        // SEM ESPACO PARA COLOCAR O MAC HEADER
        goto drop;

    eth->dstOUI   = BE16(XLAN_OUI);
    eth->dstLan   = BE16(lan->id);
    eth->dstHost  = dstHost;
    eth->dstPort  = dstPort;
    eth->srcOUI   = BE16(XLAN_OUI);
    eth->srcLan   = BE16(lan->id);
    eth->srcHost  = lan->host;
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
    net_device_s* const devPort = lan->portsDevs[srcPort];

    // TODO: SOMENTE SE ELA ESTIVER ATIVA
    if (devPort == NULL)
        goto drop;

    skb->dev = devPort;

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

    printk("XLAN: LAN %s: VIRT %s UP\n", DEV_LAN(dev)->name, dev->name);

    return 0;
}

static int xlan_down (net_device_s* const dev) {

    printk("XLAN: LAN %s: VIRT %s DOWN\n", DEV_LAN(dev)->name, dev->name);

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

    // CONSIDERA SOMENTE ESTES EVENTOS
    if (event != NETDEV_REGISTER
     && event != NETDEV_CHANGEADDR)
        goto done;

    net_device_s* port = netdev_notifier_info_to_dev(info);

    // IGNORA EVENTOS DE LANS
    // TODO: FIXME: IDENTIFICAR SE A INTERFACE É UMA LAN
    if (0)
        goto done;

    // TODO: FIXME: CONFIRM ADDR LEN == ETH_ALEN
    const eth_s* const addr = PTR(port->dev_addr);

    //
    if (addr == NULL)
        goto done;

    const uint oui = BE16(addr->dstOUI);
    const uint lid = BE16(addr->dstLan);
    const uint hid =      addr->dstHost;
    const uint pid =      addr->dstPort;

    // CONFIRMA SE É XLAN
    if (oui != XLAN_OUI)
        goto done;

    printk("XLAN: FOUND PHYSICAL %s WITH LAN %u HOST %u PORT %u\n",
        port->name, lid, hid, pid);

    if (lid >= HOST_LANS_N) {
        printk("XLAN: BAD LAN\n");
        goto done;        
    }
    
    xlan_s* const lan = &lans[lid];

    // NAO PODE CHEGAR AQUI COM EVENTOS DELA MESMA
    //ASSERT(port != lan->dev);

    if (hid != lan->host) {
        printk("XLAN: HOST MISMATCH\n");
        goto done;
    }

    if (pid >= lan->portsN) {
        printk("XLAN: BAD PORT\n");
        goto done;
    }

    net_device_s* const old = lan->portsDevs[pid];

    if (old == NULL) {
        
        rtnl_lock();

        if (rcu_dereference(port->rx_handler) != xlan_in        
            && netdev_rx_handler_register(port, xlan_in, NULL) != 0)
            // NÃO ESTÁ HOOKADA
            // E NÃO CONSEGUIU HOOKAR    
            port = NULL;

        rtnl_unlock();

        if (port) {
            printk("XLAN: HOOKED PHYSICAL\n");
            dev_hold((lan->portsDevs[pid] = port));
        } else
            printk("XLAN: FAILED TO HOOK PHYSICAL\n");
    
    } elif (old != port)
        printk("XLAN: CANNOT CHANGE PHYSICAL\n");

done:
    return NOTIFY_OK;
}

static notifier_block_s notifyDevs = {
    .notifier_call = xlan_notify_phys
};

static int __init xlan_init (void) {

    printk("XLAN: INIT\n");

    BUILD_BUG_ON(offsetof(eth_s, _align) != ETH_SIZE);

    if (HOST_LANS_N == 0)
        goto err;

    if (HOST_LANS_N >= LANS_MAX)
        goto err;

    uint lid = 0;

    do {

        xlan_s* const lan = &lans[lid];

        if (lan->name == NULL) {
            printk("XLAN: NO LAN #%u\n", lid);
            goto next;
        }

        printk("XLAN: CREATING LAN #%u %s\n", lid, lan->name);

        if (lan->host >= XLAN_LAN_HOSTS_MAX) {
            printk("XLAN: INVALID HOST %u\n", lan->host);
            goto next;
        }

        //if (lan->portsN >= XLAN_HOST_PORTS_MAX) {
            //printk("XLAN: INVALID PORTS N %u\n", lan->portsN);
            //goto next;
        //}

        // CREATE THE VIRTUAL INTERFACE
        net_device_s* const dev = alloc_netdev(sizeof(xlan_s*), lan->name, NET_NAME_USER, xlan_setup);
        
        if (dev == NULL) {
            printk("XLAN: FAILED TO CREATE VIRTUAL\n");
            goto next;
        }

        // MAKE IT VISIBLE IN THE SYSTEM
        if (register_netdev(dev)) {
            printk("XLAN: FAILED TO REGISTER VIRTUAL\n");
            free_netdev(virdevt);
            goto next;
        }

        DEV_LAN(dev) = lan;

        // CONTA QUANTAS PORTAS TEM EM CADA HOST
        foreach (h, XLAN_LAN_HOSTS_MAX) {
            uint p = 0;
            while (*(u32*)(lan->portsMACs[h][p]))
                p++;
            lan->portsQ[h] = p;
        }

        lan->dev = dev;
        lan->portsN = // SO WE NEED TO SPECIFY IT ONLY ONCE
        lan->portsQ[lan->host];
next:
    } while (++lid != HOST_LANS_N);

    // COLOCA A PARADA DE EVENTOS
    if (register_netdevice_notifier(&notifyDevs) < 0)
        goto err;

    return 0;

err:
    // CLEANUP
    while (lid) {

        const xlan_s* const lan = &lans[--lid];

        if (lan->dev) {
            unregister_netdev(lan->dev);
            free_netdev(lan->dev);
        }
    }

    return -1;
}

static void __exit xlan_exit (void) {

    printk("XLAN: EXIT\n");

    // PARA DE MONITORAR OS EVENTOS
    unregister_netdevice_notifier(&notifyDevs);

    foreach (lid, HOST_LANS_N) {

        const xlan_s* const lan = &lans[lid];

        printk("XLAN: DESTROYING LAN #%u %s\n", lid, lan->name);

        // UNHOOK PHYSICAL INTERFACES
        foreach (pid, lan->portsN) {

            net_device_s* const port = lan->portsDevs[pid];

            if (port) {

                printk("XLAN: UNHOOKING PORT #%u PHYSICAL %s\n", pid, port->name);

                rtnl_lock();

                if (rcu_dereference(port->rx_handler) == xlan_in)
                    netdev_rx_handler_unregister(port);

                rtnl_unlock();

                dev_put(port);
            }
        }

        if (lan->dev) {

            printk("XLAN: DESTROYING VIRTUAL %s\n", lan->dev->name);

            // DESTROY VIRTUAL INTERFACE
            unregister_netdev(lan->dev);

            free_netdev(lan->dev);
        }
    }
}

module_init(xlan_init);
module_exit(xlan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XLAN");
MODULE_VERSION("0.1");
