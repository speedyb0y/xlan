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

#define XLAN_LANS_N 16 // HOW MANY LANS CAN EXIST
#define XLAN_HOSTS_N 128 // HOW MANY HOSTS A LAN CAN HAVE
#define XLAN_PORTS_N 4 // HOW MANY PORTS A HOST CAN HAVE

#define IP4_NET       0xC0A80000U
#define IP4_MASK_NET  0xFFFFFF00U
#define IP4_MASK_HOST 0x000000FFU

#define IP6_NET       0x00000000622500FCULL // TODO: BE64()
            
#define IP6_O_PROTO  5
#define IP6_O_SRC1   8
#define IP6_O_SRC2  16
#define IP6_O_DST1  24
#define IP6_O_DST2  32
            
#define IP4_O_PROTO 9
#define IP4_O_SRC 12
#define IP4_O_DST 16

#define XLAN_NAME "lan-x"

static net_device_s* xdev;
static net_device_s* devs[XLAN_PORTS_N]; // PHYSICAL INTERFACES    
static u8 portsQ[XLAN_HOSTS_N]; // HOW MANY PORTS EACH HOST HAS

// MAC OF EACH PORT OF EACH HOST
static const u8 macs [XLAN_HOSTS_N] [XLAN_PORTS_N] [ETH_ALEN] = {
    [ 1] = { "\x88\xC9\xB3\xB0\xF1\xEB", "\x88\xC9\xB3\xB0\xF1\xEA" },
    [10] = { "\x00\x00\x00\x00\x00\x00" },
    [20] = { "\xBC\x5F\xF4\xF9\xE6\x66", "\xBC\x5F\xF4\xF9\xE6\x67" },
    [30] = { "\x00\x00\x00\x00\x00\x00" },
    [40] = { "\x00\x00\x00\x00\x00\x00" },
    [70] = { "\x00\x00\x00\x00\x00\x00" },
};

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {

    sk_buff_s* const skb = *pskb;

    switch (skb->protocol) {
        case BE16(ETH_P_IP):
        case BE16(ETH_P_IPV6):
            break;
        case BE16(ETH_P_ARP):
            goto drop;
        default:
            goto drop;
    }

    if (skb_linearize(skb))
        goto drop;

    // WHEN IN PROMISCUOUS MODE
    //if (skb->pkt_type == PACKET_OTHERHOST)
        //goto pass;
    
    // PULA O ETHERNET HEADER
    void* const ip = SKB_NETWORK(skb);

    if (PTR(ip) < SKB_HEAD(skb)
     || PTR(ip) > SKB_TAIL(skb))
        goto drop;
    
    // SE A INTERFACE XLAN ESTIVER DOWN, DROP
    if (!(xdev->flags & IFF_UP))
        goto drop;    
   
    // NOTE: skb->network_header JA ESTA CORRETO
    skb->mac_len    = 0;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header = skb->network_header;
#else
    skb->mac_header = skb->network_header;
#endif
    skb->data       = PTR(ip);
    skb->len        = SKB_TAIL(skb) - PTR(ip);
    skb->dev        = xdev;

    return RX_HANDLER_ANOTHER;

pass:
    return RX_HANDLER_PASS;

drop: // TODO: dev_kfree_skb ?

    kfree_skb(skb);

    return RX_HANDLER_CONSUMED;
}

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const xdev) {

    if (skb_linearize(skb))
        // NON LINEAR
        goto drop;

    void* const ip = SKB_NETWORK(skb);

    if (PTR(ip) < SKB_HEAD(skb)
     || PTR(ip) > SKB_TAIL(skb))
        goto drop;

    uint dstHost;  // IDENTIFY HOST BY IP DESTINATION
    uint hsize; // MINIMUM SIZE    
    uintll hash; // COMPUTE HASH    

    // IP VERSION
    switch (*(u8*)ip >> 4) {

        case 4: // TODO: VER DENTRO DAS MENSAGENS ICMP E GERAR O MESMO HASH DESSES AQUI

            dstHost = BE32(*(u32*)(ip + IP4_O_DST));

            if ((dstHost & IP4_MASK_NET) == IP4_NET)
                dstHost &= IP4_MASK_HOST;
            else // GW
                dstHost = 1;
            
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

            if (*(u64*)(ip + IP6_O_DST1) == IP6_NET) {
                dstHost = *(u8*)(ip + IP6_SIZE - 1);
                dstHost = (dstHost >> 4)*10 + (dstHost & 0xF);
            } else // GW
                dstHost = 1;

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

    hash += hash >> 32;
    hash += hash >> 16;
    hash += hash >> 8;

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
           eth->protocol = skb->protocol;

    skb->mac_len          = ETH_HLEN;
    skb->data             = PTR(eth);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    skb->mac_header       = PTR(eth) - SKB_HEAD(skb);
#else
    skb->mac_header       = PTR(eth);
#endif
    skb->len              = SKB_TAIL(skb) - PTR(eth);

    //
    net_device_s* const dev = devs[srcPort];

    // SOMENTE SE ELA ESTIVER ATIVA
    if (!(dev && dev->flags & IFF_UP))
        goto drop;

    skb->dev = dev;

    // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
    // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
    // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
    dev_queue_xmit(skb);

    return NETDEV_TX_OK;

drop:
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int xlan_up (net_device_s* const xdev) {

    printk("XLAN: UP\n");

    return 0;
}

static int xlan_down (net_device_s* const xdev) {

    printk("XLAN: DOWN\n");

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

    // ASSERT: rtnl_is_locked()

    // CONSIDERA SOMENTE ESTES EVENTOS
    if (event != NETDEV_REGISTER
     && event != NETDEV_CHANGEADDR)
        goto done;

    net_device_s* dev = netdev_notifier_info_to_dev(info);

    // IGNORA EVENTOS DELA MESMA
    if (dev == xdev)
        goto done;

    // TODO: FILTRAR LOOPBACK
    // TODO: FILTRAR ETHERNET
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

    foreach (pid, XLAN_PORTS_N) {

        if (devs[pid]) {
            if (devs[pid] == dev)
                // ESTA INTERFACE NAO PODE SER USADA NOVAMENTE NA MESMA LAN
                break;
        } elif (memcmp(macs[HOST][pid], mac, ETH_ALEN) == 0) {

            const char* fmt;

            if (rcu_dereference(dev->rx_handler) == xlan_in        
                || netdev_rx_handler_register(dev, xlan_in, NULL) == 0) {
                dev_hold((devs[pid] = dev));
                fmt = "XLAN: PORT %u: HOOK PHYSICAL %s: SUCCESS\n";
            } else
                // NÃO ESTÁ HOOKADA
                // E NÃO CONSEGUIU HOOKAR
                fmt = "XLAN: PORT %u: HOOK PHYSICAL %s: FAILED\n";
            
            printk(fmt, pid, dev->name);

            // ESTA INTERFACE NAO PODE SER USADA NOVAMENTE NA MESMA LAN
            break;
        }
    }

done:
    return NOTIFY_OK;
}

static notifier_block_s notifyDevs = {
    .notifier_call = xlan_notify_phys
};

static int __init xlan_init (void) {

    printk("XLAN: INITIALIZING AS HOST %u PORTS %u VIRTUAL %s\n", HOST, portsQ[HOST], XLAN_NAME);

    if (HOST >= XLAN_HOSTS_N) {
        printk("XLAN: BAD HOST ID\n");
        goto err;
    }

    if (portsQ[HOST] == 0) {
        printk("XLAN: NO PORTS\n");
        goto err;
    }

    if (portsQ[HOST] >= XLAN_PORTS_N) {
        printk("XLAN: BAD NUMBER OF PORTS\n");
        goto err;
    }

    // CREATE THE VIRTUAL INTERFACE
    xdev = alloc_netdev(0, XLAN_NAME, NET_NAME_USER, xlan_setup);
    
    if (xdev == NULL) {
        printk("XLAN: FAILED TO CREATE VIRTUAL\n");
        goto err;
    }

    // MAKE IT VISIBLE IN THE SYSTEM
    if (register_netdev(xdev)) {
        printk("XLAN: FAILED TO REGISTER VIRTUAL\n");
        goto err_free;
    }

    // CONTA QUANTAS PORTAS TEM EM CADA HOST
    foreach (hid, XLAN_HOSTS_N) {
        uint pid = 0;
        while (*(u32*)(macs[hid][pid]))
            pid++;            
        if (pid)
            printk("XLAN: HOST %u HAS %u PORTS\n", hid, pid);
        portsQ[hid] = pid;
    }
    
    // WILL YET DISCOVER THE PHYSICAL INTERFACES
    foreach (pid, XLAN_PORTS_N)
        devs[pid] = NULL;

    // COLOCA A PARADA DE EVENTOS
    if (register_netdevice_notifier(&notifyDevs) < 0) {
        printk("XLAN: FAILED TO REGISTER NETWORK DEVICES NOTIFIER\n");
        goto err_unregister;
    }

    return 0;

err_unregister:
    unregister_netdev(xdev);
err_free:
    free_netdev(xdev);
err:
    return -1;
}

static void __exit xlan_exit (void) {

    printk("XLAN: EXIT\n");

    // PARA DE MONITORAR OS EVENTOS
    unregister_netdevice_notifier(&notifyDevs);

    // UNHOOK PHYSICAL INTERFACES
    foreach (pid, XLAN_PORTS_N) {

        net_device_s* const dev = devs[pid];

        if (dev) {

            printk("XLAN: PORT %u: UNHOOKING PHYSICAL %s\n", pid, dev->name);

            rtnl_lock();

            if (rcu_dereference(dev->rx_handler) == xlan_in)
                netdev_rx_handler_unregister(dev);

            rtnl_unlock();

            dev_put(dev);
        }
    }

    printk("XLAN: DESTROYING VIRTUAL\n");

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
