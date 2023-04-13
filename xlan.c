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

typedef struct xlan_cfg_s {    
    const char* name; // O NOME INICIAL DA INTERFACE
    u8 lan; // LAN ID    
    u8 host; // HOST ID
    u8 macs // MAC OF EACH PORT OF EACH HOST
        [XLAN_HOSTS_N]
        [XLAN_PORTS_N]
        [ETH_ALEN];
} xlan_cfg_s;

// TODO: USAR MASK DE PORTAS QUE POSSUI
// TODO: USAR MASK DE PORTAS USAVEIS
// TODO: USAR AQUELA PARADA DE BITS
typedef struct xlan_s {    
    u8 lid; // LAN ID    
    u8 hid; // HOST ID
    u8 P; // HOW MANY PORTS THIS HOST HAS
    u8 PH[XLAN_HOSTS_N]; // HOW MANY PORTS EACH HOST HAS
    net_device_s* devs[XLAN_PORTS_N]; // PHYSICAL INTERFACES    
    u8 macs[XLAN_PORTS_N][ETH_ALEN]; // MAC OF EACH PORT
} xlan_s;

//
#define DEV_LAN(dev) ((xlan_s*)netdev_priv(dev))

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

// HOW MANY LANS THIS HOST HAS
#define CFGS_N (sizeof(cfgs)/sizeof(*cfgs))

static const xlan_cfg_s cfgs[] = {
    { .name = "lan-x",
        .lan = 0,
        .host = 1,
        .macs = {
            [ 1] = { "\x88\xC9\xB3\xB0\xF1\xEB", "\x88\xC9\xB3\xB0\xF1\xEA" },
            [10] = { "\x00\x00\x00\x00\x00\x00" },
            [20] = { "\xBC\x5F\xF4\xF9\xE6\x66", "\xBC\x5F\xF4\xF9\xE6\x67" },
            [30] = { "\x00\x00\x00\x00\x00\x00" },
            [40] = { "\x00\x00\x00\x00\x00\x00" },
            [70] = { "\x00\x00\x00\x00\x00\x00" },
        }
    }
};

static net_device_s* lans[XLAN_LANS_N];

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
    if (lid >= XLAN_LANS_N)
        goto drop;

    net_device_s* const dev = lans[lid];
    
    //
    if (dev == NULL)
        goto drop;

    // SE A INTERFACE XLAN ESTIVER DOWN, DROP
    if (!(dev->flags & IFF_UP))
        goto drop;    

    xlan_s* const lan = DEV_LAN(dev);   

    // CONFIRM ITS OURS
    if (hid != lan->hid)
        goto drop;

    // VALIDATE PORT
    // CONFIRM IT CAME ON THE PHYSICAL
    if (skb->dev != lan->devs[pid])
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
#if 0
    kfree_skb(skb);

    return RX_HANDLER_CONSUMED;
#else
    return RX_HANDLER_PASS;
#endif
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

    uint dstHost;  // IDENTIFY HOST BY IP DESTINATION
    uint hsize; // MINIMUM SIZE    
    uintll hash; // COMPUTE HASH    

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

    const uint dstPortsN = lan->PH[dstHost];

    if (dstPortsN == 0)
        // DESTINATION HOST HAS NO PORTS
        goto drop;
    
    const uint dstPort = hash %  dstPortsN; // CHOOSE THEIR INTERFACE
                         hash /= dstPortsN;
    const uint srcPort = hash %  lan->P; // CHOOSE MY INTERFACE

    // INSERT ETHERNET HEADER
    eth_s* const eth = PTR(ip) - ETH_SIZE;

    if (PTR(eth) < SKB_HEAD(skb))
        // SEM ESPACO PARA COLOCAR O MAC HEADER
        goto drop;

    eth->dstOUI   = BE16(XLAN_OUI);
    eth->dstLan   = BE16(lan->lid);
    eth->dstHost  = dstHost;
    eth->dstPort  = dstPort;
    eth->srcOUI   = BE16(XLAN_OUI);
    eth->srcLan   = BE16(lan->lid);
    eth->srcHost  = lan->hid;
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
    net_device_s* const devPort = lan->devs[srcPort];

    if (devPort == NULL)
        goto drop;

    // SOMENTE SE ELA ESTIVER ATIVA
    if (!(devPort->flags & IFF_UP))
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

    printk("XLAN: LAN %u: UP %s\n", DEV_LAN(dev)->lid, dev->name);

    return 0;
}

static int xlan_down (net_device_s* const dev) {

    printk("XLAN: LAN %u: DOWN %s\n", DEV_LAN(dev)->lid, dev->name);

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

    // IGNORA EVENTOS DE LANS
    // TODO: FIXME: IDENTIFICAR SE A INTERFACE É UMA LAN
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

    foreach (lid, XLAN_LANS_N) {

        net_device_s* const xdev = lans[lid];

        if (xdev == NULL)
            continue;

        // NAO PODE CHEGAR AQUI COM EVENTOS DELA MESMA
        if (xdev == dev) {
            goto done;
        }

        xlan_s* const lan = DEV_LAN(xdev);

        foreach (pid, XLAN_PORTS_N) {

            if (lan->devs[pid]) {
                if (lan->devs[pid] == dev)
                    // ESTA INTERFACE NAO PODE SER USADA NOVAMENTE NA MESMA LAN
                    break;
            } elif (memcmp(lan->macs[pid], mac, ETH_ALEN) == 0) {

                const char* fmt;

                if (rcu_dereference(dev->rx_handler) == xlan_in        
                    || netdev_rx_handler_register(dev, xlan_in, NULL) == 0) {
                    dev_hold((lan->devs[pid] = dev));
                    fmt = "XLAN: LAN %u: PORT %u: HOOK PHYSICAL %s: SUCCESS\n";
                } else
                    // NÃO ESTÁ HOOKADA
                    // E NÃO CONSEGUIU HOOKAR
                    fmt = "XLAN: LAN %u: PORT %u: HOOK PHYSICAL %s: FAILED\n";
                
                printk(fmt, lid, pid, dev->name);

                // ESTA INTERFACE NAO PODE SER USADA NOVAMENTE NA MESMA LAN
                break;
            }
        }
    }

done:
    return NOTIFY_OK;
}

static notifier_block_s notifyDevs = {
    .notifier_call = xlan_notify_phys
};

static int __init xlan_init (void) {

    BUILD_BUG_ON(offsetof(eth_s, _align) != ETH_SIZE);

    BUILD_BUG_ON((eth_oui_t) XLAN_OUI          !=  XLAN_OUI);
    BUILD_BUG_ON((eth_lid_t)(XLAN_LANS_N  - 1) != (XLAN_LANS_N  - 1));
    BUILD_BUG_ON((eth_hid_t)(XLAN_HOSTS_N - 1) != (XLAN_HOSTS_N - 1));
    BUILD_BUG_ON((eth_pid_t)(XLAN_PORTS_N - 1) != (XLAN_PORTS_N - 1));

    BUILD_BUG_ON((typeof(DEV_LAN(*lans)->lid)) (XLAN_LANS_N  - 1) != (XLAN_LANS_N  - 1));
    BUILD_BUG_ON((typeof(DEV_LAN(*lans)->hid)) (XLAN_HOSTS_N - 1) != (XLAN_HOSTS_N - 1));
    BUILD_BUG_ON((typeof(DEV_LAN(*lans)->P))    XLAN_PORTS_N      !=  XLAN_PORTS_N);
    BUILD_BUG_ON((typeof(DEV_LAN(*lans)->PH[0]))XLAN_PORTS_N      !=  XLAN_PORTS_N);

    printk("XLAN: INITIALIZING WITH %u CONFIGURED LANS\n", (uint)CFGS_N);

    if (CFGS_N == 0) {
        printk("XLAN: NO LANS\n");
        goto err;
    }

    if (CFGS_N >= XLAN_LANS_N) {
        printk("XLAN: TOO MANY LANS\n");
        goto err;
    }

    foreach (cid, CFGS_N) {

        const xlan_cfg_s* const cfg = &cfgs[cid];

        const uint lid = cfg->lan;
        const uint hid = cfg->host;

        printk("XLAN: LAN %u: CREATING AS HOST %u\n", lid, hid);

        if (lid >= XLAN_LANS_N) {
            printk("XLAN: LAN %u: BAD LAN ID\n", lid);
            continue;
        }

        if (lans[lid]) {
            printk("XLAN: LAN %u: DUPLICATE LAN ID\n", lid);
            continue;
        }

        if (hid >= XLAN_HOSTS_N) {
            printk("XLAN: LAN %u: BAD HOST ID %u\n", lid, hid);
            continue;
        }

        if (cfg->name == NULL ||
            cfg->name[0] == '\0') {
            printk("XLAN: LAN %u: MISSING NAME\n", lid);
            continue;
        }

        printk("XLAN: LAN %u: CREATING VIRTUAL INTERFACE %s\n", lid, cfg->name);

        // CREATE THE VIRTUAL INTERFACE
        net_device_s* const dev = alloc_netdev(sizeof(xlan_s), cfg->name, NET_NAME_USER, xlan_setup);
        
        if (dev == NULL) {
            printk("XLAN: LAN %u: FAILED TO CREATE VIRTUAL\n", lid);
            continue;
        }

        // MAKE IT VISIBLE IN THE SYSTEM
        if (register_netdev(dev)) {
            printk("XLAN: LAN %u: FAILED TO REGISTER VIRTUAL\n", lid);
            goto failed_free;
        }

        xlan_s* const lan = DEV_LAN(dev);

        // CONTA QUANTAS PORTAS TEM EM CADA HOST
        foreach (hid, XLAN_HOSTS_N) {
            uint pid = 0;
            while (*(u32*)(cfg->macs[hid][pid]))
                pid++;
            lan->PH[hid] = pid;
            printk("XLAN: LAN %u: HOST %u HAS %u PORTS\n", lid, hid, pid);
        }
        
        lan->lid = lid;
        lan->hid = hid;
        lan->P   = //
        lan->PH[hid];

        memcpy(lan->macs,
               cfg->macs[hid],
        sizeof(cfg->macs[hid]));
        
        if (lan->P == 0) {
            printk("XLAN: LAN %u: NO PORTS\n", lid);
            goto failed_free;
        }

        // WILL YET DISCOVER THE PHYSICAL INTERFACES
        foreach (pid, XLAN_PORTS_N)
            lan->devs[pid] = NULL;

        printk("XLAN: LAN %u: HAS %u PORTS\n", lid, lan->P);

        lans[lid] = dev;

        continue;

failed_free:
        free_netdev(dev);        
    }

    // COLOCA A PARADA DE EVENTOS
    if (register_netdevice_notifier(&notifyDevs) < 0) {
        printk("XLAN: FAILED TO REGISTER NETWORK DEVICES NOTIFIER\n");
        goto err;
    }

    return 0;

err:
    // CLEANUP
    foreach (lid, XLAN_LANS_N) {

        net_device_s* const dev = lans[lid];

        if (dev) {
            unregister_netdev(dev);
            free_netdev(dev);
        }
    }

    return -1;
}

static void __exit xlan_exit (void) {

    printk("XLAN: EXIT\n");

    // PARA DE MONITORAR OS EVENTOS
    unregister_netdevice_notifier(&notifyDevs);

    foreach (lid, XLAN_LANS_N) {

        net_device_s* const dev = lans[lid];

        if (dev == NULL)
            continue;

        printk("XLAN: LAN %u: DESTROYING\n", lid);

        const xlan_s* const lan = DEV_LAN(dev);

        // UNHOOK PHYSICAL INTERFACES
        foreach (pid, XLAN_PORTS_N) {

            net_device_s* const dev = lan->devs[pid];

            if (dev) {

                printk("XLAN: LAN %u: PORT %u: UNHOOKING PHYSICAL %s\n", lid, pid, dev->name);

                rtnl_lock();

                if (rcu_dereference(dev->rx_handler) == xlan_in)
                    netdev_rx_handler_unregister(dev);

                rtnl_unlock();

                dev_put(dev);
            }
        }

        printk("XLAN: LAN %u: DESTROYING VIRTUAL %s\n", lid, dev->name);

        // DESTROY VIRTUAL INTERFACE
        unregister_netdev(dev);

        free_netdev(dev);
    }
}

module_init(xlan_init);
module_exit(xlan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XLAN");
MODULE_VERSION("0.1");
