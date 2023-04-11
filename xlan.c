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

//
#define XLAN_HOST_PORTS_MAX 4
// MAX HOSTS IN A LAN
#define XLAN_LAN_HOSTS_MAX 256

typedef struct xlan_s {
    // NAME
    const char* const name;
    //
    const uint host;
    //
    uint portsN;
    // VIRTUAL INTERFACE
    net_device_s* virt;
    // PHYSICAL INTERFACES
    net_device_s* phys[XLAN_HOST_PORTS_MAX];
    // QUANTITY OF PORTS OF EACH HOST
    const u8 portsQ[XLAN_LAN_HOSTS_MAX];
} xlan_s;

#define HOST_LANS_N (sizeof(lans)/sizeof(*lans))

static xlan_s lans[] = {
    { .name = "lan",
        .host = HOST,
        .portsQ = {
            [ 1] = 2,
            [10] = 1,
            [20] = 1,
            [30] = 2,
            [40] = 1,
            [70] = 1,
        }
    }
};

#define VIRT_LAN(v) (*(xlan_s**)netdev_priv(v))

//
#define XLAN_OUI 0x0025U

typedef u16 eth_oui_t;
typedef u16 eth_lid_t;
typedef u8  eth_hid_t;
typedef u8  eth_pid_t;
typedef u16 eth_proto_t;

// ETHERNET HEADER
typedef struct eth_s {
    eth_oui_t dstOUI; // XLAN_OUI
    eth_lid_t  dstLan;
    eth_hid_t dstHost;
    eth_pid_t dstPort;
    eth_oui_t srcOUI; // XLAN_OUI
    eth_lid_t  srcLan;
    eth_hid_t srcHost;
    eth_pid_t srcPort;
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

    const uint code = BE16(eth->dstOUI);
    const uint lid  = BE16(eth->dstLan);
    const uint hid  =      eth->dstHost;
    const uint pid  =      eth->dstPort;

    if (code != XLAN_OUI)
        // NOT FROM XLAN
        goto pass;
    
    if (pid == 0)
        // NOT A SWITCH PORT
        goto pass;

    if (pid >= XLAN_HOST_PORTS_MAX)
        // INVALID PORT
        goto pass;

    if (lid >= XLAN_LAN_HOSTS_MAX)
        // INVALID LAN
        goto pass;

    if (lid >= HOST_LANS_N)
        // INVALID LAN
        goto pass;

    xlan_s* const lan = &lans[lid];

    if (hid != lan->host)
        // NOT OURS
        goto pass;

    if (pid >= lan->portsN)
        // INVALID LOCAL PORT
        goto pass;

    net_device_s* const virt = lan->virt;

    // TODO: SE A INTERFACE XLAN ESTIVER DOWN, PASS OU DROP?
    if (virt == NULL)
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
    skb->dev              = virt;

    return RX_HANDLER_ANOTHER;

pass:
    return RX_HANDLER_PASS;
}

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const virt) {

    xlan_s* const lan = VIRT_LAN(virt);

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
    const uint srcPort = hash %  lan->portsN;
                         hash /= lan->portsN;
    const uint dstPort = hash %  lan->portsQ[dstHost];

    // INSERT ETHERNET HEADER
    eth_s* const eth = PTR(ip) - ETH_SIZE;

    if (PTR(eth) < SKB_HEAD(skb))
        // SEM ESPACO PARA COLOCAR O MAC HEADER
        goto drop;

    eth->dstOUI   = BE16(XLAN_OUI);
    eth->dstLan   = 0;
    eth->dstHost  = dstHost;
    eth->dstPort  = dstPort;
    eth->srcOUI   = BE16(XLAN_OUI);
    eth->srcLan   = 0;
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
    net_device_s* const dev2 = lan->phys[srcPort];

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

static int xlan_up (net_device_s* const virt) {

    printk("XLAN: LAN %s: VIRT %s UP\n", VIRT_LAN(virt)->name, virt->name);

    return 0;
}

static int xlan_down (net_device_s* const virt) {

    printk("XLAN: LAN %s: VIRT %s DOWN\n", VIRT_LAN(virt)->name, virt->name);

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

    net_device_s* dev = netdev_notifier_info_to_dev(info);

    // IGNORA EVENTOS DE LANS
    // TODO: FIXME: IDENTIFICAR SE A INTERFACE É UMA LAN
    if (0)
        goto done;

    // TODO: FIXME: CONFIRM ADDR LEN == ETH_ALEN
    const void* const addr = dev->dev_addr;

    //
    if (addr == NULL)
        goto done;

    const uint oui = *(eth_oui_t*)(addr);
    const uint lid = *(eth_lid_t*)(addr + sizeof(eth_oui_t));
    const uint hid = *(eth_hid_t*)(addr + sizeof(eth_oui_t) + sizeof(eth_lid_t));
    const uint pid = *(eth_pid_t*)(addr + sizeof(eth_oui_t) + sizeof(eth_lid_t) + sizeof(eth_hid_t));

    // CONFIRMA SE É XLAN
    if (oui != BE16(XLAN_OUI))
        goto done;

    printk("XLAN: FOUND INTERFACE %s WITH LAN %u HOST %u PORT %u\n",
        dev->name, lid, hid, pid);

    if (lid >= HOST_LANS_N) {
        printk("XLAN: BAD LAN\n");
        goto done;        
    }
    
    xlan_s* const lan = &lans[lid];

    // NAO PODE HEGAR AQUI COM EVENTOS DELA MESMA
    //ASSERT(dev != lan->virt);

    if (hid != lan->host) {
        printk("XLAN: HOST MISMATCH\n");
        goto done;
    }

    if (pid >= lan->portsN) {
        printk("XLAN: BAD PORT\n");
        goto done;
    }

    net_device_s* const old = lan->phys[pid];

    if (old == NULL) {
        
        rtnl_lock();

        if (rcu_dereference(dev->rx_handler) == xlan_in        
            && netdev_rx_handler_register(dev, xlan_in, NULL) != 0)
            // JÁ ESTÁ HOOKADA
            // OU NÃO CONSEGUIU HOOKAR    
            dev = NULL;

        rtnl_unlock();

        if (dev) {
            printk("XLAN: HOOKED INTERFACE\n");
            dev_hold((lan->phys[pid] = dev));
        } else
            printk("XLAN: FAILED TO HOOK INTERFACE\n");
    
    } elif (old != dev)
        printk("XLAN: CANNOT CHANGE INTERFACE\n");

done:
    return NOTIFY_OK;
}

static notifier_block_s notifyDevs = {
    .notifier_call = xlan_notify_phys
};

static int __init xlan_init (void) {

    printk("XLAN: INIT\n");

    BUILD_BUG_ON(offsetof(eth_s, _align) != ETH_SIZE);

    uint lid = 0;

    while (lid != HOST_LANS_N) {

        xlan_s* const lan = &lans[lid];

        if (lan->name == NULL) {
            printk("XLAN: NO LAN #%u\n", lid);
            continue;
        }

        printk("XLAN: CREATING LAN #%u %s\n", lid, lan->name);

        if (lan->host >= XLAN_LAN_HOSTS_MAX) {
            printk("XLAN: INVALID HOST %u\n", lan->host);
            continue;
        }

        if (lan->portsN >= XLAN_HOST_PORTS_MAX) {
            printk("XLAN: INVALID PORTS N %u\n", lan->portsN);
            continue;
        }

        // CREATE THE VIRTUAL INTERFACE
        net_device_s* const virt = alloc_netdev(sizeof(xlan_s*), lan->name, NET_NAME_USER, xlan_setup);
        
        if (virt == NULL) {
            printk("XLAN: FAILED TO CREATE VIRTUAL\n");
            continue;
        }

        // MAKE IT VISIBLE IN THE SYSTEM
        if (register_netdev(virt)) {
            printk("XLAN: FAILED TO REGISTER VIRTUAL\n");
            free_netdev(virt);
            continue;
        }

        VIRT_LAN(virt) = lan;

        lan->virt = virt;
        lan->portsN = // SO WE NEED TO SPECIFY IT ONLY ONCE
        lan->portsQ[lan->host];
    }

    // COLOCA A PARADA DE EVENTOS
    if (register_netdevice_notifier(&notifyDevs) < 0)
        goto err;

    return 0;

err:
    // CLEANUP
    while (lid) {

        const xlan_s* const lan = &lans[--lid];

        if (lan->virt) {
            unregister_netdev(lan->virt);
            free_netdev(lan->virt);
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

            net_device_s* const phys = lan->phys[pid];

            if (phys) {

                printk("XLAN: UNHOOKING PORT #%u PHYSICAL %s\n", pid, phys->name);

                rtnl_lock();

                if (rcu_dereference(phys->rx_handler) == xlan_in)
                    netdev_rx_handler_unregister(phys);

                rtnl_unlock();

                dev_put(phys);
            }
        }

        if (lan->virt) {

            printk("XLAN: DESTROYING VIRTUAL %s\n", lan->virt->name);

            // DESTROY VIRTUAL INTERFACE
            unregister_netdev(lan->virt);

            free_netdev(lan->virt);
        }
    }
}

module_init(xlan_init);
module_exit(xlan_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("speedyb0y");
MODULE_DESCRIPTION("XLAN");
MODULE_VERSION("0.1");
