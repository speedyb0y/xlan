/*

*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/timer.h>
#include <net/ip.h>
#include <net/inet_common.h>
#include <net/addrconf.h>

#define __f_hot __attribute__((hot))
#define __f_cold __attribute__((cold))

#ifndef __packed
#define __packed __attribute__((packed))
#endif

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef atomic_t   a32;
typedef atomic64_t a64;

typedef unsigned int uint;
typedef unsigned long long int uintll;

typedef struct sk_buff sk_buff_s;
typedef struct net_device net_device_s;
typedef struct net net_s;
typedef struct net_device_ops net_device_ops_s;
typedef struct notifier_block notifier_block_s;

// TODO: FIXME:
typedef typeof(jiffies) jiffies_t;

#define clear(obj) memset((obj), 0, sizeof(*(obj)))

#define SKB_HEAD(skb) PTR((skb)->head)
#define SKB_DATA(skb) PTR((skb)->data)
#define SKB_TAIL(skb) PTR(skb_tail_pointer(skb))
#define SKB_END(skb)  PTR(skb_end_pointer(skb))

#define SKB_MAC(skb)     PTR(skb_mac_header(skb))
#define SKB_NETWORK(skb) PTR(skb_network_header(skb))

#define PTR(p) ((void*)(p))

#define loop while (1)

#define elif(c) else if (c)

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

#include "xconf.h"

#define HOSTS_N 256 // MULTIPLE OF U64
#define PORTS_N 32 // atomic_t

#define VENDOR             XCONF_XLAN_VENDOR
#define _NET4              XCONF_XLAN_NET4
#define _NET6              XCONF_XLAN_NET6
#define HOST               XCONF_XLAN_HOST
#define GW                 XCONF_XLAN_GW
#define BUCKETS_PER_SECOND XCONF_XLAN_BUCKETS_PER_SECOND
#define BUCKETS_BURST      XCONF_XLAN_BUCKETS_BURST

#define XLAN_TIMER_DELAY    (XCONF_XLAN_TIMER_DELAY*HZ) // AFTER SYSTEM BOOT
#define XLAN_TIMER_INTERVAL (XCONF_XLAN_TIMER_INTERVAL*HZ)

#if !(VENDOR && VENDOR <= 0xFFFFFFFF && !(VENDOR & 0x01000000))
#error "BAD VENDOR"
#endif

#if !(_NET4 && !(_NET4 % HOSTS_N))
#error "BAD NET4"
#endif

#if !(_NET6)
#error "BAD NET6"
#endif

#if !(HOST && HOST < HOSTS_N)
#error "BAD HOST"
#endif

#if !(GW != HOST && GW < HOSTS_N)
#error "BAD GW"
#endif

#if GW == 0
#undef GW
#define GW HOST
#endif

#define ETH_O_DST      0
#define ETH_O_DST_V    0
#define ETH_O_DST_H    4
#define ETH_O_DST_P    5
#define ETH_O_SRC      6
#define ETH_O_SRC_V    6
#define ETH_O_SRC_H   10
#define ETH_O_SRC_P   11
#define ETH_O_TYPE    12
#define ETH_SIZE      14

#define CNTL_TOTAL_SIZE (ETH_SIZE + CNTL_SIZE_)

#define CNTL_O_BOOT     0
#define CNTL_O_COUNTER  8
#define CNTL_O_MASK    16
#define CNTL_SIZE_     64 // YOU MOSTLY WON'T USE IT

#define IP4_O_PROTO   9
#define IP4_O_SRC     12
#define IP4_O_SRC_N   12
#define IP4_O_SRC_H   15
#define IP4_O_DST     16
#define IP4_O_DST_N   16
#define IP4_O_DST_H   19
#define IP4_SIZE      20

#define IP6_O_VERSION  0
#define IP6_O_FLOW     2
#define IP6_O_PROTO    5
#define IP6_O_SRC      8
#define IP6_O_SRC_N    8
#define IP6_O_SRC_H   23
#define IP6_O_DST     24
#define IP6_O_DST_N   24
#define IP6_O_DST_H   39
#define IP6_SIZE      40

#define NET4 ((u32)_NET4)
#define NET6 ((u64)_NET6)

#define ETH_P_XLAN 0x2562

#define MAC_VENDOR(mac) ((u32*)mac)[0]
#define MAC_HOST(mac)    ((u8*)mac)[4]
#define MAC_PORT(mac)    ((u8*)mac)[5]

#define dst_vendor  (*(u32*)(pkt + ETH_O_DST_V))
#define dst_host    (*(u8 *)(pkt + ETH_O_DST_H))
#define dst_port    (*(u8 *)(pkt + ETH_O_DST_P))
#define src_vendor  (*(u32*)(pkt + ETH_O_SRC_V))
#define src_host    (*(u8 *)(pkt + ETH_O_SRC_H))
#define src_port    (*(u8 *)(pkt + ETH_O_SRC_P))
#define pkt_type    (*(u16*)(pkt + ETH_O_TYPE))

#define cntl_bootid  (*(u64*)(pkt + ETH_SIZE + CNTL_O_BOOT))
#define cntl_counter (*(u64*)(pkt + ETH_SIZE + CNTL_O_COUNTER))
#define cntl_mask    (*(u32*)(pkt + ETH_SIZE + CNTL_O_MASK))

#define proto4      (*(u8 *)(pkt + ETH_SIZE + IP4_O_PROTO))
#define addrs4      (*(u64*)(pkt + ETH_SIZE + IP4_O_SRC))
#define src4_net    (*(u32*)(pkt + ETH_SIZE + IP4_O_SRC_N))
#define src4_host   (*(u8 *)(pkt + ETH_SIZE + IP4_O_SRC_H))
#define dst4_net    (*(u32*)(pkt + ETH_SIZE + IP4_O_DST_N))
#define dst4_host   (*(u8 *)(pkt + ETH_SIZE + IP4_O_DST_H))
#define ports4      (*(u32*)(pkt + ETH_SIZE + IP4_SIZE))

#define flow6       (*(u16*)(pkt + ETH_SIZE + IP6_O_FLOW))
#define proto6      (*(u8 *)(pkt + ETH_SIZE + IP6_O_PROTO))
#define addrs6      ( (u64*)(pkt + ETH_SIZE + IP6_O_SRC))
#define src6_net    (*(u64*)(pkt + ETH_SIZE + IP6_O_SRC_N))
#define src6_host   (*(u8 *)(pkt + ETH_SIZE + IP6_O_SRC_H))
#define dst6_net    (*(u64*)(pkt + ETH_SIZE + IP6_O_DST_N))
#define dst6_host   (*(u8 *)(pkt + ETH_SIZE + IP6_O_DST_H))
#define ports6      (*(u32*)(pkt + ETH_SIZE + IP6_SIZE))

// TODO: THOSE MUST BE ATOMIC; AND BOOT AFTER BOOT
typedef struct known_s {
    u64 counter; // CONTROL PACKET COUNTER
    u64 boot; // BOOT ID
} known_s;

typedef struct stream_s {
    u32 ports; // TODO: FIXME: ATOMIC
    u32 last;
} stream_s;

typedef struct bucket_s {
    u32 can; // TODO: FIXME: ATOMIC
    u32 last;
} bucket_s;

#define PHYS_PORT(phys) ((uint)(uintptr_t)(phys)->rx_handler_data)

static void xlan_keeper (struct timer_list*);
static DEFINE_TIMER(doTimer, xlan_keeper);

// TODAS AS PORTAS DE TODOS OS HOSTS
#define ALL_PORTS (HOSTS_N * PORTS_N)

static net_device_s* xlan;
static net_device_s* physs[PORTS_N];
static known_s knowns[HOSTS_N];
static bucket_s buckets[PORTS_N];
static stream_s streams[HOSTS_N][64]; // POPCOUNT64()
static a32 seens[HOSTS_N]; // CADA BIT É UMA PORTA QUE FOI VISTA COMO RECEBENDO
static a32 masks[HOSTS_N]; // CADA WORD É UM MASK, CADA BIT É UMA PORTA QUE ESTA RECEBENDO
static u8 timeouts[HOSTS_N*PORTS_N]; // CADA WORD É UM NUMERO

#define SEEN_MASK(p) (1U << (p))

// ARGUMENTO DA FUNCAO test_and_clear_bit
typedef unsigned long BITWORD_t;

static void xlan_keeper (struct timer_list* const timer) {

    const jiffies_t now = jiffies;

    // UPDATE THE MASKS OF THE PORTS THAT ARE RECEIVING
#if 0
    foreach (h, HOSTS_N) {

        u32 seen = atomic_read(&seens[h]); // TODO: ATOMIC READ AND CLEAR
                    atomic_set(&seens[h], 0);
        u32 mask = atomic_read(&masks[h]);

        foreach (p, PORTS_N) {
            const u32 b = 1U << p;
            if (seen & b) {
                // IN REPORTED IT'S ALIVE            
                mask |= b;
                // KEEP IT ACTIVE FOR A WHILE
                    timeouts[p] = 8;
            } elif (timeouts[p])
                // NOTHING REPORTED, AND IT WAS ON
              if (--timeouts[p] == 0)
                    // NOTHING REPORTED FOR TOO LONG
                    mask ^= b;
        }

        atomic_set(&masks[h], mask);
    }
#endif

    // UPDATE THE MASKS OF THE PORTS THAT ARE RECEIVING
    foreach (p, ALL_PORTS) {
        if (test_and_clear_bit(p, (BITWORD_t*)seens)) {
            // IN REPORTED IT'S ALIVE            
            set_bit(p, (BITWORD_t*)masks);
            // KEEP IT ACTIVE FOR A WHILE
                timeouts[p] = 8;
        } elif (timeouts[p])
            // NOTHING REPORTED, AND IT WAS ON
          if (--timeouts[p] == 0)
                // NOTHING REPORTED FOR TOO LONG
                clear_bit(p, (BITWORD_t*)masks);
    }

    //
    u8* pkt[CNTL_TOTAL_SIZE];

    dst_vendor   = 0xFFFFFFFFU;
    dst_host     = 0xFFU;
    dst_port     = 0xFFU;
    src_vendor   = BE32(VENDOR);
    src_host     = HOST;
    src_port     = 0;
    pkt_type     = BE16(ETH_P_XLAN);
    cntl_bootid  = BE64(knowns[HOST].boot);
    cntl_counter = BE64(knowns[HOST].counter++);
    cntl_mask    = BE32( masks[HOST].counter);

    foreach (p, PORTS_N) {

        net_device_s* const phys = physs[p];

        if (phys && phys->flags & IFF_UP) {

            if (0) {
                // SE ESTAVA DESMARCADA COMO USAVEL PARA ENVIAR, RECOLOCA
            }

            sk_buff_s* const skb = alloc_skb(64 + CNTL_TOTAL_SIZE, GFP_ATOMIC);

            if (skb) { src_port = p;
                
                //
                void* const pkt = memcpy(SKB_DATA(skb), pkt, CNTL_TOTAL_SIZE);

                //
                skb->transport_header = PTR(pkt) - SKB_HEAD(skb);
                skb->network_header   = PTR(pkt) - SKB_HEAD(skb);
                skb->mac_header       = PTR(pkt) - SKB_HEAD(skb);
                skb->data             = PTR(pkt);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
                skb->tail             = PTR(pkt) + CNTL_TOTAL_SIZE - SKB_HEAD(skb);
#else
                skb->tail             = PTR(pkt) + CNTL_TOTAL_SIZE;
#endif
                skb->mac_len          = ETH_HLEN;
                skb->len              = CNTL_TOTAL_SIZE;
                skb->ip_summed        = CHECKSUM_NONE;
                skb->dev              = phys;
                skb->protocol         = BE16(ETH_P_XLAN); // TODO: FIXME:

                // SEND IT
                dev_queue_xmit(skb);
            }
        } else {
            // TODO: DESMARCA ELA DA LISTA DE PHYS USAVEIS PARA ENVIAR

        }
    }

    // REINSTALL TIMER
    doTimer.expires = now + XLAN_TIMER_INTERVAL*HZ;
    add_timer(&doTimer);
}

static rx_handler_result_t xlan_in (sk_buff_s** const pskb) {
    
    if (xlan->operstate != IF_OPER_UP // netif_oper_up()
     && xlan->operstate != IF_OPER_UNKNOWN)
        goto drop;

    // WE ARE DOING
    sk_buff_s* const skb = *pskb;

    const void* const pkt = SKB_MAC(skb);

    if (src_vendor != BE32(VENDOR)) 
        goto drop;

    // NORMAL PACKET
    if (dst_vendor == BE32(VENDOR)
     || dst_host == HOST
     || dst_port == PHYS_PORT(skb->dev)) {
        skb->dev = xlan;
        return RX_HANDLER_ANOTHER;
    }

    // CONTROLE
    if (dst_vendor != 0xFFFFFFFFU // CONTROLS ARE BROADCAST
     || pkt_type != BE16(ETH_P_XLAN) // EXPLICITLY
     || skb->len != CNTL_TOTAL_SIZE) // COMPLETE
        goto drop;

    // MARCA ESTA INTERFACE AQUI COMO RECEBENDO
    // TODO: ATOMIC OR?
    atomic_set ( &seens[HOST], atomic_read(&seens[HOST]));
//|SEEN_MASK(PHYS_PORT(skb->dev))
    const uint rhost    = src_host;
    const uint rport    = src_port;
    const u64  rboot    = cntl_boot;
    const u64  rcounter = cntl_counter;
    const u32  rmask    = cntl_mask;

    if (rhost == HOST
     || rhost >= HOSTS_N
     || rport >= PORTS_N)
        goto drop;

    known_s* const known = &knowns[rhost];

    // IGNORA SE FOR UM PACOTE COM INFORMACOES DESATUALIZADAS
    if (known->counter >= rcounter) {
        if (known->boot == rboot)
            goto drop; // NOTE: A MUDANCA NO BOOT DELE PODE PASSAR DESPERCEBIDA SE O COUNTER FOR MAIOR
        known->boot    = rboot;
    }   known->counter = rcounter;

    // NOTE: AQUI PODERIA SALVAR A INFORMACAO rport, PARA CONFIRMAR que h:p X h:p estao funcionando
    // NOTA: ESTA PEGANDO O masks DELE, E COOCANDO NO NOSSO seens    
    atomic_set(&seens[rhost], rmask);
drop:
    kfree_skb(skb);

    return RX_HANDLER_CONSUMED;
}

quando for construir o pacote de controle GERAL, informa:
 this port sending it
 foreach (p, PORTS_N) {
    if (seen[HOST][p] >= now)
        manda dizendo que ela esta ativa
 }

static netdev_tx_t xlan_out (sk_buff_s* const skb, net_device_s* const xlan) {

    // ONLY LINEAR
    if (skb_linearize(skb))
        goto drop;

    void* const pkt = SKB_NETWORK(skb) - ETH_SIZE;

    // CONFIRMA ESPACO
    if (PTR(pkt) < SKB_HEAD(skb))
        goto drop;

    // NOTE: ASSUME QUE NÃO TEM IP OPTIONS
    const int v4 = skb->protocol == BE16(ETH_P_IP);

    // IDENTIFY DESTINATION
    const uint rhost = v4 ?
        ( (dst4_net & BE32(0xFFFFFF00U)) == BE32(NET4) ? dst4_host : GW ):
        (  dst6_net                      == BE64(NET6) ? dst6_host : GW );

    // É INVALIDO / ERA EXTERNO E NAO TEMOS GATEWAY / PARA SI MESMO
    if (rhost >= HOSTS_N
     || rhost == HOST)
        goto drop;

    // SELECT A PATH
    // OK: TCP | UDP | UDPLITE | SCTP | DCCP
    // FAIL: ICMP
    stream_s* const stream = &streams[rhost][__builtin_popcountll( (u64) ( v4
        ? proto4 * ports4 + addrs4
        : proto6 * ports6 * flow6
        + addrs6[0] + addrs6[1]        
        + addrs6[2] + addrs6[3]        
    ))];

    uint now   = jiffies;
    uint last  = stream->last;
    uint ports = stream->ports;
    
    // FORCA A MUDANCA DA PORTA ATUAL SE...
    if ((now - last) >= HZ/5) {
        // O ULTIMO ENVIADO JA DEU TEMPO DE SER PROCESSADO
        printk("XLAN: OUT: CHANGING FROM PORTS %u BECAUSE BURST IS COMPLETE\n",
            ports);
        ports++;
    } elif (0) {
        // TODO: OU SE O PACOTE É UM TCP-SYN, RST RETRANSMISSION ETC
        ports++;
    } else {
        // CONTINUA
    }
    
    foreach (c, (PORTS_N * PORTS_N * 2)) {
        ports %= PORTS_N * PORTS_N;

        const uint rport = ports / PORTS_N;
        const uint lport = ports % PORTS_N; // <- MUDA A PORTA LOCAL COM MAIS FREQUENCIA,
                // PARA QUE O SWITCH A DESCUBRA
                // E PORQUE NOS TEMOS MAIS CONTROLE SE ESSA NOSSA PORTA ESTA EXAUSTA OU NAO

        net_device_s* const phys = physs[lport];

        if (phys && (phys->flags & IFF_UP) == IFF_UP) { // IFF_RUNNING // IFF_LOWER_UP

            bucket_s* const bucket = &buckets[lport];

            uint bcan = bucket->can;
            
            if (bcan == 0) {
                if (c >= PORTS_N*PORTS_N) {
                    // SE CHEGAMOS AO SEGUNDO ROUND, É PORQUE ELE ESTA ZERADO
                    // SE ESTA CHEIO E NAO TEM OUTRO JEITO, LIBERA UM PEQUENO BURST
                    bcan = BUCKETS_BURST;
                    printk("XLAN: OUT: BURSTING! LPORT %u RHOST %u RPORT %u BCAN %u\n",
                        lport, rhost, rport, bcan);
                } elif (now >= bucket->last) {
                    const uint elapsed =
                        now >= bucket->last ?
                        now -  bucket->last : HZ;
                        bcan += (elapsed * BUCKETS_PER_SECOND)/HZ;
                    if (bcan > BUCKETS_PER_SECOND)
                        bcan = BUCKETS_PER_SECOND;
                    printk("XLAN: OUT: BUCKET! LPORT %u RHOST %u RPORT %u BCAN %u ELAPSED %u\n",
                        lport, rhost, rport, bcan, elapsed);
                } else { // SE DEU OVERFLOW NO JIFFIES CONSIDERA COMO 1 SEGUNDO
                    printk("XLAN: OUT: BUCKET TIME OVERFLOW\n");
                    bcan = BUCKETS_PER_SECOND;
                }
            }

            //
            if (bcan) {                
                bucket->can = bcan - 1;
                bucket->last = now;
                stream->ports = ports;
                stream->last  = now;                

                // FILL ETHERNET HEADER
                dst_vendor = BE32(VENDOR);
                dst_host   = rhost;
                dst_port   = rport;
                src_vendor = BE32(VENDOR);
                src_host   = HOST;
                src_port   = lport;
                pkt_type   = skb->protocol;

                // UPDATE SKB
                skb->data       = PTR(pkt);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
                skb->mac_header = PTR(pkt) - SKB_HEAD(skb);
#else
                skb->mac_header = PTR(pkt);
#endif
                skb->len        = SKB_TAIL(skb) - PTR(pkt);
                skb->mac_len    = ETH_HLEN;
                skb->dev        = phys;

                // -- THE FUNCTION CAN BE CALLED FROM AN INTERRUPT
                // -- WHEN CALLING THIS METHOD, INTERRUPTS MUST BE ENABLED
                // -- REGARDLESS OF THE RETURN VALUE, THE SKB IS CONSUMED
                dev_queue_xmit(skb);

                return NETDEV_TX_OK;
            }
        }

        ports++;
    }

drop:
    printk("XLAN: OUT: DROP: PROTOCOL 0x%04X SIZE %d\n",
        skb->len, BE16(skb->protocol));

    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int __f_cold xlan_down (net_device_s* const xlan) {

    printk("XLAN: %s DOWN\n", xlan->name);

    // TODO: DON'T EXECUTE TIMER

    return 0;
}

static int __f_cold xlan_up (net_device_s* const xlan) {

    printk("XLAN: %s UP\n", xlan->name);

    // TODO: REARM TIMER

    return 0;
}

static int __f_cold xlan_enslave (net_device_s* xlan, net_device_s* phys, struct netlink_ext_ack* extack) {

    const u8* const mac = PTR(phys->dev_addr);

    if (mac == NULL)
        return -EINVAL;

    const uint vendor = BE32(MAC_VENDOR(mac));
    const uint host   =      MAC_HOST(mac);
    const uint port   =      MAC_PORT(mac);

    printk("XLAN: ENSLAVE PHYS %s: VENDOR 0x%04X HOST %u PORT %u MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
        phys->name, vendor, host, port,
        mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5]);

    if (vendor != VENDOR)
        printk("XLAN: WARNING: WRONG VENDOR\n");

    if (host != HOST)
        printk("XLAN: WARNING: WRONG HOST\n");

    if (port >= PORTS_N) {
        printk("XLAN: FAILED: BAD PORT\n");
        return -EINVAL;
    }

    if (physs[port] == phys) {
        printk("XLAN: FAILED: PHYS ALREADY ATTACHED AS THIS PORT\n");
        return -EISCONN;
    }

    if (physs[port]) {
        printk("XLAN: FAILED: OTHER PHYS ATTACHED AS THIS PORT\n");
        return -EEXIST;
    }
    
    if (phys == xlan
     || phys->flags & IFF_LOOPBACK
     || phys->addr_len != ETH_ALEN) {
        printk("XLAN: FAILED: BAD PHYS (ITSELF / LOOPBACK / NOT ETHERNET)\n");
        return -EINVAL;
    }

    if (netdev_is_rx_handler_busy(phys)) {
        printk("XLAN: FAILED: PHYS ALREADY HAS A HANDLER\n");
        return -EBUSY;
    }

    if (netdev_rx_handler_register(phys, xlan_in, (uintpntr_t)p) != 0) {
        printk("XLAN: FAILED: FAILED TO ATTACH HANDLER\n");
        skb_free(skb);
        return -1;
    }

    // HOLD IT
    dev_hold(phys);
    
    // REGISTER IT
    physs[port] = phys;

    return 0;
}

static int __f_cold xlan_unslave (net_device_s* xlan, net_device_s* phys) {

    foreach (p, PORTS_N) {
        if (physs[p] == phys) {            
            physs[p] = NULL; // UNREGISTER
            netdev_rx_handler_unregister(phys); // UNHOOK
            dev_put(phys); // DROP
            printk("XLAN: DETACHED PHYS %s FROM PORT %u\n", phys->name, p);
            return 0;
        }
    }

    printk("XLAN: CANNOT DETACH PHYS %s FROM ANY PORT\n", phys->name);

    return -ENOTCONN;
}

static const net_device_ops_s xlanDevOps = {
    .ndo_init             = NULL,
    .ndo_open             = xlan_up,
    .ndo_stop             = xlan_down,
    .ndo_start_xmit       = xlan_out,
    .ndo_set_mac_address  = NULL,
    .ndo_add_slave        = xlan_enslave,
    .ndo_del_slave        = xlan_unslave,
    // TODO: SET MTU - NAO EH PARA SETAR AQUI E SIM NO ROUTE
};

static void __f_cold xlan_setup (net_device_s* const dev) {

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
    dev->mtu             = ETH_DATA_LEN;
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

    // CREATE THE VIRTUAL INTERFACE
    // MAKE IT VISIBLE IN THE SYSTEM
    printk("XLAN: INIT - VENDOR 0x%04x HOST %u 0x%02X GW %u 0x%02X NET4 0x%08X NET6 0x%016llX\n",
        VENDOR, HOST, HOST, GW, GW, NET4, (unsigned long long int)NET6);

    BUILD_BUG_ON(sizeof(atomic_t)  != sizeof(int));
    BUILD_BUG_ON(sizeof(atomic_t)  != sizeof(u32));
    BUILD_BUG_ON(sizeof(a32)       != sizeof(u32));
    BUILD_BUG_ON(sizeof(BITWORD_t  != sizeof(a32));
    BUILD_BUG_ON(sizeof(BITWORD_t) != sizeof(seens[0]));
    BUILD_BUG_ON(sizeof(BITWORD_t) != sizeof(masks[0]));

    clear(physs);
    clear(streams);
    clear(buckets);
    clear(seen);
    clear(masks);
    clear(knowns);

    //
    foreach (p, ALL_PORTS) {
        seen [p] = ATOMIC_INIT(0);
        masks[p] = ATOMIC_INIT(0);
    }

    // BOOT ID
    knowns[HOST].boot = jiffies; // TODO: FIXME:

    //
    if ((xlan = alloc_netdev(0, "xlan", NET_NAME_USER, xlan_setup)) == NULL) {
        printk("XLAN: FAILED\n");
        return -1;
    }

    //
    register_netdev(xlan);

    // INSTALL TIMER
    doTimer.expires = jiffies + XLAN_TIMER_DELAY;
    add_timer(&doTimer);

    return 0;
}

late_initcall(xlan_init);
