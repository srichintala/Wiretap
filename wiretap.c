#include<stdio.h>
#include<time.h>
#include<pcap.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<linux/if_ether.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ether.h>
#include<netinet/in.h>
#include<netinet/ip_icmp.h>

#define FILE_NAME_SIZE 1024	   //file name size
#define NUMBER_OF_PROTOID 50   //number of protocol ids
#define IP_ALEN 4              //length of ip addresses
#define IP_HLEN 20			   //length of ip headers
#define NUM_TPROTO 30          //number of tcp protocols
#define MIN_TCP_HLEN 20        //minimum tcp headers
#define NUM_TCP_OPTIONS 40      //number of maximum tcp options considered
#define Mul_factor 4            //multiplying factor for data offset and ip header length
#define BUF_SIZE 1024
#define MAX_IP_ADDR_STING 15	//xxx.xxx.xxx.xxx

struct Option
{
	u_int8_t kind;
	u_int8_t length;
};

static int pcount=0;
time_t start = 0;
time_t end = 0;
int min = 0;
int max = 0;
double sum = 0;
int iterator =0;

u_char **eh_dest;
int *eh_d;
int en_dest = 0;
u_char **eh_source;
int *eh_s;
int en_source = 0;

int *TprotoIDs;
int *TprotoOcc;
int n_Tproto = 0;

int *protoIDs;
int *protoOcc;
int n_proto = 0;

struct in_addr **ip_s;
struct in_addr **ip_d;
int n_ip_s = 0;
int n_ip_d = 0;
int *ip_s_cnt;
int *ip_d_cnt;

struct ether_arp **a;
int n_arp = 0;
int *a_cnt;

int *tsport;
int *ts_p;
u_int16_t tsports = 0;

u_int16_t *tdport;
int *td_p;
u_int16_t tdports = 0;

u_int16_t *usport;
int *us_p;
u_int16_t usports = 0;

u_int16_t *udport;
int *ud_p;
u_int16_t udports = 0;

int ack = 0;
int urg = 0;
int fin = 0;
int psh = 0;
int rst = 0;
int syn = 0;

u_int8_t *icmp_type;
int *icmp_t;
int icmpt = 0;

u_int8_t *icmp_code;
int *icmp_c;
int icmpc = 0;

struct Option opt[NUM_TCP_OPTIONS];
int opt_cnt[NUM_TCP_OPTIONS][2];

void usage(FILE * file)
{
  if(file == NULL)
  {
    file = stdout;
  }
	fprintf(file,
		  "wiretap [OPTIONS] [file]\n"
          "--help         \t Print this help screen\n"
		  "--open <capture file to open>\n"	); 
}

void parse_args(int argc, char *argv[], char *fname)
{
	if(argc<2||argc>3)
	{
		usage(stdout);
		exit(1);
	}
	if(strcmp(argv[1],"--help")==0)
	{
		usage(stdout);
		exit(1);
	}
	
	if(strcmp(argv[1],"--open")!=0)
	{
		usage(stdout);
		exit(1);		
	}
	if(argc!=3)
	{
		usage(stdout);
		exit(0);
	}
	if(strstr(argv[2], ".pcap")==NULL)
	{
		fprintf(stderr, "ERROR: Require .pcap file\n");
		usage(stderr);
		exit(1);
	}
	strcpy(fname, argv[2]);	
}

void callback(u_char* args, const struct pcap_pkthdr *header, const u_char *packet)
{
	if(pcount == 0)
	{
		start = header->ts.tv_sec;
		min = header->caplen;
	}
	if(min>header->caplen)
	{
		min = header->caplen;
	}
	if(max<header->caplen)
	{
		max = header->caplen;
	}
	sum = sum + header->caplen;
	end = header->ts.tv_sec;	
	pcount++;
}

void sniffPackets(u_char* args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int i=0,j=0;
	struct ethhdr *e = (struct ethhdr *)(packet);
	for(j=0;j<iterator;j++)
	{
		if(bcmp((struct ether_addr *)e->h_source,(struct ether_addr *)eh_source[j],sizeof(struct ether_addr))==0)
		{	
			eh_s[j] = eh_s[j] + 1;
			break;
		}
	}	
	if(j == iterator)
	{
		bcopy((struct ether_addr *)((e->h_source)),(struct ether_addr *)eh_source[en_source],sizeof(struct ether_addr));		
		en_source++;
	}
	for(i=0;i<iterator;i++)
	{
		if(bcmp((struct ether_addr *)e->h_dest,(struct ether_addr *)eh_dest[i],sizeof(struct ether_addr))==0)
		{	
			eh_d[i] = eh_d[i] + 1;
			break;
		}
	}	
	if(i == iterator)
	{
		bcopy((struct ether_addr *)((e->h_dest)),(struct ether_addr *)eh_dest[en_dest],sizeof(struct ether_addr));		
		en_dest++;
	}
	int proto = 0,k=0;
	proto = ntohs(e->h_proto);
	for(k=0;k<iterator;k++)
	{
		if(proto == protoIDs[k])
		{
			protoOcc[k] = protoOcc[k] + 1;
			break;
		}
	}
	if(k == iterator)
	{
		protoIDs[n_proto] = proto;
		n_proto++;
	} 
	int p =0, m=0, n=0;
	
	if(proto == ETH_P_ARP) 
	{
		struct ether_arp *arp = (struct ether_arp*)(packet + ETH_HLEN);
		for(n=0;n<iterator;n++)
		{
			if(bcmp((struct ether_addr *)(arp->arp_sha), (struct ether_addr *)(a[n]->arp_sha), sizeof(struct ether_addr))==0)
			{
				if(bcmp(arp->arp_spa, a[n]->arp_spa, sizeof(arp->arp_spa))==0)
				{
					a_cnt[n] = a_cnt[n] + 1;
					break;
				}
			}
		}
		if(n == iterator)
		{
			bcopy((struct ether_addr *)(arp->arp_sha),(struct ether_addr *)(a[n_arp]->arp_sha),sizeof(struct ether_addr));
			bcopy(arp->arp_spa, a[n_arp]->arp_spa, sizeof(arp->arp_spa));
			n_arp++;
		}
		iterator++;
		return;
	}
	int ipProto = 0;
	if(proto == ETH_P_IP)
	{
		struct ip *ip_hdr = (struct ip *)(packet + ETH_HLEN);
		for(p=0;p<iterator;p++)
		{
			if(bcmp(&(ip_hdr->ip_src), ip_s[p], sizeof(struct in_addr))==0)
			{
				ip_s_cnt[p] = ip_s_cnt[p] + 1;
				break;
			}
		}
		if(p == iterator)
		{
			bcopy( &(ip_hdr->ip_src), ip_s[n_ip_s], sizeof(struct in_addr));
			n_ip_s++;
		}
		for(m=0;m<iterator;m++)
		{
			if(bcmp(&(ip_hdr->ip_dst), ip_d[m], sizeof(struct in_addr))==0)
			{
				ip_d_cnt[m] = ip_d_cnt[m] + 1;
				break;
			}
		}
		if(m == iterator)
		{
			bcopy( &(ip_hdr->ip_dst), ip_d[n_ip_d], sizeof(struct in_addr));
			n_ip_d++;
		}
		
		ipProto = ip_hdr->ip_p;
		for(n = 0;n<n_Tproto;n++)
		{
			if(ipProto == TprotoIDs[n])
			{
				TprotoOcc[n] = TprotoOcc[n] + 1;
				break;
			}
		}
		if(n == n_Tproto)
		{
			TprotoIDs[n] = ipProto;
			n_Tproto++;
		}
		if(ipProto == IPPROTO_TCP)
		{
			struct tcphdr *tcp = (struct tcphdr *)(packet + ETH_HLEN + (ip_hdr->ip_hl)*Mul_factor);
			int x =0;
			for(x=0;x<iterator;x++)
			{
				if(tsport[x] == tcp->source)
				{
					ts_p[x]++;
					break;
				}
			}
			if(x == iterator)
			{
				tsport[tsports] = tcp->source;
				tsports++;
			}
			for(x=0;x<tdports;x++)
			{
				if(tdport[x] == tcp->dest)
				{
					td_p[x]++;
					break;
				}
			}
			if(x == tdports)
			{
				tdport[x] = tcp->dest;
				tdports++;
			}
			//tcp flags
			if(tcp->syn)
				syn++;
			if(tcp->fin)
				fin++;
			if(tcp->psh)
				psh++;
			if(tcp->ack)
				ack++;
			if(tcp->rst)
				rst++;
			if(tcp->urg)
				urg++;
			//tcp options
			
			if((tcp->doff)*Mul_factor > MIN_TCP_HLEN)
			{
				int temp = MIN_TCP_HLEN;
				struct Option *OPTION = (struct Option *)(packet + ETH_HLEN + (ip_hdr->ip_hl)*Mul_factor + MIN_TCP_HLEN);
				int flag = 0;
				while(temp<tcp->doff*Mul_factor)
				{
					if(OPTION->kind == TCPOPT_EOL )
					{
						temp++;
						opt_cnt[OPTION->kind][0] = OPTION->kind;
						opt_cnt[OPTION->kind][1]++; 
						break;
					}
					if(OPTION->kind == TCPOPT_NOP )
					{
						if(flag == 0)
						{
							flag = 1;
							opt_cnt[OPTION->kind][0] = OPTION->kind;
							opt_cnt[OPTION->kind][1]++; 
						}
						temp++;
						OPTION = (struct Option *)(packet + ETH_HLEN + (ip_hdr->ip_hl)*Mul_factor + temp);
					}
					else
					{
						opt_cnt[OPTION->kind][0] = OPTION->kind;
						opt_cnt[OPTION->kind][1]++;
						temp+=OPTION->length;
						OPTION = (struct Option *)(packet + ETH_HLEN + (ip_hdr->ip_hl)*Mul_factor + temp);
					}
				}
			}
		}
		else if(ipProto == IPPROTO_UDP)
		{
			struct udphdr *udp = (struct udphdr *)(packet + ETH_HLEN + ip_hdr->ip_hl*Mul_factor);
			int x =0;
			for(x=0;x<usports;x++)
			{
				if(usport[x] == udp->source)
				{
					us_p[x]++;
					break;
				}
			}
			if(x == usports)
			{
				usport[x] = udp->source;
				usports++;
			}
			for(x=0;x<udports;x++)
			{
				if(udport[x] == udp->dest)
				{
					ud_p[x]++;
					break;
				}
			}
			if(x == udports)
			{
				udport[x] = udp->dest;
				udports++;
			}
		}
		else if(ipProto == IPPROTO_ICMP)
		{
			struct icmp *icmp= (struct icmp *)(packet+ETH_HLEN+ ip_hdr->ip_hl*Mul_factor);
			int k=0;
			for(k=0; k<icmpt ;k++)
			{
				if(icmp_type[k] == icmp->icmp_type)
				{
					icmp_t[k]++;
					break;
				}
			}
			if(k == icmpt)
			{
				icmp_type[k] = icmp->icmp_type;
				icmpt++;
			}
			for(k=0; k<icmpc ;k++)
			{
				if(icmp_code[k] == icmp->icmp_code)
				{
					icmp_c[k]++;
					break;
				}
			}
			if(k == icmpc)
			{
				icmp_code[k] = icmp->icmp_code;
				icmpc++;
			}
		}
		else 
		{
			iterator++;
			return;
		}
	}
	iterator++;
}

int main(int argc, char *argv[])
{
	char fname[FILE_NAME_SIZE];
	int cnt = -1;
	char errbuf[PCAP_ERRBUF_SIZE];
	char timeBuf[BUF_SIZE];
	struct tm *t;
	double avg = 0;
	int i=0, j=0, flag = 0;
	pcap_t *handle;
	parse_args(argc, argv, fname);
	FILE *fp;
	fp = fopen("statistics.txt","w");
	if(fp==NULL)
	{
		printf("\n file could not be created");
		return 0;
	}	
	handle = pcap_open_offline(fname,errbuf);
	if(handle == NULL)
	{
		fprintf(stdout,"\n %s",errbuf);
		return 0;
	}
	if(pcap_datalink(handle)!=DLT_EN10MB)
	{
		fprintf(stdout,"\n not ethernet");
		exit(1);
	}		
	pcap_loop(handle, cnt, callback, NULL);
	pcap_close(handle);
	t = localtime(&start);
	strftime(timeBuf,sizeof(timeBuf),"%F %T %Z",t);
	avg = sum/pcount;
	fprintf(fp,"\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n\n");
	fprintf(fp,"=========Packet capture summary=========");
	fprintf(fp,"\nCapture start date: 	%s",timeBuf);
	fprintf(fp,"\nCapture duration:    	%d seconds",end - start);
	fprintf(fp,"\nPackets in capture: 	%d",pcount);
	fprintf(fp,"\nMinimum packet size: 	%d",min);
	fprintf(fp,"\nMaximum packet size: 	%d",max);
	fprintf(fp,"\nAverage packet size: 	%0.2lf",avg);
	
	handle = pcap_open_offline(fname,errbuf);
	if(handle == NULL)
	{
		fprintf(stdout,"\n %s",errbuf);
	}
	
	eh_d = malloc(sizeof(int)*pcount);
	eh_s = malloc(sizeof(int)*pcount);
	
	protoIDs = malloc(sizeof(int)*NUMBER_OF_PROTOID);
	protoOcc = malloc(sizeof(int)*NUMBER_OF_PROTOID);
	
	TprotoIDs = malloc(sizeof(int)*NUM_TPROTO);
	TprotoOcc = malloc(sizeof(int)*NUM_TPROTO);
	
	ip_d_cnt = malloc(sizeof(int)*pcount);
	ip_s_cnt = malloc(sizeof(int)*pcount);
	
	eh_dest = (u_char**)malloc(sizeof(u_char *)*pcount);
	eh_source = (u_char **)malloc(sizeof(u_char *)*pcount);
	
	ip_s = (struct in_addr **)malloc(sizeof(struct in_addr *)*pcount);
	ip_d = (struct in_addr **)malloc(sizeof(struct in_addr *)*pcount);
	
	a = (struct ether_arp **)malloc(sizeof(struct ether_arp *)*pcount);
	a_cnt = malloc(sizeof(int)*pcount);
	
	ts_p = (int *)malloc(sizeof(int)*pcount);
	td_p = (int *)malloc(sizeof(int)*pcount);
	
	tsport = (int *)malloc(sizeof(int)*pcount);
	tdport = (u_int16_t *)malloc(sizeof(u_int16_t)*pcount);
	
	us_p = (int *)malloc(sizeof(int)*pcount);
	ud_p = (int *)malloc(sizeof(int)*pcount);
	
	usport = (u_int16_t *)malloc(sizeof(u_int16_t)*pcount);
	udport = (u_int16_t *)malloc(sizeof(u_int16_t)*pcount);

	icmp_type = (u_int8_t *)malloc(sizeof(u_int8_t)*pcount);
	icmp_code = (u_int8_t *)malloc(sizeof(u_int8_t)*pcount);
	
	icmp_t = (int *)malloc(sizeof(int)*pcount);
	icmp_c = (int *)malloc(sizeof(int)*pcount);
	
	for(i=0;i<pcount;i++)
	{
		eh_dest[i] = (u_char*)malloc(sizeof(u_char)*ETH_ALEN);
		eh_source[i] = (u_char*)malloc(sizeof(u_char)*ETH_ALEN);
		ip_d[i] = (struct in_addr *)malloc(MAX_IP_ADDR_STING);
		ip_s[i] = (struct in_addr *)malloc(MAX_IP_ADDR_STING);
		a[i] = (struct ether_arp *)malloc(sizeof(struct ether_arp));
		memset(eh_source[i],0,ETH_ALEN);
		memset(eh_dest[i],0,ETH_ALEN);
		memset(ip_d[i],0,sizeof(ip_d[i]));
		memset(ip_s[i],0,sizeof(ip_s[i]));
		memset(a[i],0,sizeof(a[i]));
		memset(&eh_d[i],0,sizeof(eh_d[i]));
		memset(&eh_s[i],0,sizeof(eh_s[i]));
		memset(&ip_d_cnt[i],0,sizeof(ip_d_cnt[i]));
		memset(&ip_s_cnt[i],0,sizeof(ip_s_cnt[i]));
		memset(&a_cnt[i],0,sizeof(a_cnt[i]));
		memset(&tsport[i],0,sizeof(tsport[i]));
		memset(&tdport[i],0,sizeof(tdport[i]));
		memset(&ts_p[i],0,sizeof(ts_p[i]));
		memset(&td_p[i],0,sizeof(td_p[i]));
		memset(&usport[i],0,sizeof(usport[i]));
		memset(&udport[i],0,sizeof(udport[i]));
		memset(&us_p[i],0,sizeof(us_p[i]));
		memset(&ud_p[i],0,sizeof(ud_p[i]));
		memset(&icmp_t[i],0,sizeof(icmp_t[i]));
		memset(&icmp_c[i],0,sizeof(icmp_c[i]));
		memset(&icmp_type[i],0,sizeof(icmp_type[i]));
		memset(&icmp_code[i],0,sizeof(icmp_code[i]));
	}
	for(i=0;i<NUMBER_OF_PROTOID;i++)
	{
		memset(&protoIDs[i],0,sizeof(protoIDs[i]));
		memset(&protoOcc[i],0,sizeof(protoOcc[i]));
	}
	for(i=0;i<NUM_TPROTO;i++)
	{
		memset(&TprotoIDs[i],0,sizeof(TprotoIDs[i]));
		memset(&TprotoOcc[i],0,sizeof(TprotoOcc[i]));
	}
	pcap_loop(handle, cnt, sniffPackets, NULL);
	
	fprintf(fp,"\n\n=========Link layer=========\n\n");
	fprintf(fp,"---------Source ethernet addresses---------\n\n");
	if(en_source!=0)
	{
		for(i=0;i<en_source;i++)
		{
			for(j=0;j<ETH_ALEN;j++)
			fprintf(fp,"%02x:",eh_source[i][j]);
			fprintf(fp,"%02x                      %d\n",eh_source[i][j],eh_s[i]+1);
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
	fprintf(fp,"\n\n---------Destination ethernet addresses---------\n\n");
	if(en_dest!=0)
	{
		for(i=0;i<en_dest;i++)
		{
			for(j=0;j<ETH_ALEN;j++)
			fprintf(fp,"%02x:",eh_dest[i][j]);
			fprintf(fp,"%02x                      %d\n",eh_dest[i][j],eh_d[i]+1);
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
	fprintf(fp,"\n\n=========Network layer=========\n\n");
	fprintf(fp,"\n\n---------Network layer protocols---------\n\n");
	if(n_proto!=0)
	{
		for(i=0;i<n_proto;i++)
		{
			if(protoIDs[i]==ETH_P_IP)
				fprintf(fp,"\n%-40s%d","IP",protoOcc[i]+1);
			else if(protoIDs[i]==ETH_P_ARP)
				fprintf(fp,"\n%-40s%d","ARP",protoOcc[i]+1);
			else
			{
				char str[BUF_SIZE];
				sprintf(str,"%d(0x%x)",protoIDs[i],protoIDs[i]);
				fprintf(fp,"\n%-40s%d",str,protoOcc[i]+1);
			}
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
	
	fprintf(fp,"\n\n---------Source IP addresses---------\n\n");
	if(n_ip_s!=0)
	{
		for(i=0;i<n_ip_s;i++)
		{
			fprintf(fp,"\n%-40s%d",(char *)inet_ntoa(*ip_s[i]),ip_s_cnt[i]+1);
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
		
	fprintf(fp,"\n\n---------Destination IP addresses---------\n\n");
	
	for(i=0;i<n_ip_d;i++)
	{
		fprintf(fp,"\n%-40s%d",(char *)inet_ntoa(*ip_d[i]),ip_d_cnt[i]+1);
	}
	
	fprintf(fp,"\n\n---------Unique ARP participants---------\n\n");
	if(n_arp!=0)
	{
		for(i=0;i<n_arp;i++)
		{
			for(j=0;j<ETH_ALEN-1;j++)
			{
				fprintf(fp,"%02x:",a[i]->arp_sha[j]);
			}
			fprintf(fp,"%02x / ",a[i]->arp_sha[j]);
			fprintf(fp,"%-15s   %d\n",inet_ntoa(*((struct in_addr *)(a[i]->arp_spa))),a_cnt[i]+1);
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
		
	fprintf(fp,"\n\n=========Transport layer=========\n\n");
	fprintf(fp,"---------Transport layer protocols---------\n\n");
	
	if(n_Tproto!=0)
	{
		for(i=0;i<n_Tproto;i++)
		{
			if(TprotoIDs[i] == IPPROTO_UDP)
			fprintf(fp,"\n%-40s%d","UDP",TprotoOcc[i]+1);
			else if(TprotoIDs[i] == IPPROTO_ICMP)
			fprintf(fp,"\n%-40s%d","ICMP",TprotoOcc[i]+1);
			else if(TprotoIDs[i] == IPPROTO_TCP)
			fprintf(fp,"\n%-40s%d","TCP",TprotoOcc[i]+1);
			else
			fprintf(fp,"\n%-40d%d",TprotoIDs[i],TprotoOcc[i]+1);
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
		
	fprintf(fp,"\n\n=========Transport layer: TCP=========\n\n");
	fprintf(fp,"---------Source TCP ports---------\n\n");
	
	if(tsports!=0)
	{
		for(i=0;i<tsports;i++)
		{
			fprintf(fp,"\n%-40d%d",ntohs(tsport[i]),ts_p[i]+1);
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
		
	fprintf(fp,"\n\n---------Destination TCP ports---------\n\n");
	
	if(tdports!=0)
	{
		for(i=0;i<tdports;i++)
		{
			fprintf(fp,"\n%-40d%d",ntohs(tdport[i]),td_p[i]+1);
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
	
	if(tsports!=0 || tdports!=0)
	{
		fprintf(fp,"\n\n---------TCP Flags---------\n\n");
		fprintf(fp,"\n%-40s%d","ACK",ack);
		fprintf(fp,"\n%-40s%d","SYN",syn);
		fprintf(fp,"\n%-40s%d","FIN",fin);
		fprintf(fp,"\n%-40s%d","PSH",psh);
		fprintf(fp,"\n%-40s%d","RST",rst);
		fprintf(fp,"\n%-40s%d","URG",urg);
	}
	else
		fprintf(fp,"\n (no results)\n");
		
	fprintf(fp,"\n\n---------TCP options---------\n");
	
	for(i=0;i<NUM_TCP_OPTIONS;i++)
	{
		if(opt_cnt[i][1]!=0)
		{
			flag = 1;
			fprintf(fp,"\n%d (0x%x)                                %d",opt_cnt[i][0],opt_cnt[i][0],opt_cnt[i][1]);
		}
	}
	if(flag!=1)
		fprintf(fp,"\n (no results)\n");
		
	fprintf(fp,"\n\n=========Transport layer: UDP=========\n\n");
	fprintf(fp,"---------Source UDP ports---------\n\n");
	
	if(usports!=0)
	{
		for(i=0;i<usports;i++)
		{
			fprintf(fp,"\n%-40d%d",ntohs(usport[i]),us_p[i]+1);
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
		
	fprintf(fp,"\n\n---------Destination UDP ports---------\n\n");
	
	if(udports!=0)
	{
		for(i=0;i<udports;i++)
		{
			fprintf(fp,"\n%-40d%d",ntohs(udport[i]),ud_p[i]+1);
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
		
	fprintf(fp, "\n\n=========Transport layer: ICMP=========\n\n");
	fprintf(fp,"\n---------ICMP types---------\n");
	if(icmpt!=0)
	{
		for(i=0;i<icmpt;i++)
		{	
			fprintf(fp,"\n%-40d%d",icmp_type[i],icmp_t[i]+1);
		}
	}
	else
		fprintf(fp,"\n (no results)\n");
		
	fprintf(fp,"\n---------ICMP codes---------\n");
	if(icmpc!=0)
	{
		for(i=0;i<icmpc;i++)
		{	
			fprintf(fp,"\n%-40d%d",icmp_code[i],icmp_c[i]+1);
		}
	}
	else
	{
		fprintf(fp,"\n (no results)\n");
	}
	fprintf(fp,"\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	pcap_close(handle);
	fclose(fp);
	
	FILE *f;
	f = fopen("statistics.txt","r");
	if(f==NULL)
	{
		printf("\n does not exist");
		return 0;
	}
	char ch;
	while(1)
	{
		ch = fgetc(f);
		if(ch==EOF)
		{
			break;
		}
		putc(ch,stdout);
	}
	fclose(f);
	printf("\n%s","Output stored in statistics.txt");
	for(i=0;i<pcount;i++)
	{
		free(*(eh_dest+i));
		free(*(eh_source+i));
		free(*(ip_d+i));
		free(*(ip_s+i));
		free(*(a+i));
	}	
		
	free(eh_dest);
	free(eh_source);
	free(ip_d);
	free(ip_s);
	free(a);
	free(eh_d);
	free(eh_s);
	free(TprotoIDs);
	free(TprotoOcc);
	free(protoIDs);
	free(protoOcc);
	free(ip_s_cnt);
	free(ip_d_cnt);
	free(a_cnt);
	free(tsport);
	free(ts_p);
	free(tdport);
	free(td_p);
	free(usport);
	free(us_p);
	free(udport);
	free(ud_p);
	free(icmp_type);
	free(icmp_t);
	free(icmp_code);
	free(icmp_c);
}