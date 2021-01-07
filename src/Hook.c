#include "Hook.h"

// Rule tables
int num_rules = 0;				   // number of rules
rule_t rule_table[MAX_RULES];	  // Our rule table
rule_t rule_table_temp[MAX_RULES]; // Temp rule table

static void correct_checksum(struct sk_buff *skb)
{
	struct tcphdr *tcp_header;
	struct iphdr *ip_header = ip_hdr(skb);
	int tcplen;
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

	skb->ip_summed = CHECKSUM_NONE;
	skb->csum_valid = 0;

	/* Linearize the skb */
	if (skb_linearize(skb) < 0)
	{
		/* Handle error */
	}
	ip_header = ip_hdr(skb);
	tcp_header = tcp_hdr(skb);

	/* Fix TCP header checksum */
	tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
	tcp_header->check = 0;
	tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));
}

// This function compares two ip addresses, after applying the given mask.
static int compare_ips(__be32 ipadd1, __be32 ipadd2, __be32 mask)
{
	if ((ipadd1 & mask) == (ipadd2 & mask))
	{
		return 1;
	}
	return 0;
}

// This function compares two ports, where only port2 can have special values.
// It returns 1 if and only if port1 is in the group of port2.
static int compare_ports(__be16 port1, __be16 port2)
{
	return (port2 == PORT_ANY) || ((port2 == PORT_ABOVE_1023) && (port1 > PORT_ABOVE_1023)) || (port1 == port2);
}

// This function checks if a tcp header is the header to a christmas packet
static int check_xmas_packet(struct tcphdr *tcph)
{
	return tcph->urg && tcph->psh && tcph->fin;
}

// This function compares two protocols, where only protocol2 can have special values.
// It returns 1 if and only if protocol1 is in the group of protocol2.
static int check_protocol(__u8 protocol1, __u8 protocol2)
{
	return ((protocol2 == PROT_ANY) || (protocol1 == protocol2));
}

// This function checks if protocol1 is one of the protocols we consider
// in this exercise.
static int check_protocol_in_family(__u8 protocol1)
{
	return (protocol1 == PROT_TCP) || (protocol1 == PROT_UDP) || (protocol1 == PROT_ICMP);
}

// Given two net devices, this function checks if the direction of the packet
// is in, out or neither. if its neither, we always accept. Notice that this also deals
// with the case of loopback packets.
static direction_t get_direction(char *in)
{
	if (strcmp(in, IN_NET_DEVICE_NAME) == 0)
	{
		return DIRECTION_OUT;
	}
	else if (strcmp(in, OUT_NET_DEVICE_NAME) == 0)
	{
		return DIRECTION_IN;
	}
	else
	{
		return DIRECTION_NON;
	}
}

// The local out hook. We assume that the firewall does not send any packets by itself.

unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct tcphdr *tcph;
	__be16 src_port, dst_port;
	struct iphdr *iph = ip_hdr(skb); // gets the ip header
	int action = NF_ACCEPT;
	reason_t temp;
	__be32 ipt;

	if (!iph)
	{
		return NF_ACCEPT;
	}

	if (!state)
	{
		return NF_ACCEPT;
	}

	if (iph->version != IP_VERSION) // checks the ip version. if its not 4, accepts.
	{
		return NF_ACCEPT;
	}

	if (iph->protocol != PROT_TCP)
	{
		return NF_ACCEPT;
	}

	if (!state->out)
	{
		return NF_ACCEPT;
	}

	tcph = tcp_hdr(skb); // tcp header
	if (!tcph)
	{
		return NF_ACCEPT;
	}
	src_port = tcph->source;
	dst_port = tcph->dest;

	// If the port is FTP or HTTP, changes the fields to fit the mitm
	if (dst_port == FTP_PORT || dst_port == HTTP_PORT || dst_port == SMTP_PORT || dst_port == NIFI_PORT)
	{
		printk("HERE1\n");
		ipt = get_client_ip(iph->saddr, iph->daddr, src_port, dst_port); //address of client;
		action = check_tcp_connection(tcph, iph, &temp);				 // Changes the rules table accordingly.
		iph->saddr = ipt;
		correct_checksum(skb);
	}
	// If the port is 800 or 210, changes the fields to fit the mitm
	else if (src_port == FAKE_FTP_PORT || src_port == FAKE_HTTP_PORT || src_port == FAKE_SMTP_PORT || src_port == FAKE_NIFI_PORT)
	{
		printk("HERE2\n");
		ipt = get_server_ip(iph->saddr, iph->daddr, src_port, dst_port); // address of server
		action = check_tcp_connection(tcph, iph, &temp);				 // Changes the rules table accordingly.
		if (src_port == FAKE_NIFI_PORT)
		{
			tcph->source = htons(ntohs(tcph->source) * 10);
		}
		else
		{
			tcph->source = htons(ntohs(tcph->source) / 10);
		}
		iph->saddr = ipt;
		correct_checksum(skb);
	}
	return action;
}

// This is the modules hook function. it drops/accepts  packets according to the rules.
unsigned int hook_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{

	int index = 0;
	struct iphdr *iph = ip_hdr(skb); // gets the ip header
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct timeval log_time;
	TCP_node *mitm_c = NULL;
	TCP_node *mitm_s = NULL;

	direction_t direction;
	ack_t ack = ACK_NO;

	log_row_t log_real; // log_row, used to log the packets.
	log_row_t *log;

	if (!iph)
	{
		return NF_ACCEPT;
	}

	if (!state)
	{
		return NF_ACCEPT;
	}

	if (iph->version != IP_VERSION) // checks the ip version. if its not 4, accepts.
	{
		return NF_ACCEPT;
	}

	if (!check_protocol_in_family(iph->protocol))
	{
		return NF_ACCEPT;
	}

	// Gets the packet direction. if its not in or out, accepts.
	if (!state->in)
	{
		return NF_ACCEPT;
	}
	direction = get_direction(state->in->name);
	if (direction == DIRECTION_NON)
	{
		return NF_ACCEPT;
	}

	// Check the packet protocol. if its not one of the protocols we check, accepts.
	log = &log_real;
	log->src_ip = iph->saddr; // Source and Destination ip addresses.
	log->dst_ip = iph->daddr;
	log->src_port = 0;
	log->dst_port = 0;
	log->protocol = iph->protocol;
	log->count = 1;
	do_gettimeofday(&log_time);		  // gets the time stamp.
	log->timestamp = log_time.tv_sec; // saves the timestamp to the log
	log->action = NF_DROP;
	log->reason = REASON_NO_MATCHING_RULE;

	if (iph->protocol == PROT_TCP)
	{
		tcph = tcp_hdr(skb); // tcp header
		if (!tcph)
		{
			return NF_ACCEPT;
		}

		log->src_port = tcph->source; // soure port from tcp header
		log->dst_port = tcph->dest;   // dest port from tcp header

		if (tcph->ack) // checks ack
		{
			ack = ACK_YES;
		}
		else
		{
			ack = ACK_NO;
		}

		if (check_xmas_packet(tcph)) // Checks if the packet is xmas packet. if it is,
		{							 // logs and drops it.
			log->action = NF_DROP;
			log->reason = REASON_XMAS_PACKET;
			add_log(log);
			return NF_DROP;
		}
	}
	else if (iph->protocol == PROT_UDP)
	{
		udph = udp_hdr(skb); // udp header and ports
		if (!udph)
		{
			return NF_ACCEPT;
		}

		log->src_port = udph->source;
		log->dst_port = udph->dest;
	}

	if (ack == ACK_NO)
	{
		for (index = 0; index < num_rules; index++) // Compares the packet to all of the rules
		{

			if (check_protocol(iph->protocol, rule_table[index].protocol)) // checks if protocol matches
			{
				// Checks if direction matches
				if ((rule_table[index].direction == DIRECTION_ANY) || (rule_table[index].direction == direction))
				{
					// Checks if ip addresses match
					if (compare_ips(rule_table[index].src_ip, log->src_ip, rule_table[index].src_prefix_mask) && compare_ips(rule_table[index].dst_ip, log->dst_ip, rule_table[index].dst_prefix_mask))
					{
						// Checks if ports match. (ignores ICMP)
						if ((iph->protocol == PROT_ICMP) || (compare_ports(log->src_port, rule_table[index].src_port) && compare_ports(log->dst_port, rule_table[index].dst_port)))
						{
							// Checks if ack match. (Ignores not TCP)
							if ((iph->protocol != PROT_TCP) || (ack & rule_table[index].ack))
							{

								// If everything matched, logs the packet and act according to the rule.
								log->action = rule_table[index].action;
								log->reason = index;
								break;
							}
						}
					}
				}
			}
		}
		if ((log->action == NF_ACCEPT) && (log->protocol == PROT_TCP))
		{   // If we accepted the packet, we build a new entry for it. If its an HTTP or FTP packet,
			// we add two new entrys, for the MITM too.
			if (log->src_port == FTP_PORT || log->src_port == HTTP_PORT || log->dst_port == FTP_PORT || log->dst_port == HTTP_PORT || log->src_port == SMTP_PORT || log->src_port == NIFI_PORT || log->dst_port == SMTP_PORT || log->dst_port == NIFI_PORT)
			{
				add_tcp_connection(tcph, iph, &mitm_c, &mitm_s, log->reason);
				iph->daddr = state->in->ip_ptr->ifa_list->ifa_address;
				if (direction == DIRECTION_IN)
				{
					if (log->src_port == NIFI_PORT || log->dst_port == NIFI_PORT)
					{
						tcph->dest = htons(ntohs(tcph->dest) / 10);
					}
					else
					{
						tcph->dest = htons(ntohs(tcph->dest) * 10);
					}
				}
			}

			add_tcp_connection(tcph, iph, &mitm_c, &mitm_s, log->reason);
			tcph->dest = log->dst_port;
		}
	}
	if (log->protocol == PROT_TCP)
	{ //If the packet is HTTP or FTP, changes the fields.
		if (log->src_port == FTP_PORT || log->src_port == HTTP_PORT || log->dst_port == FTP_PORT || log->dst_port == HTTP_PORT || log->src_port == SMTP_PORT || log->src_port == NIFI_PORT || log->dst_port == SMTP_PORT || log->dst_port == NIFI_PORT)
		{
			iph->daddr = state->in->ip_ptr->ifa_list->ifa_address;
			if (direction == DIRECTION_IN)
			{
				if (log->src_port == NIFI_PORT || log->dst_port == NIFI_PORT)
				{
					tcph->dest = htons(ntohs(tcph->dest) / 10);
				}
				else
				{
					tcph->dest = htons(ntohs(tcph->dest) * 10);
				}
			}
			else
			{
				log->dst_port = get_client_port(iph->saddr, iph->daddr, tcph->source, tcph->dest);
			}

			correct_checksum(skb);
		}
		// Checks if the packet fits the connection table. If it does, update the connection and accepts, else drops.
		log->action = check_tcp_connection(tcph, iph, &log->reason);
	}

	// logs the packet and drop with reason "no rule matched".
	add_log(log);
	return log->action;
}
