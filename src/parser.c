
#include "parser.h"

// We want to aviod dynamic allocation as much as possible, so we declare this static variables
char rule_name[20]; 
__u8 direction;
__u32 src_ip;
__u8 src_prefix_size; 
__u32 dst_ip;
__u8 dst_prefix_size; 
__u16 src_port;		  
__u16 dst_port;		  
__u8 protocol;		  
__u8 ack;			  
__u8 action;

// A function that checks if a number is a valid protocol
static int is_protocol(__u8 protocol)
{
	if (protocol == PROT_ICMP || protocol == PROT_TCP || protocol == PROT_UDP || protocol == PROT_OTHER || protocol == PROT_ANY)
	{
		return 1;
	}
	return 0;
}

// This function checks if all the values fileld in the static variables are legal for
// the rule table, and if so fills them at the given row.
static int validate_and_fill_rule(rule_t *rule_table, int index)
{
	// Checks if all the values are legal
	if ((src_prefix_size > 32) || (dst_prefix_size > 32) || !is_protocol(protocol) || (src_prefix_size < 0) || (dst_prefix_size < 0))
	{
		return -1;
	}
	if ((direction != DIRECTION_IN) && (direction != DIRECTION_OUT) && (direction != DIRECTION_ANY))
	{
		return -1;
	}
	if ((ack != ACK_YES) && (ack != ACK_NO) && (ack != ACK_ANY))
	{
		return -1;
	}
	if ((action != NF_DROP) && (action != NF_ACCEPT))
	{
		return -1;
	}
	
	// Fills the rule table with the static variables

	memcpy(rule_table[index].rule_name, rule_name, strlen(rule_name));
	rule_table[index].direction = direction;

	rule_table[index].src_ip = htonl(src_ip);
	if (src_prefix_size == 0)
	{
		rule_table[index].src_prefix_mask = 0;
	}
	else
	{
		rule_table[index].src_prefix_mask = htonl(((~0) << (32 - src_prefix_size)));
	}
	rule_table[index].src_prefix_size = src_prefix_size;

	rule_table[index].dst_ip = htonl(dst_ip);
	if (dst_prefix_size == 0)
	{
		rule_table[index].dst_prefix_mask = 0;
	}
	else
	{
		rule_table[index].dst_prefix_mask = htonl(((~0) << (32 - dst_prefix_size)));
	}
	rule_table[index].dst_prefix_size = dst_prefix_size;

	rule_table[index].src_port = htons(src_port);
	rule_table[index].dst_port = htons(dst_port);
	rule_table[index].protocol = protocol;

	rule_table[index].ack = ack;
	rule_table[index].action = action;

	return 0;
}

// Given a buffer, this function reads a rule table from this buffer, where we read at most
// MAX_RULE_SIZE bytes from the buffer each time to prevent allocating to much
// dynamic memory and to be able to verify the users input.
int get_rule_table(rule_t *rule_table, const char *buf, size_t count)
{

	size_t read;
	size_t bytes_left = count;
	char *str = (char *)kcalloc(1, MAX_RULE_SIZE + 2, GFP_KERNEL);
	char *line;
	int index = 0;

	str[MAX_RULE_SIZE] = '\0';

	while (bytes_left > 0)
	{
		if (index >= 50) // There are at most 50 rules.
		{
			kfree(str);
			return -1; 
		}
		if (bytes_left > MAX_RULE_SIZE) // Calculating the number of bytes to read next
		{
			read = MAX_RULE_SIZE;
		}
		else
		{
			read = bytes_left;
		}
		memcpy(str, buf + count - bytes_left, read); // Reads from the buffer to our str
		str[read] = '\0'; // We want to deal with the case where the user didnt end his
		// input with \0.
		line = strchr(str, '\n');
		if (line)
		{
			line[1] = '\0';
			// We check if exists a legal rules table line in the str.
			if (sscanf(str, "%19s %hhu %u %hhu %u %hhu %hhu %hu %hu %hhu %hhu\n", rule_name, &direction, &src_ip, &src_prefix_size, &dst_ip, &dst_prefix_size, &protocol, &src_port, &dst_port, &ack, &action) == 11)
			{

				if (validate_and_fill_rule(rule_table, index) < 0) // We check the values and fill the table
				{
					kfree(str);
					return -1;
				}

				index++;
			}
			else
			{
				kfree(str);
				return -1;
			}
		}
		else
		{ // Reading the last line of the input
			str[read] = '\n';
			str[read+1] = '\0';
			if (sscanf(str, "%20s %hhu %u %hhu %u %hhu %hhu %hu %hu %hhu %hhu", rule_name, &direction, &src_ip, &src_prefix_size, &dst_ip, &dst_prefix_size, &protocol, &src_port, &dst_port, &ack, &action) == 11)
			{

				if (validate_and_fill_rule(rule_table, index) < 0)
				{
					kfree(str);
					return -1;
				}
				bytes_left++;
				index++;

			}
			else
			{
				kfree(str);
				return -1;
			}
		}
		bytes_left = bytes_left - strlen(str);
	}

	kfree(str);
	return index; // Returning the new amount of rules
}

// This function format the rule table given to it and puts it in the buffer.
int send_rule_table(rule_t *rule_table, char *buf, int num_rules)
{
	unsigned int index;
	unsigned int num_bytes_w = 0;
	char *str = (char *)kcalloc(1, MAX_RULE_SIZE + 1, GFP_KERNEL);

	for (index = 0; index < num_rules; index++) // We each time read a line and send it to the buffer
	{
		scnprintf(str, MAX_RULE_SIZE + 1, "%s %hhu %u %hhu %u %hhu %hhu %hu %hu %hhu %hhu\n", rule_table[index].rule_name, rule_table[index].direction, ntohl(rule_table[index].src_ip), rule_table[index].src_prefix_size, ntohl(rule_table[index].dst_ip), rule_table[index].dst_prefix_size, rule_table[index].protocol, ntohs(rule_table[index].src_port), ntohs(rule_table[index].dst_port), rule_table[index].ack, rule_table[index].action);
		memcpy(buf + num_bytes_w, str, strlen(str));
		num_bytes_w = num_bytes_w + strlen(str);
	}

	buf[num_bytes_w] = '\0';
	return num_bytes_w;
}
