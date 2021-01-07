#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include "fw.h"
#include "parser.h"
#include "Hook.h"

MODULE_LICENSE("GPL");

static int major_number;
static struct class* Sysfs_class = NULL;

static struct device* Log_device = NULL;
static struct device* Reset_device = NULL;
static struct device* Rules_device = NULL;
static struct device* Conns_device = NULL;
static struct device* MITM_device = NULL;

static struct nf_hook_ops op;
static struct nf_hook_ops local_out;

// Rule tables

extern int num_rules; // number of rules
extern rule_t rule_table[]; // The rule table
extern rule_t rule_table_temp[]; // Temp rule table, used for loading new rules


// When opening the read logs device, the module resets the logs iterator. (see Logs.c iter_init())
int open_logs(struct inode *_inode, struct file *_file)
{
	iter_init();
	return 0;
}

// Read at most "length" bytes of log. The iterator remembers where the reading was stoped, 
// so we always continue reading from where we stopped.
ssize_t read_logs(struct file *filp, char *buff, size_t length, loff_t *offp)
{
	int num_of_bytes = get_logs(buff, length);
	if (num_of_bytes == 0) { 
    	return 0;
	} else if (num_of_bytes < 0) {
		return -EFAULT;
	}
	return num_of_bytes;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = open_logs,
	.read = read_logs
};

// Calling function "send_rule_table" from parser module.
ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return send_rule_table(rule_table, buf, num_rules);
}

// Calling function "send connection table " from the connection table module.
ssize_t display_conns(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return send_connection_table(buf);
}



// First, the module checks if CLEAR_RULES was sent and if so, it clears all the rules.
// Otherwise, it calls the "get_rule_table" method from parser.c. If the rules are in the
// Wrong format, the module returns an error value and the previous rules remain untouched.
ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int num_rules_temp;
	if ((count == strlen(CLEAR_RULES)) && (strncmp(CLEAR_RULES,buf,strlen(CLEAR_RULES)) == 0)) {
		num_rules = 0;
		return count;
	}
	num_rules_temp = get_rule_table(rule_table_temp, buf, count);
	if (num_rules_temp < 0) {
		return -EINVAL; // Change!
	}	
	num_rules = num_rules_temp;
	memcpy(rule_table, rule_table_temp, MAX_RULES*sizeof(rule_t));
	return count;
}

// If the user sent RESET, the module calls "clear_logs()" method from "Logs.c" which
// clears the log.
ssize_t modify_reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	if ((count == strlen(RESET)) && (strcmp(RESET, buf) == 0)) {
		clear_logs();
	} else {
		return -EINVAL;
	}
	return count;	
}

// This function has 2 porpuses. First, given the right input it sets a connection entry for the
// user space program for the port command. Otherwise, it can change an entry from a client to a server,
// to be from the mitm to the server.
ssize_t modify_mitm(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	__u32 src_ip, dst_ip, mitm_ip;
	__u16 src_port, dst_port, mitm_port;
	TCP_node* temp1 = NULL;
	TCP_node* temp2 = NULL;
	struct tcphdr tcph; 
	struct iphdr iph;
	if (sscanf(buf, "%u %hu %u %hu %u %hu", &src_ip, &src_port, &dst_ip, &dst_port, &mitm_ip ,&mitm_port) != 6) {
		if (sscanf(buf, "%u %hu %u %hu", &src_ip, &src_port, &dst_ip, &dst_port) != 4) {
			return -EINVAL;
		}
		iph.saddr = src_ip;
		iph.daddr = dst_ip;
		tcph.source = 0;
		tcph.dest = dst_port;
		add_tcp_connection(&tcph,&iph,&temp1,&temp2, REASON_PROXY);
	} else {
		set_mitm_connection(htonl(src_ip), htons(src_port), htonl(dst_ip), htons(dst_port), htonl(mitm_ip), htons(mitm_port));
	}

	return count;
}


static DEVICE_ATTR(conns, S_IRUGO , display_conns, NULL);
static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO , display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IWUSR, NULL, modify_reset);
static DEVICE_ATTR(mitm, S_IWUSR, NULL, modify_mitm);



static int __init my_init(void)
{
	//create char device
	major_number = register_chrdev(0, DEVICE_CHAR_NAME, &fops);
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	Sysfs_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(Sysfs_class))
	{
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}
	
	//create sysfs log device
	Log_device = device_create(Sysfs_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, CLASS_NAME "_" DEVICE_NAME_LOG);	
	if (IS_ERR(Log_device))
	{
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}

	//create sysfs reset device
	Reset_device = device_create(Sysfs_class, NULL, MKDEV(major_number, MINOR_RESET), NULL, DEVICE_NAME_LOG);	
	if (IS_ERR(Reset_device))
	{
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}
	
	//create sysfs file attributes for reset
	if (device_create_file(Reset_device, (const struct device_attribute *)&dev_attr_reset.attr))
	{
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}

	//create sysfs rules device
    Rules_device = device_create(Sysfs_class, NULL, MKDEV(major_number, MINOR_RULES), NULL, DEVICE_NAME_RULES);	
	if (IS_ERR(Rules_device))
	{
        device_remove_file(Reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}

	//create sysfs file attributes for rules
	if (device_create_file(Rules_device, (const struct device_attribute *)&dev_attr_rules.attr))
	{
        device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RULES));
        device_remove_file(Reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}

	//create sysfs conns device
    Conns_device = device_create(Sysfs_class, NULL, MKDEV(major_number, MINOR_CONNS), NULL, DEVICE_NAME_CONNS);	
	if (IS_ERR(Conns_device))
	{
		device_remove_file(Rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(Reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}

	//create sysfs file attributes for conns
	if (device_create_file(Conns_device, (const struct device_attribute *)&dev_attr_conns.attr))
	{
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_CONNS));
		device_remove_file(Rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(Reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}

	//create sysfs MITM device
	MITM_device = device_create(Sysfs_class, NULL, MKDEV(major_number, MINOR_MITM), NULL, DEVICE_NAME_MITM);	
	if (IS_ERR(MITM_device))
	{
		device_remove_file(Conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_CONNS));
		device_remove_file(Rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(Reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}

	//create sysfs file attributes for MITM
	if (device_create_file(MITM_device, (const struct device_attribute *)&dev_attr_mitm.attr))
	{
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_MITM));
		device_remove_file(Conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_CONNS));
		device_remove_file(Rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(Reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}

	// Registers the hooks!
	op.hook = (nf_hookfn*) hook_pre_routing;
	op.pf =  PF_INET;
	op.hooknum = NF_INET_PRE_ROUTING;
	op.priority = NF_IP_PRI_FIRST;
	if (nf_register_net_hook(&init_net, &op) < 0) {
		device_remove_file(MITM_device, (const struct device_attribute *)&dev_attr_mitm.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_MITM));
		device_remove_file(Conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_CONNS));
		device_remove_file(Rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(Reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}

	local_out.hook = (nf_hookfn*) hook_local_out;
	local_out.pf =  PF_INET;
	local_out.hooknum = NF_INET_LOCAL_OUT;
	local_out.priority = NF_IP_PRI_FIRST;
	if (nf_register_net_hook(&init_net, &local_out) < 0) {
		nf_unregister_net_hook(&init_net, &op);
		device_remove_file(MITM_device, (const struct device_attribute *)&dev_attr_mitm.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_MITM));
		device_remove_file(Conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_CONNS));
		device_remove_file(Rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RULES));
		device_remove_file(Reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RESET));
		device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(Sysfs_class);
		unregister_chrdev(major_number, DEVICE_CHAR_NAME);
		return -1;
	}

	init_connections();
	init_log();
	return 0;
}

static void __exit my_exit(void)
{
	// Removes everything
	delete_connections();
	clear_logs();
	device_remove_file(MITM_device, (const struct device_attribute *)&dev_attr_mitm.attr);
	device_destroy(Sysfs_class, MKDEV(major_number, MINOR_MITM));
	device_remove_file(Conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
	device_destroy(Sysfs_class, MKDEV(major_number, MINOR_CONNS));
	device_remove_file(Rules_device, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RULES));
	device_remove_file(Reset_device, (const struct device_attribute *)&dev_attr_reset.attr);
	device_destroy(Sysfs_class, MKDEV(major_number, MINOR_RESET));
	device_destroy(Sysfs_class, MKDEV(major_number, MINOR_LOG));
	class_destroy(Sysfs_class);
	unregister_chrdev(major_number, DEVICE_CHAR_NAME);

	nf_unregister_net_hook(&init_net, &op);
	nf_unregister_net_hook(&init_net, &local_out);
}

module_init(my_init);
module_exit(my_exit);

