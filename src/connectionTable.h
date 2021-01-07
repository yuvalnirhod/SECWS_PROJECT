#include <linux/list.h>
#include "fw.h"
#include <linux/ip.h>
#include <linux/tcp.h>

// This module is in charge of the TCP State machine and connection table. 
// We use a linked list to hold the connections, where we have two entrys for each connections.
// In case of a proxy, we hold 4 connections, one for mitm-client and the other for mitm-server.
// We also have an array of rules that enforce the tcp state machine, that we load at the beggining

// All the tcp states
typedef enum {
    NONE = 0,
    LISTEN = 1,
    SYN_SENT = 2,
    SYN_RCVD = 3,
    ESTABLISHED = 4,
    CLOSE_WAIT = 5,
    LAST_ACK = 6,
    FIN_WAIT_1 = 7,
    FIN_WAIT_2 = 8,
    CLOSING = 9,
    TIME_WAIT_s = 10,
    CLOSED = 11,
} States;

// Connections identifier
typedef struct {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;

} TCP_connection_identifier;

// Connection state
typedef struct {
    States state;
    States prev_state;
    int type;

    unsigned char received:1,
        syn:1,
        ack:1,
        fin:1,
        rst:1,
        left:3;

} TCP_connection_state;


// Connnection entry
typedef struct cns {
    struct cns* mitm;
    TCP_connection_identifier idr;
    TCP_connection_state state;
    struct list_head node;
    unsigned int index;
    reason_t rule_index;
    

} TCP_node;

// TCP State machine rule
typedef struct {

    int type; // If it is the client in the connection or the server
    States state; // the starting state

    unsigned char received:1, // Flags - Recived is whether a packet was already received
        syn:1, // TCP flags..
        ack:1,
        fin:1,
        rst:1,
        direction:1, // Whether the packet was sent to the source or from it
        left:2;

    // if received = 1, we have two rules that need to be enforced. The first packet is being checked against
    // The first rule, and the second against the second. only if both of the packets fit we move to
    // the next state.
    unsigned char syn2:1, 
        ack2:1,
        fin2:1,
        rst2:1,
        left2:4;

    States prev_state; // prev state the entry has been in. (can be NONE)
    States to_state; // State to transition to

} transition;

void init_connections(void);
void delete_connections(void);
void fill_server_transtions(transition *tr);
void fill_client_transtions(transition *tr);
ssize_t send_connection_table(char *buf);
int add_tcp_connection(struct tcphdr *tcph, struct iphdr *iph, TCP_node** mitm_client, TCP_node** mitm_server, reason_t rule_index);
int check_tcp_connection(struct tcphdr *tcph, struct iphdr *iph, reason_t *reason);
int set_mitm_connection(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, __be32 mitm_ip, __be16 mitm_port);
__be16 get_src_port(__be32 src_ip, __be32 dst_ip, __be16 mitm_port, __be16 dst_port);
__be32 get_client_ip(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);
__be16 get_client_port(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port);
__be32 get_server_ip(__be32 src_ip, __be32 dst_ip, __be16 mitm_port, __be16 dst_port);
