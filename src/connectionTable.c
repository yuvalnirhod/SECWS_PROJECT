#include "connectionTable.h"

#define SERVER (0)
#define CLIENT (1)
#define MEMORY_BUFFER_SIZE 20
#define SYN 1
#define ACK 2
#define FIN 3
#define RST 4
#define IN 0
#define OUT 1

#define ON 1
#define OFF 0
#define TR 100

#define get_conn_num_ptr(entry) (((int *)(entry - entry->index)) - 1)

// Linked list for the entrys
LIST_HEAD(connections);
// Memory buffer for the entrys
TCP_node *memory_buffer;
// Index of where the buffer is not used
int not_used_ind = MEMORY_BUFFER_SIZE * 2;

// An array of rules
transition transitions[TR];
// Number of rules
unsigned int tr_ind = 0;

// Initializes the connection rules
void init_connections(void)
{
    fill_client_transtions(transitions);
    fill_server_transtions(transitions);
}

// Fills an entry
void fill_tcp_node(TCP_node **node, __be32 saddr, __be32 daddr, __be16 src_port, __be16 dst_port, reason_t rule_index)
{

    node[0] = &memory_buffer[not_used_ind];
    node[0]->index = not_used_ind;
    node[0]->rule_index = rule_index;

    node[0]->idr.src_ip = saddr;
    node[0]->idr.dst_ip = daddr;
    node[0]->idr.src_port = src_port;
    node[0]->idr.dst_port = dst_port;

    node[0]->state.state = CLOSED;
    node[0]->state.received = 0;
    node[0]->state.left = 0;
    node[0]->state.rst = 0;
    node[0]->state.ack = 0;
    node[0]->state.fin = 0;
    node[0]->state.syn = 0;
    node[0]->state.prev_state = NONE;

    // Adds the entry to the list
    list_add_tail(&(node[0]->node), &connections);
    not_used_ind++;
}


// Checks if a packet is a part of a connection. is some port is 0, we think of it as "any" (for the ftp data)
int is_part_of_connection(TCP_node *node, __be32 saddr, __be32 daddr, __be16 src_port, __be16 dst_port)
{
    int a = (node->idr.src_ip == saddr) && (node->idr.dst_ip == daddr);
    int b = (node->idr.src_port == src_port);
    int c = (node->idr.dst_port == dst_port);
    if (node->idr.src_port == 0)
    {
        if (a && c)
        {
            node->idr.src_port = src_port;
            return 1;
        }
    }
    else if (node->idr.dst_port == 0)
    {
        if (a && b)
        {
            node->idr.dst_port = dst_port;
            return 1;
        }
    }
    return a && b && c;
}

// Adds some new tcp connection. 
// Adds two entrys, one for each side of the connection.
// If the function is given two TCP_nodes, it marks that they are the other side of the man in the middle connection,
// Otherwise it returns the entrys its just created throught those fields.
int add_tcp_connection(struct tcphdr *tcph, struct iphdr *iph, TCP_node **mitm_client, TCP_node **mitm_server, reason_t rule_index)
{
    int *index_ptr;
    TCP_node *client_side;
    TCP_node *server_side;
    reason_t temp;

    // If there already is a starting entry for this connection, return
    if (check_tcp_connection(tcph, iph, &temp) == NF_ACCEPT)
    {
        return 0;
    }

    // If the buffer is empty, allocate more space
    if (not_used_ind >= MEMORY_BUFFER_SIZE * 2)
    {
        index_ptr = (int *)kmalloc(sizeof(TCP_node) * MEMORY_BUFFER_SIZE * 2 + sizeof(int), GFP_KERNEL);
        if (!index_ptr)
        {
            return -1;
        }
        index_ptr[0] = MEMORY_BUFFER_SIZE * 2;
        memory_buffer = (TCP_node *)(index_ptr + 1);
        not_used_ind = 0;
    }

    // Creates two entrys
    fill_tcp_node(&client_side, iph->saddr, iph->daddr, tcph->source, tcph->dest, rule_index);
    fill_tcp_node(&server_side, iph->daddr, iph->saddr, tcph->dest, tcph->source, rule_index);
    client_side->state.type = CLIENT;
    server_side->state.type = SERVER;
    client_side->mitm = NULL;
    server_side->mitm = NULL;

    // Creates the MITM connection
    if (mitm_client[0] != NULL)
    {
        mitm_client[0]->mitm = client_side;
        client_side->mitm = mitm_client[0];
    }
    else
    {
        mitm_client[0] = client_side;
    }

    if (mitm_server[0] != NULL)
    {
        mitm_server[0]->mitm = server_side;
        server_side->mitm = mitm_server[0];
    }
    else
    {
        mitm_server[0] = server_side;
    }

    return 0;
}

// This function deletes a connection. If the connection has a non closed MITM connection connected to it,
// it doesnt free its memory. If it has a finished MITM connection connected to it, it just
// frees the memory of that connection too.
void delete_tcp_connection(TCP_node *node)
{
    int *index_ptr;
    list_del(&node->node);
    if (node->mitm != NULL)
    {
        if ((node->mitm->state.state == CLOSED) || (node->mitm->state.state == TIME_WAIT_s))
        {
            index_ptr = get_conn_num_ptr(node->mitm);
            index_ptr[0] -= 1;
            if (index_ptr[0] == 0)
            {
                kfree(index_ptr);
            }
        }
        else
        {
            return;
        }
    }

    index_ptr = get_conn_num_ptr(node);
    index_ptr[0] -= 1;
    if (index_ptr[0] == 0)
    {
        kfree(index_ptr);
    }
}

// Deletes all the connections
void delete_connections(void)
{
    TCP_node *node;
    TCP_node *node_temp;

    list_for_each_entry_safe(node, node_temp, &connections, node)
    {
        node->state.state = CLOSED;
        delete_tcp_connection(node);
    }
}

// Switches a connection's state
void switch_state(TCP_connection_state *conn, States state)
{
    conn->received = 0;
    conn->left = 0;
    conn->ack = 0;
    conn->fin = 0;
    conn->syn = 0;
    conn->rst = 0;
    conn->prev_state = conn->state;
    conn->state = state;
}

// Checks if a packet fits a connection tcp state according to the given rule.
int compare_trans(TCP_connection_state *conn, struct tcphdr *tcph, int dir, transition *trans)
{
    if ((trans->prev_state != NONE) && (trans->prev_state != conn->prev_state))
    {
        return 0;
    }
    if ((trans->type != conn->type) || (trans->state != conn->state))
    {
        return 0;
    }
    switch (conn->received) // If the connection already received a packet, It checks both rules to allooow retransmite
    {
    case 1: // Checks if all fields match, and if so switches the state
        if ((dir == OUT) && (trans->syn2 == tcph->syn) &&
            (trans->ack2 == tcph->ack) && (trans->fin2 == tcph->fin) && (trans->rst2 == tcph->rst) &&
            (trans->left == conn->left))
        {
            switch_state(conn, trans->to_state);
            return 1; // returns that the packet was used
        }

    case 0: // Checks if all the fields match. if so, checks if we need to switch state or just mark that a 
            // packet has been reveived.
        if ((trans->direction == dir) && (trans->syn == tcph->syn) &&
            (trans->ack == tcph->ack) && (trans->fin == tcph->fin) && (trans->rst == tcph->rst) && (!conn->received || (conn->left == trans->left)))
        {
            if (trans->received)
            {

                conn->received = 1;
                conn->left = trans->left;
            }
            else
            {
                if (trans->state != trans->to_state)
                {
                    switch_state(conn, trans->to_state);
                }
            }
            return 1; //returns that the pacekt was used.
        }
    }
    return 0;
}

// Checks if a packet fits a connection tcp state.
// goes over all the rules and applies the above function.
int state_transition(TCP_connection_state *conn, struct tcphdr *tcph, int dir, transition *trans, int len)
{
    int i;
    int val = 0;
    for (i = 0; i < len; i++)
    {
        val += compare_trans(conn, tcph, dir, &trans[i]);
    }

    return val;
}

// Checks if a packet is a part of a connection. It checks both directions, and passes the direction that fit.
int check_and_apply_transition(TCP_node *node, __be32 saddr, __be32 daddr, __be16 src_port, __be16 dst_port, struct tcphdr *tcph, int dir)
{
    int legal = 0;
    if (is_part_of_connection(node, saddr, daddr, src_port, dst_port))
    {
        legal = state_transition(&node->state, tcph, dir, transitions, tr_ind);
        if ((node->state.state == CLOSED) || (node->state.state == TIME_WAIT_s))
        {
            delete_tcp_connection(node);
        }
    }
    return legal;
}

// Cheks if a packet fits some entry. Goes over all the entrys and applies the above function
// If it fits any entry, accepts, otherwise drops.
int check_tcp_connection(struct tcphdr *tcph, struct iphdr *iph, reason_t *reason)
{
    TCP_node *node;
    TCP_node *node_temp;
    int legal = 0;
    int temp1, temp2;

    list_for_each_entry_safe(node, node_temp, &connections, node)
    {
        temp1 = check_and_apply_transition(node, iph->saddr, iph->daddr, tcph->source, tcph->dest, tcph, OUT);
        if (node != NULL)
        {
            temp2 = check_and_apply_transition(node, iph->daddr, iph->saddr, tcph->dest, tcph->source, tcph, IN);
        }
        else
        {
            temp2 = 0;
        }
        if (temp1 + temp2 > 0)
        {
            reason[0] = node->rule_index;
        }
        legal += temp1 + temp2;
    }

    if (legal > 0)
    {
        return NF_ACCEPT;
    }
    reason[0] = REASON_ILLEGAL_VALUE;
    return NF_DROP;
}

// Given some connection identifier, switches the connection to be from the MITM to the server instead of client to server.
int set_mitm_connection(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, __be32 mitm_ip, __be16 mitm_port)
{
    TCP_node *node;
    TCP_node *node_temp;

    list_for_each_entry_safe(node, node_temp, &connections, node)
    {
        if (node->idr.src_ip == src_ip && node->idr.src_port == src_port && node->idr.dst_ip == dst_ip && node->idr.dst_port == dst_port)
        {
            node->idr.src_ip = mitm_ip;
            node->idr.src_port = mitm_port;
        }
        else if (node->idr.dst_ip == src_ip && node->idr.dst_port == src_port && node->idr.src_ip == dst_ip && node->idr.src_port == dst_port)
        {
            node->idr.dst_ip = mitm_ip;
            node->idr.dst_port = mitm_port;
        }
    }

    return 0;
}

// Gets client IP given MITM to server connection.
__be32 get_client_ip(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port)
{
    TCP_node *node;
    TCP_node *node_temp;

    list_for_each_entry_safe(node, node_temp, &connections, node)
    {
        if (is_part_of_connection(node, src_ip, dst_ip, src_port, dst_port))
        {
            if (node->mitm != NULL)
            {
                return node->mitm->idr.src_ip;
            }
        }
    }

    return 0;
}

// Gets client port given MITM to SERVER connection
__be16 get_client_port(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port)
{
    TCP_node *node;
    TCP_node *node_temp;

    list_for_each_entry_safe(node, node_temp, &connections, node)
    {
        if (is_part_of_connection(node, src_ip, dst_ip, src_port, dst_port))
        {
            if (node->mitm != NULL)
            {
                return node->mitm->idr.dst_port;
            }
        }
    }

    return 0;
}

// Gets server IP given MITM to client connection
__be32 get_server_ip(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port)
{
    TCP_node *node;
    TCP_node *node_temp;

    list_for_each_entry_safe(node, node_temp, &connections, node)
    {
        if (is_part_of_connection(node, dst_ip, src_ip, dst_port, src_port))
        {
            if (node->mitm != NULL)
            {
                return node->mitm->idr.dst_ip;        
            }
        }
    }

    return 0;
}

// Fills rule flags
void fill_flags(transition *tr, int F1)
{
    if (F1 == SYN)
    {
        tr->syn = 1;
    }
    else if (F1 == ACK)
    {
        tr->ack = 1;
    }
    else if (F1 == FIN)
    {
        tr->fin = 1;
    }
    else if (F1 == RST)
    {
        tr->rst = 1;
    }
}

// Fills rule flags 2
void fill_flags2(transition *tr, int F1)
{
    if (F1 == SYN)
    {
        tr->syn2 = 1;
    }
    else if (F1 == ACK)
    {
        tr->ack2 = 1;
    }
    else if (F1 == FIN)
    {
        tr->fin2 = 1;
    }
    else if (F1 == RST)
    {
        tr->rst2 = 1;
    }
}

// Fills a transition. (rules)
void fill_transition_helper(transition *tr, int type, States state, States to_state, int received, int dir, int F1, int F2, int F1t, int F2t, int to_left, States prev_state)
{
    tr->type = type;
    tr->state = state;
    tr->to_state = to_state;
    tr->prev_state = prev_state;
    tr->received = received;
    tr->direction = dir;
    tr->left = 0;

    tr->syn = 0;
    tr->fin = 0;
    tr->ack = 0;
    tr->rst = 0;
    tr->syn2 = 0;
    tr->fin2 = 0;
    tr->ack2 = 0;
    tr->rst2 = 0;

    fill_flags(tr, F1);
    fill_flags(tr, F2);

    if (received)
    {
        tr->direction = IN;
        tr->left = to_left;
        fill_flags2(tr, F1t);
        fill_flags2(tr, F2t);
    }
}

// Given some rule, creates transitions that enforce it, and allow retransmit
void fill_transition(transition *tr, int type, States state, States to_state, int received, int dir, int F1, int F2, int F1t, int F2t, int to_left)
{
    fill_transition_helper(tr, type, state, to_state, received, dir, F1, F2, F1t, F2t, to_left, NONE);
    tr_ind++;
    if (state != to_state) // Retransmit!
    {
        if (received)
        {
            fill_transition_helper(tr + 1, type, to_state, to_state, OFF, OUT, F1t, F2t, OFF, OFF, OFF, to_state);
            tr_ind++;
        }
        else
        {
            fill_transition_helper(tr + 1, type, to_state, to_state, OFF, dir, F1, F2, OFF, OFF, OFF, to_state);
            tr_ind++;
        }
    }
}

// All the rules for the SERVER
void fill_server_transtions(transition *tr)
{
    fill_transition(&tr[tr_ind], SERVER, CLOSED, LISTEN, OFF, IN, SYN, OFF, OFF, OFF, OFF);            // CLOSED -> LISTEN
    fill_transition(&tr[tr_ind], SERVER, LISTEN, SYN_RCVD, ON, IN, SYN, OFF, SYN, ACK, OFF);           // LISTEN -> SYN_RCVD
    fill_transition(&tr[tr_ind], SERVER, SYN_RCVD, ESTABLISHED, OFF, IN, ACK, OFF, OFF, OFF, OFF);     // SYN_RCVD -> ESTABLISHED
    fill_transition(&tr[tr_ind], SERVER, ESTABLISHED, ESTABLISHED, OFF, IN, ACK, OFF, OFF, OFF, OFF);  // ESTABLISHED -> ESTABLISHED
    fill_transition(&tr[tr_ind], SERVER, ESTABLISHED, ESTABLISHED, OFF, OUT, ACK, OFF, OFF, OFF, OFF); // ESTABLISHED -> ESTABLISHED
    fill_transition(&tr[tr_ind], SERVER, ESTABLISHED, CLOSE_WAIT, ON, IN, FIN, ACK, ACK, OFF, 1);      // ESTABLISHED -> CLOSE_WAIT
    fill_transition(&tr[tr_ind], SERVER, CLOSE_WAIT, LAST_ACK, OFF, OUT, FIN, ACK, OFF, OFF, OFF);     // CLOSE_WAIT -> LAST_ACK
    fill_transition(&tr[tr_ind], SERVER, ESTABLISHED, LAST_ACK, ON, IN, FIN, ACK, FIN, ACK, 1);        // ESTABLISHED -> LAST_ACK
    fill_transition(&tr[tr_ind], SERVER, LAST_ACK, CLOSED, OFF, IN, ACK, OFF, OFF, OFF, OFF);          // LAST_ACK -> CLOSED

    fill_transition(&tr[tr_ind], SERVER, ESTABLISHED, FIN_WAIT_1, OFF, OUT, FIN, ACK, OFF, OFF, OFF); // ESTABLISHED -> FIN_WAIT_1
    fill_transition(&tr[tr_ind], SERVER, FIN_WAIT_1, TIME_WAIT_s, ON, IN, FIN, ACK, ACK, OFF, 1);     // FIN_WAIT_1 -> CLOSING
    fill_transition(&tr[tr_ind], SERVER, FIN_WAIT_1, FIN_WAIT_2, OFF, IN, ACK, OFF, OFF, OFF, OFF);   // FIN_WAIT_1 -> FIN_WAIT_2
    fill_transition(&tr[tr_ind], SERVER, CLOSING, TIME_WAIT_s, OFF, IN, ACK, OFF, OFF, OFF, OFF);     // CLOSING -> TIME_WAIT_s
    fill_transition(&tr[tr_ind], SERVER, FIN_WAIT_2, TIME_WAIT_s, ON, IN, FIN, ACK, ACK, OFF, OFF);   // FIN_WAIT_2 -> TIME_WAIT_s MAYBE CHANGE!
}

// All the rules for the CLIENT
void fill_client_transtions(transition *tr)
{
    fill_transition(&tr[tr_ind], CLIENT, CLOSED, SYN_SENT, OFF, OUT, SYN, OFF, OFF, OFF, OFF);         // CLOSED -> SYN_SENT
    fill_transition(&tr[tr_ind], CLIENT, SYN_SENT, ESTABLISHED, ON, IN, SYN, ACK, ACK, OFF, 1);        // SYN_SENT -> ESTABLISHED
    fill_transition(&tr[tr_ind], CLIENT, ESTABLISHED, FIN_WAIT_1, OFF, OUT, FIN, ACK, OFF, OFF, OFF);  // ESTABLISHED -> FIN_WAIT_1
    fill_transition(&tr[tr_ind], CLIENT, ESTABLISHED, ESTABLISHED, OFF, IN, ACK, OFF, OFF, OFF, OFF);  // ESTABLISHED -> ESTABLISHED
    fill_transition(&tr[tr_ind], CLIENT, ESTABLISHED, ESTABLISHED, OFF, OUT, ACK, OFF, OFF, OFF, OFF); // ESTABLISHED -> ESTABLISHED
    fill_transition(&tr[tr_ind], CLIENT, FIN_WAIT_1, TIME_WAIT_s, ON, IN, FIN, ACK, ACK, OFF, 1);      // FIN_WAIT_1 -> CLOSING
    fill_transition(&tr[tr_ind], CLIENT, FIN_WAIT_1, FIN_WAIT_2, OFF, IN, ACK, OFF, OFF, OFF, OFF);    // FIN_WAIT_1 -> FIN_WAIT_2
    fill_transition(&tr[tr_ind], CLIENT, CLOSING, TIME_WAIT_s, OFF, IN, ACK, OFF, OFF, OFF, OFF);      // CLOSING -> TIME_WAIT_s
    fill_transition(&tr[tr_ind], CLIENT, FIN_WAIT_2, TIME_WAIT_s, ON, IN, FIN, ACK, ACK, OFF, OFF);    // FIN_WAIT_2 -> TIME_WAIT_s MAYBE CHANGE!

    fill_transition(&tr[tr_ind], CLIENT, ESTABLISHED, CLOSE_WAIT, ON, IN, FIN, ACK, ACK, OFF, 1);  // ESTABLISHED -> CLOSE_WAIT
    fill_transition(&tr[tr_ind], CLIENT, CLOSE_WAIT, LAST_ACK, OFF, OUT, FIN, ACK, OFF, OFF, OFF); // CLOSE_WAIT -> LAST_ACK
    fill_transition(&tr[tr_ind], CLIENT, ESTABLISHED, LAST_ACK, ON, IN, FIN, ACK, FIN, ACK, 1);    // ESTABLISHED -> LAST_ACK
    fill_transition(&tr[tr_ind], CLIENT, LAST_ACK, CLOSED, OFF, IN, ACK, OFF, OFF, OFF, OFF);      // LAST_ACK -> CLOSED
}

// Parses and sends the connection table. We combine the MITM connections to appear as one connection
// From the client to the server
ssize_t send_connection_table(char *buf)
{
    ssize_t bytes_written = 0;
    TCP_node *entry;
    TCP_node *node_temp;

    __be32 dst_ip, src_ip;
    __be16 dst_port, src_port;
    States state;

    list_for_each_entry_safe(entry, node_temp, &connections, node)
    {
        if (entry->mitm != NULL)
        {
            if ((ntohs(entry->idr.dst_port) / 10 == ntohs(entry->mitm->idr.dst_port)) || (entry->idr.src_ip == entry->mitm->idr.src_ip))
            {
                src_ip = entry->idr.src_ip;
                dst_ip = entry->mitm->idr.dst_ip;
                src_port = entry->idr.src_port;
                dst_port = entry->mitm->idr.dst_port;
            }
            else if ((ntohs(entry->idr.src_port) * 10 == ntohs(entry->mitm->idr.src_port)) || (entry->idr.src_ip == entry->mitm->idr.src_ip))
            { 
                src_ip = entry->idr.src_ip;
                dst_ip = entry->mitm->idr.dst_ip;
                src_port = entry->idr.src_port;
                dst_port = entry->mitm->idr.dst_port;
            }
            else
            {
                continue;
            }
        }
        else
        {
            src_ip = entry->idr.src_ip;
            src_port = entry->idr.src_port;
            dst_ip = entry->idr.dst_ip;
            dst_port = entry->idr.dst_port;
        }
        state = entry->state.state;
        bytes_written += scnprintf(buf + bytes_written, 70, "%u %u %hu %hu %hu\n",
                                   ntohl(src_ip), ntohl(dst_ip), ntohs(src_port),
                                   ntohs(dst_port), state);
    }

    return bytes_written;
}