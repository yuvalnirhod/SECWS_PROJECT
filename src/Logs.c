#include "Logs.h"

DECLARE_HASHTABLE(log_table, LOG_TABLE_SIZE);  // Declaring the hash table
static struct log_table_entry *log_entrys;     // A pool of allocted memory
static int not_used_index = ALLOCATION_NUMBER; // Index of the first block of memory not used
                                               // in the alocated memory array.
static struct log_table_iterator iter;         // The iterator
static char string_to_send[70];                // this is more than the maximum size of the log.

// This function calculates the key of a log_row_t object, used by the hash table.
// It takes into account all of the packet's fields.
static unsigned int get_key(log_row_t *log)
{
    __be32 key = log->src_ip + log->dst_ip + (__be32)log->src_port + (__be32)log->dst_port + (__be32)log->protocol + (__be32)log->reason + (__be32)log->action;
    return (unsigned int)key;
}

// This function is used to compare to between two different log rows.
// It takes into account everything but the timestamp and count.
// We compare the reason field too because the rules can change while the firewall is running
static int compare_logs(log_row_t *log1, log_row_t *log2)
{
    return (log1->protocol == log2->protocol) && (log1->reason == log2->reason) && (log1->src_ip == log2->src_ip) && (log1->dst_ip == log2->dst_ip) && (log1->src_port == log2->src_port) && (log1->dst_port == log2->dst_port) && (log1->action == log2->action);
}

// This function initilizes the iterator.
void iter_init(void)
{
    iter.index = 0;
    iter.node = log_table->first;
}

// This function returns the next entry and advances the iterator
static int iter_next(struct log_table_entry **entry)
{

    while (iter.node == NULL)
    { // Looks for non-empty entry
        iter.index++;
        if (iter.index >= (1 << LOG_TABLE_SIZE))
        {
            return -1; // No more entrys left.
        }
        iter.node = log_table[iter.index].first;
    }

    *entry = hlist_entry_safe(iter.node, typeof(**entry), node);
    iter.node = iter.node->next;
    return 0;
}

// This function initilizes the log.
void init_log(void)
{
    hash_init(log_table);
    iter_init();
    return;
}

// This function clears the log. It frees all the memory, then
// initilize the log. The way it frees the memory is by going over
// all of the entrys, and freeing a block of memory only after we went through
// all of its entrys. This is explained with more details in the dry documentation document
int clear_logs(void)
{
    struct log_table_entry *entry;
    int *priv = NULL;
    int *temp_int;
    int bkt;

    hash_for_each(log_table, bkt, entry, node)
    {
        if (priv != NULL)
        { // Checks if there is something to free from the previous round
            kfree(priv);
            priv = NULL;
        }
        temp_int = ((int *)(entry - entry->index)) - 1; // Marks this entry as "seen"
        temp_int[0]--;
        if (*temp_int == 0)
        { // If we saw all of the entrys for this block, free it in the next round
            priv = temp_int;
        }
    }
    if (priv != NULL)
    {
        kfree(priv);
    }

    hash_init(log_table);
    not_used_index = ALLOCATION_NUMBER;
    return 0;
}

// This function adds a log row to the log. It first checks if it already exists in the log,
// and if so just updates the counter and the timestamp. Otherwise, it creates a new
// entry in the log using the pool of allocated memory. If the pool is empty,
// it allocates more.
int add_log(log_row_t *log)
{
    int *temp_int;
    struct log_table_entry *entry;
    unsigned int key = get_key(log); // gets the log row's key. the hash table uses a built in hash function on the key.

    // For each entry that has the same key as our log row, check if there equal.
    hash_for_each_possible(log_table, entry, node, key)
    {
        if (compare_logs(&entry->log_entry, log))
        {
            entry->log_entry.count++; // if so, update the counter and timestamp and exit
            entry->log_entry.timestamp = log->timestamp;
            return 0;
        }
    }

    // Check if there is still memory that was allocated before.
    if (not_used_index >= ALLOCATION_NUMBER)
    { // if note, allocate some more
        temp_int = (int *)kmalloc(sizeof(struct log_table_entry) * ALLOCATION_NUMBER + sizeof(int), GFP_KERNEL);
        if (temp_int == NULL)
        {
            return -1;
        }
        temp_int[0] = 0;
        log_entrys = (struct log_table_entry *)(temp_int + 1);
        not_used_index = 0;
    }

    // Create a new entry and add it to the hash table. 
    entry = &log_entrys[not_used_index];
    entry->log_entry = *log;
    hash_add(log_table, &entry->node, key);
    temp_int = ((int *) log_entrys) - 1;
    entry->index = not_used_index;
    temp_int[0]++; // update in the memory pool that another block is being used.
    not_used_index++;

    return 0;
}

// The following function iterates over the log and format as many log rows that can fit
// in "length". It starts from where the last call to this function ended, or from the
// start if the iterator was initilized
ssize_t get_logs(char *buff, size_t length)
{
    struct log_table_entry *entry;
    ssize_t num_bytes_w = 0;
    struct hlist_node *node;
    int index;

    while (iter_next(&entry) == 0) // If we havent reached the end yet
    {
        scnprintf(string_to_send, 70, "%lu %u %u %hu %hu %hhu %hhu %d %u\n", entry->log_entry.timestamp,
                  ntohl(entry->log_entry.src_ip), ntohl(entry->log_entry.dst_ip), ntohs(entry->log_entry.src_port),
                  ntohs(entry->log_entry.dst_port), entry->log_entry.protocol, entry->log_entry.action,
                  entry->log_entry.reason, entry->log_entry.count);

        if (strlen(string_to_send) + num_bytes_w >= length)
        {
            iter.node = node;
            index = iter.index;
            return num_bytes_w; // if we passed "length", dont add the last log and finish.
        }

        // Copy the formated log row to the user buffer.
        if (copy_to_user(buff + num_bytes_w, string_to_send, strlen(string_to_send)))
        {
            return -1;
        }
        num_bytes_w = num_bytes_w + strlen(string_to_send);
        node = iter.node;
        index = iter.index;
    }

    return num_bytes_w;
}
