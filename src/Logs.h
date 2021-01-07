#include "fw.h"
#include <linux/list.h>
#include <linux/hashtable.h>

#define LOG_TABLE_SIZE 10
#define ALLOCATION_NUMBER 10

// This module is in charge of the logs. it does everything from managing the
// data structure to formating them.
// The module uses a hash table to store the logs. at each entry of the table theres a
// linked list, so there is no issue of not enought space in the structure. (We can always
// extend the linked lists)

// The module also uses some more tricks to keep the data structure efficient. 
// I explain these methods in the dry documentation file.

// The hash table uses implicit linked lists, which are more efficent in memory.
struct log_table_entry {
    log_row_t log_entry;
    struct hlist_node node;
    int index;
};

// The structure for the iterator.
struct log_table_iterator {
    int index;
    struct hlist_node *node;
};


void init_log(void);
int clear_logs(void);
int add_log(log_row_t *log);
int get_logs(char *buff, size_t length);
void iter_init(void);