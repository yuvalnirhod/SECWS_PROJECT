#include <linux/kernel.h>
#include "fw.h"

// A header file for the parser module. the parser is in charge of parsing
// the input from the user, and formating the rule table data so it could be 
// sent back to the user.

int get_rule_table(rule_t *rule_table, const char *buf, size_t count);
int send_rule_table(rule_t *rule_table, char *buf, int num_rules);