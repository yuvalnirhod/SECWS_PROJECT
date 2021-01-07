#include "fw.h"
#include "Logs.h"
#include "connectionTable.h"
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/inetdevice.h>

#define FTP_PORT htons(21)
#define HTTP_PORT htons(80)
#define SMTP_PORT htons(25)
#define NIFI_PORT htons(8080)

#define FAKE_FTP_PORT htons(210)
#define FAKE_HTTP_PORT htons(800)
#define FAKE_SMTP_PORT htons(250)
#define FAKE_NIFI_PORT htons(808)


// The hook module is in charge of the hook. 

unsigned int hook_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
