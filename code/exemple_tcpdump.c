#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
/* ... */

struct sock_filter code[] = {
	{ 0x28,  0,  0, 0x0000000c },
	{ 0x15,  0,  8, 0x000086dd },
	{ 0x30,  0,  0, 0x00000014 },
	{ 0x15,  2,  0, 0x00000084 },
	{ 0x15,  1,  0, 0x00000006 },
	{ 0x15,  0, 17, 0x00000011 },
	{ 0x28,  0,  0, 0x00000036 },
	{ 0x15, 14,  0, 0x00000016 },
	{ 0x28,  0,  0, 0x00000038 },
	{ 0x15, 12, 13, 0x00000016 },
	{ 0x15,  0, 12, 0x00000800 },
	{ 0x30,  0,  0, 0x00000017 },
	{ 0x15,  2,  0, 0x00000084 },
	{ 0x15,  1,  0, 0x00000006 },
	{ 0x15,  0,  8, 0x00000011 },
	{ 0x28,  0,  0, 0x00000014 },
	{ 0x45,  6,  0, 0x00001fff },
	{ 0xb1,  0,  0, 0x0000000e },
	{ 0x48,  0,  0, 0x0000000e },
	{ 0x15,  2,  0, 0x00000016 },
	{ 0x48,  0,  0, 0x00000010 },
	{ 0x15,  0,  1, 0x00000016 },
	{ 0x06,  0,  0, 0x0000ffff },
	{ 0x06,  0,  0, 0x00000000 },
};

struct sock_fprog bpf = {
	.len = ARRAY_SIZE(code),
	.filter = code,
};

sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
if (sock < 0)
	/* ... bail out ... */

ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
if (ret < 0)
	/* ... bail out ... */

/* do stuff  */
close(sock);
