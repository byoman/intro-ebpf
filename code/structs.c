struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};

Such a structure is assembled as an array of 4-tuples, that contains
a code, jt, jf and k value. jt and jf are jump offsets and k a generic
value to be used for a provided code.

struct sock_fprog {			/* Required for SO_ATTACH_FILTER. */
	unsigned short		   len;	/* Number of filter blocks */
	struct sock_filter __user *filter;
};

For socket filtering, a pointer to this structure (as shown in
follow-up example) is being passed to the kernel through setsockopt(2).
