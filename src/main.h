#ifndef _MAIN_H_
#define _MAIN_H_

#include <pcap/pcap.h>
#include <stdint.h>
#include "list.h"

#ifndef INT_MAX
#define INT_MAX 2147483647
#endif

#define MAX_DIRLEN	256

#define MAC_LEN			6

#define MAX_NODES		255
#define MAX_ESSIDS		255
#define MAX_BSSIDS		255
#define MAX_HISTORY		255
#define MAX_CHANNELS		64
#define MAX_ESSID_LEN		32
#define MAX_RATES		109	/* in 500kbps steps: 54 * 2 + 1 for array index */
#define MAX_FSTYPE		0xff
#define MAX_FILTERMAC		9

#define _DATA			0
#define _MGMT			1
#define _CTRL			2

#define TOTAL_RECEIVED_PACKETS(stn) \
	((stn->received_packets[_DATA]) + (stn->received_packets[_MGMT]) + (stn->received_packets[_CTRL]))

/* packet types we actually care about, e.g filter */
#define PKT_TYPE_CTRL		0x000001
#define PKT_TYPE_MGMT		0x000002
#define PKT_TYPE_DATA		0x000004

#define PKT_TYPE_BEACON		0x000010
#define PKT_TYPE_PROBE		0x000020
#define PKT_TYPE_ASSOC		0x000040
#define PKT_TYPE_AUTH		0x000080
#define PKT_TYPE_RTS		0x000100
#define PKT_TYPE_CTS		0x000200
#define PKT_TYPE_ACK		0x000400
#define PKT_TYPE_NULL		0x000800

#define PKT_TYPE_ARP		0x001000
#define PKT_TYPE_IP		0x002000
#define PKT_TYPE_ICMP		0x004000
#define PKT_TYPE_UDP		0x008000
#define PKT_TYPE_TCP		0x010000
#define PKT_TYPE_OLSR		0x020000
#define PKT_TYPE_OLSR_LQ	0x040000
#define PKT_TYPE_OLSR_GW	0x080000
#define PKT_TYPE_BATMAN		0x100000
#define PKT_TYPE_MESHZ		0x200000

#define PKT_TYPE_ALL_MGMT	(PKT_TYPE_BEACON | PKT_TYPE_PROBE | PKT_TYPE_ASSOC | PKT_TYPE_AUTH)
#define PKT_TYPE_ALL_CTRL	(PKT_TYPE_RTS | PKT_TYPE_CTS | PKT_TYPE_ACK)
#define PKT_TYPE_ALL_DATA	(PKT_TYPE_NULL | PKT_TYPE_ARP | PKT_TYPE_ICMP | PKT_TYPE_IP | \
				 PKT_TYPE_UDP | PKT_TYPE_TCP | PKT_TYPE_OLSR | PKT_TYPE_OLSR_LQ | \
				 PKT_TYPE_OLSR_GW | PKT_TYPE_BATMAN | PKT_TYPE_MESHZ)

#define WLAN_MODE_AP		0x01
#define WLAN_MODE_IBSS		0x02
#define WLAN_MODE_STA		0x04
#define WLAN_MODE_PROBE		0x08

#define PHY_FLAG_SHORTPRE	0x0001
#define PHY_FLAG_BADFCS		0x0002
#define PHY_FLAG_A		0x0010
#define PHY_FLAG_B		0x0020
#define PHY_FLAG_G		0x0040
#define PHY_FLAG_MODE_MASK	0x00f0

/* default config values */
#define INTERFACE_NAME		"wlan0"
#define NODE_TIMEOUT		60	/* seconds */
#define CHANNEL_TIME		250000	/* 250 msec */
/* update display every 100ms - "10 frames per sec should be enough for everyone" ;) */
#define DISPLAY_UPDATE_INTERVAL 100000	/* usec */
#define RECV_BUFFER_SIZE	0	/* not used by default */
#define DEFAULT_PORT		"4444"	/* string because of getaddrinfo() */

#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803    /* IEEE 802.11 + radiotap header */
#endif

#ifndef ARPHRD_IEEE80211_PRISM
#define ARPHRD_IEEE80211_PRISM 802      /* IEEE 802.11 + Prism2 header  */
#endif

#define PHY80211N_MCS_CALC(bw,gi) \
	((2 * gi) + (bw == 1? 1 : 0))

enum rate_change_type {
	CHANGE_TYPE_SEQUENTIAL=0,
	CHANGE_TYPE_SEQUENTIAL_AFTER=1,
	CHANGE_TYPE_SEQUENTIAL_BEFORE=2,
	CHANGE_TYPE_NON_SEQUENTIAL=3,
};

struct config {
	int			arphrd;
	pcap_t			*descr;
	char			*dev;
	struct bpf_program 	fp;
	char			output_directory[MAX_DIRLEN];
};

extern struct config conf;

struct ieee_80211_radiotap_mcs {
	uint8_t known_bandwidth:1,
		known_mcs_index:1,
		known_guard_interval:1,
		known_ht_format:1,
		known_fec_type:1,
		known_reserved:3;
	uint8_t flags_bandwidth:2,
		flags_guard_interval:1,
		flags_ht_format:1,
		flags_fec_type:1,
		flags_reserved:3;
	uint8_t mcs;

} __attribute__((packed));

struct packet_info {
	struct list_head	retransmits;

	struct timeval		received;
	unsigned int		phy_rate;
	unsigned int		phy_freq;
	unsigned char		phy_chan;
	int			phy_signal;
	int			phy_noise;
	unsigned int		phy_snr;
	unsigned int		phy_flags;

	/* general */
	unsigned int		pkt_types;	/* bitmask of packet types */

	/* 802.11n specific fields */
	unsigned int		phy_n;
	struct ieee_80211_radiotap_mcs mcs;

	/* wlan mac */
	unsigned int		wlan_len;	/* packet length */
	unsigned int		wlan_type;	/* frame control field */
	unsigned char		wlan_src[MAC_LEN];
	unsigned char		wlan_dst[MAC_LEN];
	unsigned char		wlan_qos_class;	/* for QDATA frames */
	unsigned int		wlan_nav;	/* frame NAV duration */
	unsigned int		wlan_seqno;	/* sequence number */

	/* flags */
	unsigned int		wlan_wep:1,	/* WEP on/off */
				wlan_retry:1;
	unsigned int		wlan_retries;
};

struct loss {
	struct list_head	list;
	struct timeval		time;
	unsigned int		num_lost;
};

struct sample {
	struct list_head	list;
	struct timeval		time;
	unsigned int		sample_to;
	unsigned int		sample_from;
	unsigned int		wlan_seqno;
	unsigned int		stn_received_ct;
};

struct sample_freq {
	struct list_head	list;
	unsigned int		since_last;
	unsigned int		num_samples;
};

struct sample_statistics {
	unsigned int		num_samples;
	struct timeval		next_analysis;
	

	struct sample		*last_analyzed_sample;


	struct list_head	sampling_frequency;

	unsigned int		num_samples_range[100];
	unsigned int		min_frames_between_samples;

};

struct rate_change {
	struct list_head	list;
	struct timeval		time;
	unsigned int		new_rate;
	unsigned int		wlan_seqno;
	enum rate_change_type	change_type;
	unsigned int		stn_received_ct;
};

struct rate_change_statistics {
	unsigned int		num_rate_changes;
	unsigned int		min_frame_between_changes;
	
	struct rate_change	*last_analyzed_rate_change;
	struct timeval		next_analysis;
	
	
	struct timeval		min_time_between_rate_changes;
	unsigned int		min_pkt_between_rate_changes;
	unsigned int		rate_change_type_stats[4];
	unsigned int		max_rate_change_per_sec;
	unsigned int		rate_change_over_multiple_steps;
};

struct retry {
	struct list_head	list;
	struct timeval		time;
	unsigned int		num_retries;
	unsigned int		original_rate;
	unsigned int 		wlan_seqno;
	/* We assume the retry chain does not exceed 64 */
	unsigned int		retry_chain[64];
};

struct retry_statistics {
	struct list_head	retries;
	unsigned int		max_num_retries;
};

struct control_statistics {
	unsigned long int	num_rts;
	unsigned long int	num_cts;
};

struct station {
	struct list_head	list;
	struct list_head	samples;
	struct list_head	rate_changes;
	struct list_head	losses;
	unsigned char		wlan_srcmac[MAC_LEN];

	/* Statistics */
	unsigned long int	received_packets[3];
	unsigned long int	received_retransmits;
	unsigned long int	retransmitted_packets;
	unsigned long int	estimated_lost_packets;
	unsigned long int	mcs_num_packets[32][4];
	unsigned long int	legacy_num_packets[109];


	/* Analysis variables */
	int			prev_is_sample;
	unsigned int		current_best_rate;
	struct packet_info	*a, *b, *c, *d, *e;

	struct rate_change_statistics	rate_change_stat;
	struct sample_statistics	sample_stat;
	struct control_statistics	ctrl_stat;
	struct retry_statistics		retry_stat;

	/* flags */
	unsigned int		use_rts:1,
				use_cts:1,
				use_sampling:1;

	/* filters */
	int			filter_last_seqno;
	struct packet_info	*prev;


	/* PHY information */
	unsigned int		curr_phy_rate;
	unsigned int		curr_phy_freq;
	unsigned int		curr_phy_channel;
	unsigned int		curr_phy_snr;
	int			curr_phy_signal;
	int			curr_phy_noise;

	int			phy_n;
	int			curr_mcs_index;
	int			curr_guard_interval;
	int 			curr_ht_format;
	int			curr_bandwidth;
}; 



void print_packet_debug(struct station *stn, struct packet_info *p);

#endif
