#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <net/if.h>
#include <err.h>

#include "main.h"
#include "util.h"
#include "parser.h"
#include "list.h"
#include "generic_classifier.h"
#include "statistics.h"
#include "view_main.h"

struct config conf;

struct list_head stations;

static void
handle_mgmt_packet(struct station *stn, struct packet_info *p)
{
	
	statistics_handle_mgmt_packet(stn, stn->prev);
}

static void
handle_ctrl_packet(struct station *stn, struct packet_info *p)
{
	
	statistics_handle_ctrl_packet(stn, stn->prev);
}

static void
handle_data_packet(struct station *stn, struct packet_info *p)
{
	struct packet_info *tmp, *entry;

	if (p->pkt_types & PKT_TYPE_NULL)
		return;

	if (stn->prev == NULL) {
		if (!p->wlan_retry) {
			stn->prev = malloc(sizeof(struct packet_info));
	        	memcpy(stn->prev, p, sizeof(struct packet_info));
		        INIT_LIST_HEAD(&(stn->prev->retransmits));
		}
		return;
	}

	/* Add the frame to the retry list of the mother-frame */
	if (p->wlan_retry || p->wlan_seqno == stn->prev->wlan_seqno) {
		if (p->wlan_seqno == stn->prev->wlan_seqno) {
			tmp = malloc(sizeof(struct packet_info));
			memcpy(tmp, p, sizeof(struct packet_info));
			list_add_tail(&(tmp->retransmits), &(stn->prev->retransmits));
			/* Force the wlan_retry flag as some drivers
			 * don't actually set the retry flag in the radiotap header */
			tmp->wlan_retry = 1;
			/* Increment the retry counter for the mother-frame */
			stn->prev->wlan_retries++;
		}
		return;
	}
	
	print_packet_debug(stn, stn->prev);

	statistics_handle_data_packet(stn, stn->prev);
	
	generic_classifier(stn, stn->prev);

	list_for_each_entry_safe(entry, tmp, &(stn->prev->retransmits), retransmits)
		free (entry);
	
	free (stn->prev);
	stn->prev = NULL;

	stn->prev = malloc(sizeof(struct packet_info));
	memcpy(stn->prev, p, sizeof(struct packet_info));
	INIT_LIST_HEAD(&(stn->prev->retransmits));	
}

static void
handle_packet(struct station *stn, struct packet_info *p)
{
	if (p->pkt_types & PKT_TYPE_MGMT) {
		/* We got a MGMT packet */
		handle_mgmt_packet(stn, p);
	} else if (p->pkt_types & PKT_TYPE_CTRL) {
		/* We got a CTRL packet */
		handle_ctrl_packet(stn, p);
	} else if (p->pkt_types & PKT_TYPE_DATA) {
		/* We got a DATA packet */
		handle_data_packet(stn, p);
	} else {
		DEBUG("GOT UNKNOWN PACKET TYPE\n");
		return;
	}
}

void
pcap_callback(u_char *args, const struct pcap_pkthdr* pkthdr,
	const u_char *packet)
{
	struct packet_info p;
	struct station *entry;
	DEBUG("-------- NEW ----------\n");

	bzero(&p, sizeof(struct packet_info));
	INIT_LIST_HEAD(&(p.retransmits));
	
	memcpy(&(p.received), &(pkthdr->ts), sizeof(struct timeval));

	/* implicit from bzero... */
	p.phy_n = 0;

	int n = parse_radiotap_header((void*)packet, pkthdr->len, &p);
	
	if (n < 0) {
		return;
	}
	
	if (parse_80211_header(packet + n, pkthdr->len - n, &p)) {
		DEBUG("Failed to parse packet.");
		return;
	}

	list_for_each_entry(entry, &stations, list) {
		if (MAC_SAME(p.wlan_src, entry->wlan_srcmac)) {
			handle_packet(entry, &p);
		} 
	}
}

void
print_packet_debug(struct station *stn, struct packet_info *p)
{

#ifdef DEBUGPKT
        char pkt_type;

	if (p->wlan_retry)
		return;

        if (p->pkt_types & PKT_TYPE_CTRL)
                pkt_type = 'C';
        else if (p->pkt_types & PKT_TYPE_DATA)
                pkt_type = 'D';
        else if (p->pkt_types & PKT_TYPE_MGMT)
                pkt_type = 'M';
        else
                pkt_type = 'U';

	char src[18];
	char dst[18];

	memcpy(src, ether_sprintf(p->wlan_src), 17);
	memcpy(dst, ether_sprintf(p->wlan_dst), 17);

	src[17] = '\0';
	dst[17] = '\0';


	char frame_type;
	if (p->pkt_types & PKT_TYPE_NULL) {
		frame_type = 'N';
	} else {
		frame_type = 'P';
	}

        fprintf(stderr, "[%c%c%c%c] %5d %6d (%2d %2d %2d %2d) %3d %4d %s %ld/%ld %ld.%06ld %d\n",
		frame_type,
                p->wlan_retry ? 'R' : ' ',
                pkt_type,
		p->phy_n ? 'N' : 'B',
                p->wlan_seqno,
                p->phy_rate,
		p->mcs.mcs,
		p->mcs.known_bandwidth? p->mcs.flags_bandwidth : -1,
		p->mcs.known_guard_interval ? p->mcs.flags_guard_interval : -1,
		p->mcs.known_ht_format ? p->mcs.flags_ht_format : -1,
                p->phy_chan,
                p->wlan_len,
		src,
		TOTAL_RECEIVED_PACKETS(stn),
		stn->estimated_lost_packets,
                p->received.tv_sec,
                p->received.tv_usec,
		stn->current_best_rate
        );
#endif
}

static int
create_station(const char *srcmac)
{
	struct station *new;

	new = malloc(sizeof(struct station));
	bzero(new, sizeof(struct station));

	convert_string_to_mac(srcmac, new->wlan_srcmac);
	new->filter_last_seqno = -1;

	new->rate_change_stat.min_time_between_rate_changes.tv_sec = INT_MAX;
	new->rate_change_stat.min_pkt_between_rate_changes = INT_MAX;

	INIT_LIST_HEAD(&(new->samples));
	INIT_LIST_HEAD(&(new->rate_changes));
	INIT_LIST_HEAD(&(new->losses));

	INIT_LIST_HEAD(&(new->sample_stat.sampling_frequency));
	INIT_LIST_HEAD(&(new->retry_stat.retries));

	list_add_tail(&new->list, &stations);


	return 0;
}

/*
 *  Get the hardware type of the given interface as ARPHRD_xxx constant.
 */
int
device_get_arptype(int fd, char* ifname)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
		err(1, "Could not get arptype");
	DEBUG("ARPTYPE %d\n", ifr.ifr_hwaddr.sa_family);
	return ifr.ifr_hwaddr.sa_family;
}

static void
free_station(struct station *stn)
{

	struct sample *sentry, *sentry_tmp;
	list_for_each_entry_safe(sentry, sentry_tmp, &(stn->samples), list) {
		free(sentry);
	}

	struct rate_change *rc, *rc_tmp;
	list_for_each_entry_safe(rc, rc_tmp, &(stn->rate_changes), list) {
		free(rc);
	}

	if (stn->prev)
		free(stn->prev);
	
	free(stn);
}

void
free_lists(void) 
{
	struct station *entry, *tmp;
	list_for_each_entry_safe(entry, tmp, &stations, list) {
		free_station(entry);
	}
}

static void
dump_samples(struct station *stn)
{
	struct sample *entry;
	FILE *f;
	
	f = fopen("/tmp/samples.dat", "w");
	if (f == NULL) {
		perror("fopen samples");
		return;
	}
	
	list_for_each_entry(entry, &stn->samples, list) {
		fprintf(f, "%ld.%06ld %d\n", entry->time.tv_sec, entry->time.tv_usec,
			entry->sample_to);
	}

	fclose(f);
}

static void
dump_rate_changes(struct station *stn)
{
	struct rate_change *entry;
	FILE *f;
	
	f = fopen("/tmp/rate_changes.dat", "w");
	if (f == NULL) {
		perror("fopen rate_changes");
		return;
	}
	
	list_for_each_entry(entry, &stn->rate_changes, list) {
		fprintf(f, "%ld.%06ld %d %d\n", entry->time.tv_sec, entry->time.tv_usec,
			entry->new_rate, entry->wlan_seqno);
	}

	fclose(f);
}

static void
dump_80211bg_rates(struct station *stn)
{
	FILE *f;
	int i, tot;
	int r[12] = { 2, 4, 11, 12, 18, 22, 24, 36, 48, 72, 96, 108 };
	f = fopen("/tmp/rates80211bg.dat", "w");
	if (f == NULL) {
		perror("fopen 80211bg rates");
		return;
	}

	tot = 0;
	for (i=0;i<12;i++)
		tot += stn->legacy_num_packets[r[i]];


	fprintf(f,"%5s %11s %s\n", "Rate", "Num packets", "Per cent");

	for (i=0;i<12;i++) {
		fprintf(f, "%5d %11ld %8.2f\n",
		r[i] * 1000 / 2,
		stn->legacy_num_packets[r[i]],
		(stn->legacy_num_packets[r[i]] / (float)tot) * 100.0
		);
	}
	
	fclose(f);
}

static void
dump_80211n_rates(struct station *stn)
{
	FILE *f;
	int i;
	f = fopen("/tmp/rates80211n.dat", "w");
	if (f == NULL) {
		perror("fopen 80211n rates");
		return;
	}
	fprintf(f, " MCS  -- Long GI  --    -- Short GI --\n");
	fprintf(f, "Index 20MHz    40MHz    20MHz    40MHz\n");

	for (i=0; i<32; i++) {
		fprintf(f, "%2d %8ld %8ld %8ld %8ld\n",
			i,
			stn->mcs_num_packets[i][0],
			stn->mcs_num_packets[i][1],
			stn->mcs_num_packets[i][2],
			stn->mcs_num_packets[i][3]

			);
	}


	fclose(f);
}

static void
dump_losses(struct station *stn)
{
	struct loss *entry;
	FILE *f;
	f = fopen("/tmp/losses.dat", "w");
	if (f == NULL) {
		perror("fopen losses");
		return;
	}

	list_for_each_entry(entry, &(stn->losses), list) {
		fprintf(f, "%ld.%06ld %d\n",
			entry->time.tv_sec, entry->time.tv_usec,
			entry->num_lost);
	}

	fclose(f);


}

static void
dump_retry_chains(struct station *stn)
{
	struct retry *entry;
	FILE *f;
	char buf[1024];
	int i,n;

	f = fopen("/tmp/retries.dat", "w");
	if (f == NULL) {
		perror("fopen retries");
		return;
	}

	list_for_each_entry(entry, &(stn->retry_stat.retries), list) {
		n = snprintf(buf, 1024, "%ld.%06ld %4d %d %d",
			entry->time.tv_sec, entry->time.tv_usec,
			entry->wlan_seqno,
			entry->num_retries,
			entry->original_rate);
		for (i=0;i<entry->num_retries;i++) {
			n += snprintf(&buf[n], 1024 - n, " %d",
				entry->retry_chain[i]);
		}

		fprintf(f, "%s\n", buf);
	}

	fclose(f);

}

static void
dump_statistics(struct station *stn)
{
	FILE *f;
	f = fopen("/tmp/statistics.dat", "w");
	if (f == NULL) {
		perror("fopen statistics");
		return;
	}

	fprintf(f, "Statistics for station %s\n",
		ether_sprintf(stn->wlan_srcmac));
	fprintf(f, "-------- Capture statistics --------\n");
	fprintf(f, "Captured :             %10ld\n",
		stn->received_packets[_DATA]);
	fprintf(f, "Estimated lost :       %10ld\n",
		stn->estimated_lost_packets);
	fprintf(f, "Captured retransmits : %10ld for %ld frames\n",
		stn->received_retransmits, stn->retransmitted_packets);
	fprintf(f, "Loss ratio :           %11.1f\n",
		(stn->estimated_lost_packets / (float)(stn->received_packets[_DATA] + stn->estimated_lost_packets)) * 100.0);
	
	fprintf(f, "-------- Rate Change statistics --------\n");
	fprintf(f, "Total Rate Changes :   %10d\n",
		stn->rate_change_stat.num_rate_changes);
	fprintf(f, "Changes rate more then one step? ");
	if (stn->rate_change_stat.rate_change_over_multiple_steps)
		fprintf(f, "yes, %d times.\n",
		stn->rate_change_stat.rate_change_over_multiple_steps);
	else
		fprintf(f, "no - amrr?\n");

	fprintf(f, "Maximum rate changes pr. second : %d\n",
		stn->rate_change_stat.max_rate_change_per_sec);
	fprintf(f, "Min time between change %10ld.%06ld seconds.\n",
		stn->rate_change_stat.min_time_between_rate_changes.tv_sec,
		stn->rate_change_stat.min_time_between_rate_changes.tv_usec);
	fprintf(f, "Min pkt between change  %10d\n",
		stn->rate_change_stat.min_pkt_between_rate_changes);


	fprintf(f, "-------- Sample statistics --------\n");
	fprintf(f, "Total Samples :        %10d\n",
		stn->sample_stat.num_samples);
	fprintf(f, "Sampling ratio :       %f\n",
		(stn->sample_stat.num_samples / (float)(stn->sample_stat.num_samples +
		stn->received_packets[_DATA])) * 100.0);
	fprintf(f, "Minimum frames between samples : %d\n",
		stn->sample_stat.min_frames_between_samples);

	fprintf(f, "-------- Control statistics --------\n");
	fprintf(f, "Num RTS :              %10ld\n",
		stn->ctrl_stat.num_rts);
	fprintf(f, "Num CTS :              %10ld\n",
		stn->ctrl_stat.num_cts);

	
	fprintf(f, "-------- Retry statistics --------\n");
	fprintf(f, "Max num retries :      %10d\n",
		stn->retry_stat.max_num_retries);

	fclose(f);
}

static void
dump_station_stats(struct station *stn)
{
	dump_samples(stn);
	dump_rate_changes(stn);
	dump_80211bg_rates(stn);
	dump_80211n_rates(stn);
	dump_statistics(stn);
	dump_losses(stn);
	dump_retry_chains(stn);
}



static void
exit_handler(void)
{
	view_main_exit();
	fprintf(stderr, "Exiting...\n");

	pcap_close(conf.descr);


	struct station *stn = list_first_entry(&stations, struct station, list);

	dump_station_stats(stn);

	free_lists();
}

static void
sigint_handler(int sig) {
	exit(0);
}

static void
sigpipe_handler(int sig) {

}


int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *filtermac;

	conf.dev = argv[1];
	filtermac = argv[2];

	INIT_LIST_HEAD(&stations);

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigpipe_handler);
	atexit(exit_handler);

	if(conf.dev == NULL)
	{
		printf("%s\n",errbuf);
		exit(1);
	}

	DEBUG("DEV: %s\n",conf.dev);

	conf.descr = pcap_open_live(conf.dev,BUFSIZ,10, DISPLAY_UPDATE_INTERVAL / 1000,errbuf);

	if(conf.descr == NULL)
	{
		printf("pcap_open_live(): %s\n",errbuf);
		exit(1);
	}
	
	conf.arphrd = device_get_arptype(pcap_fileno(conf.descr), conf.dev);


	if (conf.arphrd != ARPHRD_IEEE80211_RADIOTAP) {
		printf("Wrong monitor type! Please use radiotap headers\n");
                exit(1);
        }

#define FILTER
#ifdef FILTER
	char buf[128];
	snprintf(buf, sizeof(buf), "wlan host %s", filtermac);
	/* Lets add a filter */
	if (pcap_compile(conf.descr, &conf.fp, buf,
	   0, 0) == -1) {
		fprintf(stderr, "Could not compile filter...\n");
		exit(1);
	}
	DEBUG("Setting filter: %s\n", buf);
	if (pcap_setfilter(conf.descr, &conf.fp) == -1) {
		fprintf(stderr, "Could not apply filter....\n");
		exit(1);
	}
	pcap_freecode(&conf.fp);
#endif


	create_station(filtermac);

#ifdef DO_DEBUG
	pcap_loop(conf.descr, 0, pcap_callback, NULL);
#else
#ifdef DEBUGPKT
	pcap_loop(conf.descr, 0, pcap_callback, NULL);
#else
	view_main_setup();

	struct pcap_pkthdr *pkt_hdr;
	const u_char *data;

	view_main_set_active_station(list_first_entry(&stations, struct station, list));


	for (; /* ever */ ;) {
		int res = pcap_next_ex(conf.descr, &pkt_hdr, &data);
		switch (res) {
		case 1: /* Successfully read packet */
			pcap_callback(NULL, pkt_hdr, data);
			break;
		case 0: /* timeout expired */
			break;
		case -1:
		case -2:
			break;
		}

		view_main_update();
	}
#endif
#endif
	return 0;
}
