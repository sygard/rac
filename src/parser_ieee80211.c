#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>

#include "main.h"
#include "parser.h"
#include "util.h"
#include "ieee80211.h"

int
ieee80211_get_hdrlen(u16 fc)
{
        int hdrlen = 24;

        switch (fc & IEEE80211_FCTL_FTYPE) {
        case IEEE80211_FTYPE_DATA:
                if ((fc & IEEE80211_FCTL_FROMDS) && (fc & IEEE80211_FCTL_TODS))
                        hdrlen = 30; /* Addr4 */
                /*
                 * The QoS Control field is two bytes and its presence is
                 * indicated by the IEEE80211_STYPE_QOS_DATA bit. Add 2 to
                 * hdrlen if that bit is set.
                 * This works by masking out the bit and shifting it to
                 * bit position 1 so the result has the value 0 or 2.
                 */
                hdrlen += (fc & IEEE80211_STYPE_QOS_DATA) >> 6;
                break;
        case IEEE80211_FTYPE_CTL:
                /*
                 * ACK and CTS are 10 bytes, all others 16. To see how
                 * to get this condition consider
                 *   subtype mask:   0b0000000011110000 (0x00F0)
                 *   ACK subtype:    0b0000000011010000 (0x00D0)
                 *   CTS subtype:    0b0000000011000000 (0x00C0)
                 *   bits that matter:         ^^^      (0x00E0)
                 *   value of those: 0b0000000011000000 (0x00C0)
                 */
                if ((fc & 0xE0) == 0xC0)
                        hdrlen = 10;
                else
                        hdrlen = 16;
                break;
        }

        return hdrlen;
}


int
parse_80211_header(const u_char* buf, int len, struct packet_info* p)
{
	struct ieee80211_hdr* wh;
	int hdrlen;
	uint8_t *sa = NULL;
	uint8_t *da = NULL;
	u16 fc;

	if (len < 2)
		return -1;

	wh = (struct ieee80211_hdr*)buf;
	fc = le16toh(wh->frame_control);
	hdrlen = ieee80211_get_hdrlen(fc);

	DEBUG("len %d hdrlen %d\n", len, hdrlen);

	if (len < hdrlen)
		return -1;

	p->wlan_len = len;
	p->wlan_type = (fc & (IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE));



	switch (p->wlan_type & IEEE80211_FCTL_FTYPE) {
	case IEEE80211_FTYPE_DATA:
		p->pkt_types = PKT_TYPE_DATA;

                switch (p->wlan_type & IEEE80211_FCTL_STYPE) {
                case IEEE80211_STYPE_NULLFUNC:
                        p->pkt_types |= PKT_TYPE_NULL;
                        break;
                case IEEE80211_STYPE_QOS_DATA:
                        /* TODO: ouch, should properly define a qos header */
                        p->wlan_qos_class = wh->addr4[0] & 0x7;
                        DEBUG("***QDATA %x\n", p->wlan_qos_class);
                        break;
                }

		sa = ieee80211_get_SA(wh);
		da = ieee80211_get_DA(wh);

		p->wlan_seqno = le16toh(wh->seq_ctrl) / 16;

		if (fc & IEEE80211_FCTL_PROTECTED)
			p->wlan_wep = 1;
		if (fc & IEEE80211_FCTL_RETRY)
			p->wlan_retry = 1;
		break;
	case IEEE80211_FTYPE_CTL:
		p->pkt_types = PKT_TYPE_CTRL;
		DEBUG("CTL\n");
		switch (p->wlan_type & IEEE80211_FCTL_STYPE) {
		case IEEE80211_STYPE_RTS:
			p->pkt_types |= PKT_TYPE_RTS;
			p->wlan_nav = le16toh(wh->duration_id);
			DEBUG("RTS NAV %d\n", p->wlan_nav);
			sa = wh->addr2;
			da = wh->addr1;
			break;

		case IEEE80211_STYPE_CTS:
			p->pkt_types |= PKT_TYPE_CTS;
			p->wlan_nav = le16toh(wh->duration_id);
			DEBUG("CTS NAV %d\n", p->wlan_nav);
			da = wh->addr1;
			break;

		case IEEE80211_STYPE_ACK:
			p->pkt_types |= PKT_TYPE_ACK;
			p->wlan_nav = le16toh(wh->duration_id);
			DEBUG("ACK NAV %d\n", p->wlan_nav);
			da = wh->addr1;
			break;

		case IEEE80211_STYPE_PSPOLL:
			sa = wh->addr2;
			break;

		case IEEE80211_STYPE_CFEND:
			da = wh->addr1;
			sa = wh->addr2;
			break;

		case IEEE80211_STYPE_CFENDACK:
			/* dont know, dont care */
			break;
		}

		break;
	
	case IEEE80211_FTYPE_MGMT:
		p->pkt_types = PKT_TYPE_MGMT;
		DEBUG("MGMT\n");
		break;
	}

	if (sa != NULL) {
		memcpy(p->wlan_src, sa, 6);
		DEBUG("SA    %s\n", ether_sprintf(sa));
	}
	if (da != NULL) {
		memcpy(p->wlan_dst, da, 6);
		DEBUG("DA    %s\n", ether_sprintf(da));
	}

	DEBUG("%s\n", get_packet_type_name(fc));

	return 0;
}

