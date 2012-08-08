#ifndef _STATISTICS_H_
#define _STATISTICS_H_

#include "main.h"

void statistics_handle_packet(struct station *stn, struct packet_info *p);

void statistics_handle_data_packet(struct station *stn, struct packet_info *p);
void statistics_handle_ctrl_packet(struct station *stn, struct packet_info *p);
void statistics_handle_mgmt_packet(struct station *stn, struct packet_info *p);


#endif
