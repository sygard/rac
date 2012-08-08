rac
===

Rate Adaptation Classifier (RAC)


This is the Rate Adaptation Classifier (RAC) which passively listens to data
traffic between wireless stations. Based on the observed traffic, RAC performs
logging and statistics. The final output of the application can be used to
classify the rate adaptation algorithm used by the observed wireless device.
RAC can be used on any platform which exports the correct headers to user-space
through the PCAP framework. RAC has the ability to listen and analyse any
IEEE 802.11b/g wireless network and contains code to perform basic statistics
on IEEE 802.11n.

RAC captures and logs the important pieces of observed data traffic and is not
affected by the encryption used by the wireless network. RAC is only interested
in the Physical (PHY) and some Link-Layer information exported by the monitor
interface.


compile
=======

Enter the src directory and type:
 # make

For a debug build, type:
 # make debugpkt
This will build the application without the ui.


usage
=====

USAGE: ./rac <phydev> <station mac address>

NB: The application need to be ran as root.

On exit, the application writes the following files to /tmp/

* losses.dat: Log of estimated lost frames. This is losses to the capture
    process, not necessarily losses between the station and the access point.
    The file contains two columns, the first is unix time, the second is
    the estimated number of lost frames.
* rate_changes.dat: This file contains the rate changes seen during the capture
    process. First column is unix time, second is the new bit-rate and the
    third is the sequence number on the first frame seen with this bit-rate.
* rates80211bg.dat: This file contains the number of frames seen for the
    different 802.11 legacy bit-rates. First column is the bit-rate, second is
    the number of frames and the last is the frame count in percent to the
    total of frames.
rates80211n.dat: This file contains the distribution of IEEE 802.11n frames
    seen. The file has five columns. The first is the MCS index. The second and
    third column is the number of captured frames for the long Guard Interval
    (GI) frames in 20MHz and 40MHz channel widths. Column four and five
    represents the number of frames received for the short GI, 20MHz and
    40MHz channel widths.
* retries.dat: This file contains captures retransmission rates. The file
    contains the time, the original bit-rate and the bit-rate of the
    retransmitted frames. First column is unix time, second is the total number
    of retransmissions, third column is the original frames bit-rate and the
    rest of the column is the bit-rate of every retransmission. If a frame has
    been retransmitted four times, there will be four columns following the
    three first.
* samples.dat: This file contains captured samples. The file structure is unix
    time in the first column and the bit-rate of the captured sample in the
    second.
* statistics.dat: This file is a dump of the statistics kept by RAC. The
    statistics kept are:
        * Number of captured frames
        * Estimated lost frames
        * Captured retransmits
        * Loss ratio
        * Total number of rate changes
        * How many rate changes which change more than one rate step
        * Maximum rate changes per second
        * Minimum time between rate changes
        * Minimum number of frames between rate changes
        * Total number of samples
        * Sampling ratio
        * Minimum number of frames between samples
        * Number of RTS frames
        * Number of CTS frames
        * Maximum number of retransmissions for a single frame
