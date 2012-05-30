# Snort Log Parser

This Ruby code parses Snort log files related to a VeRSI project for VU. The log files are taken from a VPN server that has mobile devices connected to it. This parser takes encrypted incoming requests from mobile devices and tries to match them against an unencrypted outgoing requests.

It does this matching (in a fairly dodgy way) by looking at the packet length of an encrypted incoming packet, and finding a corresponding outgoing packet that is 41 bytes shorter.

# Creating the log files

Use a command like the following to start logging with snort:
  
    snort -dev -l ./log_directory

Use a command like the following to create a plain text version of a binary log file:
  
    snort -dv -r snort_binary.log.1336714497 > snort_plain_text.log

# Running the parser

The `Analyser#analyse` function in the main entry point. Look at the rspec tests for an example usage.

Use the rake command to run the rspec tests:

    rake

The analyser can also run from the command line:

    ruby lib/analyse.rb snort_input_file openpaths_json_file user_ip_address

# An example usage

Here is an example of running through the procedure of gathering data and analysing it.

## Start Time/Date

Make a note of the start date and time:

    ~ 11:06 am 15/5/2012 (local Mac Laptop time)
    ~ Tue May 15 01:06:23 UTC 2012 (VPN Time)

## Connect mobile device to VPN

Connect your device to the PopTop VPN. We've got one running on the NeCTAR cloud at 115.146.94.29.

## Make sure OpenPaths is running on mobile device

We're using OpenPaths to collect location data for the mobile device.

## SSH to VPN

    ssh -l ubuntu -i ~/.ssh/jared_vpn.pem 115.146.94.29

## Output of `last` on VPN

Now that the mobile device is connected to the VPN you can run `last` to see who is logged in and what their IP address is:

    ubuntu   pts/2        glong.versi.unim Tue May 15 01:05   still logged in   
    gdlong   ppp0         1.139.60.94      Tue May 15 01:02   still logged in

(Ran `last` again and actual IP is 1.139.177.134)

## Get the time on the VPN

Run `date` to get the VPN machine's time.

## Change to root

    sudo -i

## Make a log directory

    mkdir log_20120515

## Start snort

    snort.bin -dev -l ./log_20120515

## Use the mobile device

Make sure its still connected to the VPN, and navigate to some web pages. For example at the following times I went to the following websites:

* 11:12am - Twitter App
* 11:12am - Facebook App
* 11:14am - ABC App
* 11:14am - Instagram App
* 11:15am - The Age Website (Safari)

## Stop snort

    ^c

### Output

    ===============================================================================
    Run time for packet processing was 291.34068 seconds
    Snort processed 11682 packets.
    Snort ran for 0 days 0 hours 4 minutes 51 seconds
       Pkts/min:         2920
       Pkts/sec:           40
    ===============================================================================
    Packet I/O Totals:
       Received:        11682
       Analyzed:        11682 (100.000%)
        Dropped:            0 (  0.000%)
       Filtered:            0 (  0.000%)
    Outstanding:            0 (  0.000%)
       Injected:            0
    ===============================================================================
    Breakdown by protocol (includes rebuilt packets):
            Eth:        11682 (100.000%)
           VLAN:            0 (  0.000%)
            IP4:        11675 ( 99.940%)
           Frag:            0 (  0.000%)
           ICMP:           29 (  0.248%)
            UDP:          157 (  1.344%)
            TCP:         6112 ( 52.320%)
            IP6:            2 (  0.017%)
        IP6 Ext:            2 (  0.017%)
       IP6 Opts:            0 (  0.000%)
          Frag6:            0 (  0.000%)
          ICMP6:            2 (  0.017%)
           UDP6:            0 (  0.000%)
           TCP6:            0 (  0.000%)
         Teredo:            0 (  0.000%)
        ICMP-IP:            0 (  0.000%)
          EAPOL:            0 (  0.000%)
        IP4/IP4:            0 (  0.000%)
        IP4/IP6:            0 (  0.000%)
        IP6/IP4:            0 (  0.000%)
        IP6/IP6:            0 (  0.000%)
            GRE:         5260 ( 45.027%)
        GRE Eth:            0 (  0.000%)
       GRE VLAN:            0 (  0.000%)
        GRE IP4:            0 (  0.000%)
        GRE IP6:            0 (  0.000%)
    GRE IP6 Ext:            0 (  0.000%)
       GRE PPTP:         5260 ( 45.027%)
        GRE ARP:            0 (  0.000%)
        GRE IPX:            0 (  0.000%)
       GRE Loop:            0 (  0.000%)
           MPLS:            0 (  0.000%)
            ARP:            0 (  0.000%)
            IPX:            0 (  0.000%)
       Eth Loop:            0 (  0.000%)
       Eth Disc:            0 (  0.000%)
       IP4 Disc:            0 (  0.000%)
       IP6 Disc:            0 (  0.000%)
       TCP Disc:            0 (  0.000%)
       UDP Disc:            0 (  0.000%)
      ICMP Disc:            0 (  0.000%)
    All Discard:            0 (  0.000%)
          Other:          122 (  1.044%)
    Bad Chk Sum:          381 (  3.261%)
        Bad TTL:            0 (  0.000%)
         S5 G 1:            0 (  0.000%)
         S5 G 2:            0 (  0.000%)
          Total:        11682
    ===============================================================================



## Convert the snort log to text

    snort.bin -dvC -r log_20120515/snort.log.1337044274 > log_20120515/snort.log.1337044274.txt
    tar -zvcf log_20120515.tgz log_20120515
    mv log_20120515.tgz ~ubuntu
    cd ~ubuntu
    chown ubuntu log_20120515.tgz
    exit
    exit

## Copy the log file to the local PC
    
    scp ubuntu@115.146.94.29:/home/ubuntu/log_20120515.tgz .
    tar -zvxf

## Get the openpaths data

You can download the location data for your mobile device from https://openpaths.cc/


## Run analyse.rb

Run analyse. The usage is:

    ruby analyse.rb snort_input_file openpaths_json_file user_ip_address

So, for example:

    ruby analyse.rb traffic_data/log_20120515/snort.log.1337044274.txt location_data/openpaths_gregorydavidlong.json 1.139.177.134

A list of datagrams with their corresponding locations for the nominated mobile device IP address should be displayed.


# Future enhancements

* Make the output neater and easier to read
* Add graphical data visualisation
* Finish incomplete unit tests
* Add automatic parsing of output from `last` command for selection of IP address. This will also require adding a date range for which we are interested in the IP address.
* Add parsing of KML location data
