Project 3: Wiretap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Name: Sri Laxmi Chintala
uname: chintals
Name: Mrunal M Pagnis
uname: mmpagnis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Contents:
~~~~~~~~~

1. Introduction
2. Files used
3. Description of code
4. Implementation

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1. Introduction:
~~~~~~~~~~~~~~~

Wiretap is an analysis routine similar to TCP Dump and Wireshark. It analyses and prints the
statistics of a pcap capture file when given as input. 

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
2. Files used:
~~~~~~~~~~~~~

wiretap.c 			: 					This is the program that processes the input .pcap file and prints the statistics.

time.h				:					The C date and time operations are defined in this header 
										file.

pcap.h				:					It has the functions of Packet Capture Library.

arpa/inet.h			:					It includes the definitions for internet operations. 

linux/if_ether.h	:					It is an include file for a list of allowed protocols. 

net/ethernet.h		:					It includes fundamental constants, structures and functions 
										related to Ethernet.
	
netinet/ip.h		:					This header file includes definitions of and structures for 
										Internet Protocol version 4(IPv4).

netinet/tcp.h		:					It has definitions for the Internet Transmission Control Protocol(TCP).

netinet/udp.h		:					It contains definitions and User Datagram Protocol(UDP) header structure.

netinet/ether.h		:					It consists of members: Types(these are structures related to ethernet 
										header and ethernet address and Macros(these are definitions).

netinet/in.h		:					It has types and macros related to Internet Protocol family.

netinet/ip_icmp.h	:					This header has all the definitions and structures related to 
										Interface Control Message Protocol(ICMP).

Files used for testing:
~~~~~~~~~~~~~~~~~~~~~~~

traceroute.pcap		:					A traceroute (primarily UDP traffic and some ARP)

wget.pcap			:					Downloads of two websites (TCP traffic with some UDP and ARP)

tcp.pcap            :                   Mainly for TCP and UDP capture packets

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
3. Description of code
~~~~~~~~~~~~~~~~~~~~~~

Wiretap program takes a file containing tcp dump data as its input and outputs the statistics into a file.

In this project we used the Packet Capture Library and the functions in the header file, pcap.h to 
read the data. For this project we used 3 functions and a callback function which are listed below:

1. pcap_open_offline()	:	An input file is opened using this function.
 
2. pcap_datalink()		:	This function returns the link-layer header type for the live capture. For this 
							project we have captured only Ethernet data.
					
3. pcap_loop()			:	In this program, pcap_loop() is called twice for individual purposes. It takes 4 arguments. 
							In the first call this function calls callback(), function in which packet summary for each 
							packet is processed and then handle is closed. 
							Again the same file is opened using pcap_open_offline(), then the pcap_loop() is called which in 
							turn calls the sniffPackets(). In this function statistics of different layers and the 
							protocols captured are processed.
							Both callback() and sniffPackets() act as callback functions.
							
4. callback()			:	In this callback function, packet summary of the capture is processed. It includes:
							capture start date, duration, number of packets captured, minimum packet size, maximum packet 
							size and average packet size.
							
5. sniffPackets()		:	This function process the statistics related to Link layer, Network layer and Transport layer.
							The function stores the addresses in dynamically allocated buffers. Theses buffers are used to 
							compare the addresses. Three types of counters are used with respect to each functionality. 
							A counter that iterates on packets. A counter that counts the unique number of addresses and/or 
							protocols and the third type of counter array which is corresponding to each unique address 
							and/or protocol.
						
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
4. Implementation
~~~~~~~~~~~~~~~~~

This project is implemented in C language. 

The commands for compiling and running the program are as follows:

Compile
~~~~~~~
Compile the program by including the pcap library -lpcap as first argument for the compiler:

gcc -lpcap wiretap.c -o wiretap
~~~~~~~~~~~~~~~~~~~~~~

The program is run by specifying options --help or --open.
Run the program by giving the following command. 

./wiretap --open traceroute.pcap

The output is saved into a text file named "statistics.txt"

For usage you may run as
./wiretap --help

This will print the usage. 

Any other command otherwise specified in the README will yeild the usage on standard display.