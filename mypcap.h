/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2020, 2022

    File Name:          mypcap.h

       N E V E R       M O D I F Y      T H I S      F I L E

---------------------------------------------------------------------------*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <arpa/inet.h>

/* The Template of a PCAP file 
    +------------+------------+-------------+------------+-------------+--------+
    | Global Hdr | packet Hdr | packet data | packet Hdr | packet data |  ....  |
    +------------+------------+-------------+------------+-------------+--------+
*/

#define PROTO_IPv4  0x0800
#define PROTO_ARP   0x0806

#define PROTO_ICMP  1
#define PROTO_TCP   6
#define PROTO_UDP   17

#define ARPREQUEST 1
#define ARPREPLY   2

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0

#define MAXIPv4ADDRLEN  (15+1)
#define MAXMACADDRLEN   (18+1)
#define MAXFRAMESZ      (6+6+2+9000)
#define MAXETHTYPENAME  10
#define MAXPROTONAMELEN  9
#define MAXARPMAP       20
#define ETHERNETHLEN     6

/*-------------------------------------------------------------------------*/
/* The global header of the pcap file */
typedef struct __attribute__((__packed__)) 
{
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

/*-------------------------------------------------------------------------*/
/* The header of each captured packet */
typedef struct __attribute__((__packed__)) 
{
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} packetHdr_t;


/*-------------------------------------------------------------------------*/
/* The Ethernet II Frame Header */
typedef struct __attribute__((__packed__))  
{
    uint8_t  eth_dstMAC[ETHERNETHLEN] ,
             eth_srcMAC[ETHERNETHLEN] ;
    uint16_t eth_type; /* 46<=eth_type<=1500 ? Payload Len : Protocol */ 
} etherHdr_t ;

/*-------------------------------------------------------------------------*/
typedef union{
    uint32_t    ip;
    uint8_t     byte[4] ;
} IPv4addr ;

/*-------------------------------------------------------------------------*/
/* The ARP Message Layout */
typedef struct __attribute__((__packed__))  
{
    uint16_t arp_htype ,    // Hardware type
             arp_ptype ;    // Protocol Type
    uint8_t  arp_hlen  ,    // Hardware address length
             arp_plen  ;    // Protocol address length 
    uint16_t arp_oper  ;    // Operation: 1=Request, 2=Reply
    uint8_t  arp_sha[ETHERNETHLEN] ;   // Sender HW address
    IPv4addr arp_spa ;      // Sender Protocol Address
    uint8_t  arp_tha[ETHERNETHLEN] ;   // Target HW address
    IPv4addr arp_tpa ;      // Target Protocol Address
} arpMsg_t ;

/*-------------------------------------------------------------------------*/
/* The IPv4 Header Layout 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct __attribute__((__packed__))  
{
    uint8_t  ip_verHlen ;       // Version (4bits) : HeaderLen (4bits) 
    uint8_t  ip_dscpEcn ;       // Differentiated Services Code Point(6bits) : 
                                // Explicit Congestion Notification (2bits)
    uint16_t ip_totLen ,        // Total Length: header + data
             ip_id     ,        // Identification
             ip_flagsFrag ;     // Flags (3bits) : Fragment Offset(13bits)
    uint8_t  ip_ttl ,           // Time To Live
             ip_proto ;         // Payload Protocol
    uint16_t ip_hdrChk ;        // Header Checksum

    IPv4addr ip_srcIP ,     // Source IP address
             ip_dstIP ;     // Destination IP address

    // variable-size Options start here
    // The following array adds no more bytes to this struct, but captures 
    // the starting address of the options section if any.    
    uint8_t  options[0] ;  

} ipv4Hdr_t ;

/*-------------------------------------------------------------------------*/
/* The ICMP Header Layout
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Identifier           |          Sequence Num         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct __attribute__((__packed__))  
{
    uint8_t  icmp_type ;        // Msg Type 
    uint8_t  icmp_code ;        // Msg Code
    uint16_t icmp_check;        // Msg Checksum
    uint8_t  icmp_line2[4] ;    // layout depends on type/Code

    // Variable-size data section
    // The following array adds no more bytes to this struct, but captures 
    // the starting address of the options section if any.    
    uint8_t  data[0] ;  

} icmpHdr_t ;

/*-------------------------------------------------------------------------*/
/*           Interface Functions */

/*-------------------------*/
/*        pre-PROJECT 1        */
/*-------------------------*/
void      errorExit( char *str ) ;
void      cleanUp() ;
int       readPCAPhdr( char *fname , pcap_hdr_t *p ) ;
void      printPCAPhdr( const pcap_hdr_t * ) ;
bool      getNextPacket( packetHdr_t *p , uint8_t  ethFrame[]  ) ;
void      printPacketMetaData( const packetHdr_t*   ) ;
void      printPacket( const etherHdr_t * ) ;

/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/
char     *macToStr( const uint8_t *p , char *buf  ) ;
