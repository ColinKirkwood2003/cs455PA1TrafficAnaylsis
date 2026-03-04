/* ------------------------------------------------------------------------
    CS-455  Advanced Computer Networking
    Simplified Packet Analysis Programming Projects
    Designed By:        Dr. Mohamed Aboutabl  (c) 2026
    
    Implemented By:     Diego Navia
    File Name:          mypcap.c

---------------------------------------------------------------------------*/

#include "mypcap.h"

/*-----------------   GLOBAL   VARIABLES   --------------------------------*/
FILE       *pcapInput  =  NULL ;        // The input PCAP file
bool        bytesOK ;   // Does the capturer's byte ordering same as mine?
                        // Affects the global PCAP header and each packet's header

bool        microSec ;  // is the time stamp in Sec + microSec ?  or in Sec + nanoSec ?

double      baseTime ;  // capturing time (in seconds ) of the very 1st packet in this file
bool        baseTimeSet = false ;
static uint16_t swap16(uint16_t v);
static uint32_t swap32(uint32_t v);

/* ***************************** */
/*          PROJECT 1            */
/* ***************************** */

/*-------------------------------------------------------------------------*/
void errorExit( char *str )
{
    if (str) puts(str) ;
    if ( pcapInput  )  fclose ( pcapInput  ) ;
    exit( EXIT_FAILURE );
}

/*-------------------------------------------------------------------------*/
void cleanUp( )
{
    if ( pcapInput  )  fclose ( pcapInput  ) ;
}

/*-------------------------------------------------------------------------*/
/*  Open the input PCAP file 'fname' 
    and read its global header into buffer 'p'
    Side effects:    
        - Set the global FILE *pcapInput to the just-opened file
        - Properly set the global flags: bytesOK  and   microSec
        - If necessary, reorder the bytes of all globap PCAP header 
          fields except for the magic_number

    Remember to check for incuming NULL pointers

    Returns:  0 on success
             -1 on failure  */

int readPCAPhdr( char *fname , pcap_hdr_t *p)
{
	// Check for incoming NULL pointers
    if ( !fname || !p )
    {
        return -1;
    }

	// Successfully open the input 'fname'
    pcapInput = fopen ( fname, "rb" );

    if ( !pcapInput )
    {
        fclose( pcapInput );
        return -1;
    }

    //read input into the golbal header
    if ( fread ( p, sizeof ( pcap_hdr_t ), 1, pcapInput ) != 1 )
    {
        fclose( pcapInput );
        pcapInput = NULL;
        return -1;
    }

    // Determine the capturer's byte ordering
    // Issue: magic_number could also be 0xa1b23c4D to indicate nano-second 
    // resolution instead of microseconds. This affects the interpretation
    // of the ts_usec field in each packet's header.

     switch (p->magic_number)
    {
        case 0xA1B2C3D4:   /* normal endian microseconds */
            bytesOK = true;
            microSec = true;
            break;

        case 0xD4C3B2A1:   /* swapped endian microseconds */
            bytesOK = false;
            microSec = true;
            break;

        case 0xA1B23C4D:   /* normal endian nanoseconds */
            bytesOK = true;
            microSec = false;
            break;

        case 0x4D3CB2A1:   /* swapped endian nanoseconds */
            bytesOK = false;
            microSec = false;
            break;

        default:
            return -1; /* invalid pcap file */
    }
    
    if (!bytesOK)
    {
        p->version_major = swap16(p->version_major);
        p->version_minor = swap16(p->version_minor);
        p->thiszone      = swap32(p->thiszone);
        p->sigfigs       = swap32(p->sigfigs);
        p->snaplen       = swap32(p->snaplen);
        p->network       = swap32(p->network);
    }

    return 0;
}

/*-------------------------------------------------------------------------*/
/* Print the global header of the PCAP file from buffer 'p'                */
void printPCAPhdr( const pcap_hdr_t *p ) 
{
    printf("magic number %X\n"                           , p->magic_number );    

    printf("major version %u\n"                          , p->version_major );
    printf("minor version %u\n"                          , p->version_minor );
    printf("GMT to local correction %d seconds\n"        , p->thiszone );
    printf("accuracy of timestamps %u\n"                 , p->sigfigs );
    printf("Cut-off max length of captured packets %u\n" , p->snaplen );
    printf("data link type %u\n"                         , p->network );
}

/*-------------------------------------------------------------------------*/
/*  Read the next packet (Header and entire ethernet frame) 
    from the previously-opened input  PCAP file 'pcapInput'
    Must check for incoming NULL pointers and incomplete frame payload
    
    If this is the very first packet from the PCAP file, set the baseTime 
    
    Returns true on success, or false on failure for any reason */

bool getNextPacket( packetHdr_t *p , uint8_t  ethFrame[]  )
{
    // Check for incoming NULL pointers
    if ( !p || !ethFrame || !pcapInput || p->incl_len > MAXFRAMESZ)
    {
        return false;
    }

    // Read the header of the next paket in the PCAP file
    if ( fread( p, sizeof(packetHdr_t), 1, pcapInput ) != 1)
    {
        return false;
    }

    /* Did the capturer use a different
    byte-ordering than mine (as determined by the magic number)? */
    if( ! bytesOK )   
    {
        // reorder the bytes of the fields in this packet header
        p->ts_sec   = swap32(p->ts_sec);
        p->ts_usec  = swap32(p->ts_usec);
        p->incl_len = swap32(p->incl_len);
        p->orig_len = swap32(p->orig_len);

    }
    
    // Read 'incl_len' bytes from the PCAP file into the ethFrame[]
    if ( fread( ethFrame, 1, p->incl_len, pcapInput ) != p->incl_len )
    {
        return false;
    }

    // If necessary, set the baseTime .. Pay attention to possibility of nano second 
    // time precision (instead of micro seconds )
    double pTime;

    if ( microSec )
    {
        pTime = p->ts_sec + p->ts_usec / 1000000.0;
    }
    else
    {
        pTime = p->ts_sec + p->ts_usec / 1000000000.0;
    }
    if ( !baseTimeSet )
    {
        baseTime = pTime;
        baseTimeSet = true;
    }
    
    return true ;
}


/*-------------------------------------------------------------------------*/
/* print packet's capture time (realative to the base time),
   the priginal packet's length in bytes, and the included length */
   
void printPacketMetaData( const packetHdr_t *p  )
{
    double pTime;

    if ( microSec )
    {
        pTime = p->ts_sec + p->ts_usec / 1000000.0;
    }
    else
    {
        pTime = p->ts_sec + p->ts_usec / 1000000000.0;
    }

    printf( "%14.6f %6u / %6u ", pTime - baseTime, p->orig_len, p->incl_len );
}

/*-------------------------------------------------------------------------*/
/* print ARP information */
void printARPinfo( const arpMsg_t *arp )
{
    if (!arp) return;

    uint16_t op = ntohs(arp->arp_oper);

    char spa[MAXIPv4ADDRLEN];
    char tpa[MAXIPv4ADDRLEN];
    char sha[MAXMACADDRLEN];

    ipToStr(arp->arp_spa, spa);
    ipToStr(arp->arp_tpa, tpa);
    macToStr(arp->arp_sha, sha);

    if (op == ARPREQUEST)
    {
        printf("Who has %s ? Tell %s", tpa, spa);
    }
    else if (op == ARPREPLY)
    {
        printf("%s is at %s", spa, sha);
    }
}

/*-------------------------------------------------------------------------*/
/* print IP information */
void printIPinfo( const ipv4Hdr_t *ip )
{
    if (!ip) return;

    char srcIP[MAXIPv4ADDRLEN];
    char dstIP[MAXIPv4ADDRLEN];

    ipToStr(ip->ip_srcIP, srcIP);
    ipToStr(ip->ip_dstIP, dstIP);

    printf("%-20s %-20s ", srcIP, dstIP);

    // Compute header length
    unsigned ihl = (ip->ip_verHlen & 0x0F) * 4;
    unsigned optionsLen = ihl - 20;

    printf("IP_HDR{ Len=%u incl. %u options bytes} ",
           ihl, optionsLen);

    if (ip->ip_proto == PROTO_ICMP)
    {
        printf("%-8s ", "ICMP");

        const icmpHdr_t *icmp =
            (const icmpHdr_t *)((const uint8_t *)ip + ihl);

        unsigned dataLen = printICMPinfo(icmp);
        printf(" AppData=%5u", dataLen);
    }
    else if (ip->ip_proto == PROTO_TCP)
    {
        printf("%-8s AppData=%5u", "TCP", 0);
    }
    else if (ip->ip_proto == PROTO_UDP)
    {
        printf("%-8s AppData=%5u", "UDP", 0);
    }
}

/*-------------------------------------------------------------------------*/
/* Print the packet's captured data starting with its ethernet frame header
   and moving up the protocol hierarchy */ 

void printPacket( const etherHdr_t *frPtr )
{
    // Null pointer checker
    if (!frPtr)
    {
        return;
    }

    char srcMAC[MAXMACADDRLEN];
    char dstMAC[MAXMACADDRLEN];

    // print Source/Destination MAC addresses REFACTORED, replaced with above
    // char src[18];
    // char dst[18];

    printf("%-20s %-20s ", macToStr(frPtr->eth_srcMAC, srcMAC), macToStr(frPtr->eth_dstMAC, dstMAC));

    // -------------------------------P1 modifications start here-------------------------------------------
    uint16_t etherType = ntohs(frPtr -> eth_type); // Extract the type from the hdr

    // Depending on type, we print a packet differently.
    // ARP and IPv4 are the allowed ones for now. Maybe refactor for switch statement instead
    if (etherType == PROTO_ARP)
    {
        printf("%-8s ", "ARP");

        const arpMsg_t *arpPtr =
            (const arpMsg_t *)((const uint8_t *)frPtr + sizeof(etherHdr_t));

        printARPinfo(arpPtr);
    }
    else if (etherType == PROTO_IPv4)
    {
        const ipv4Hdr_t *ipPtr =
            (const ipv4Hdr_t *)((const uint8_t *)frPtr + sizeof(etherHdr_t));

        printIPinfo(ipPtr);
    }
    else
    {
        printf("Unknown\n"); // Debugging purposes for now, not permanent
    }

}


/*-------------------------------------------------------------------------*/
/*               Suggested Utility Functions                               */
/*-------------------------------------------------------------------------*/


/*-------------------------------------------------------------------------*/
/*  Convert a MAC address to the format xx:xx:xx:xx:xx:xx 
    in the caller-provided 'buf' whose maximum 'size' is given
    Returns 'buf'  */

char *macToStr( const uint8_t *p , char *buf )
{
    sprintf( buf,"%02x:%02x:%02x:%02x:%02x:%02x", p[0],p[1],p[2],p[3],p[4],p[5] );
    return buf;
}

// Helper function to swap a 16 byte chunk of data to opposite endian order
static uint16_t swap16( uint16_t v )
{
    return (v >> 8) | (v << 8);
}

// Helper function to reverse order of a 32 byte chunk of data to opposite endian order
static uint32_t swap32( uint32_t v )
{
    return ((v >> 24) & 0x000000FF) | ((v >> 8)  & 0x0000FF00) | ((v << 8)  & 0x00FF0000) | ((v << 24) & 0xFF000000);
}

// Helper function to parse IP address to string readable
char *ipToStr( const IPv4addr ip , char *ipStr )
{
    sprintf(ipStr, "%u.%u.%u.%u",
        ip.byte[0], ip.byte[1],
        ip.byte[2], ip.byte[3]);

    return ipStr;
}