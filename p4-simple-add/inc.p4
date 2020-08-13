#include <core.p4>
#include <v1model.p4>

/*
P4_inc header format - custom header for sending and receiving packets for aggregation

byte:	0		1		2		3
+---------------+---------------+---------------+---------------+
|	P	|	4	|    Version	|      bos	|
+---------------+---------------+---------------+---------------+
|			       data				|
+---------------+---------------+---------------+---------------+
|			      result				|
+---------------+---------------+---------------+---------------+
*/

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t; // to give a name to macAddr
typedef bit<32> ip4Addr_t; // to give a name to ipv4 addresses
typedef bit<9> egressSpec_t;

// CONST variables, just like macros or const in C
const bit<16> P4INC_ETYPE = 0x1234; // ethernet type
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> P4INC_P = 0x50; // ascii 'P'
const bit<8> P4INC_4 = 0x34; // ascii '4'
const bit<8> P4INC_VER = 0x01; // version 1.0

// headers definition
header p4inc_t
{
	bit<8> p; // 'P'
	bit<8> four; // '4'
	bit<8> ver; // version 1.0
	bit<8> bos; // bos = 1 means this is the last packet
	bit<32> data; // payload to aggregate
	bit<32> result; // aggregated data 
}

header ipv4_t
{
	bit<4> version;
	bit<4> ihl;
	bit<8> diffserv;
	bit<16> totalLen;
	bit<16> identification;
	bit<3> flags;
	bit<13> fragOffset;
	bit<8> ttl;
	bit<8> protocol;
	bit<16> hdrChecksum;
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
}
	

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}


struct metadata {
    /* empty */
}

// headers struct will save all the headers we want to use for each packet
struct headers {
    ethernet_t	ethernet;
    ipv4_t	ipv4;
    p4inc_t	p4inc;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// parse incoming packets and get them valid for processing by control
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

	// check to make sure we're using the right ethernet type
	state start
	{
		packet.extract(hdr.ethernet);

		transition select(hdr.ethernet.etherType)
		{
			TYPE_IPV4	:	parse_ipv4;
			default		:	accept;
		}

	}

	// grab the ipv4 header
	state parse_ipv4
	{
		packet.extract(hdr.ipv4);
		
		transition check_p4inc;
	}

	// make sure the p4inc header is formatted correctly
	state check_p4inc
	{
		transition select(packet.lookahead<p4inc_t>().p,
		packet.lookahead<p4inc_t>().four,
		packet.lookahead<p4inc_t>().ver)
		{
			(P4INC_P, P4INC_4, P4INC_VER)	:	parse_p4inc;
			default				:	accept;
		}
	}

	// grab the p4inc header
	state parse_p4inc
	{
		packet.extract(hdr.p4inc);
		transition accept;
	}
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

	register<bit<32>>(1) result_reg; // will save the aggregated data between packets
	
	// drop a packet if unsure what to do with it
	action drop_packet()
	{
		mark_to_drop(standard_metadata);
	}
	
	// clear the aggregated data whenever bos reached, e.g. clear after every data set
	action clear_reg()
	{
		result_reg.write(0, 0);
	}

	action write_replace()
	{
		bit<32> tmp;
		result_reg.read(tmp, 0);
		result_reg.write(0, hdr.p4inc.data + tmp);
	} 

	action forward_to_host(macAddr_t dstAddr, egressSpec_t port)
	{
		bit<32> tmp;

		write_replace(); // each packet we want to aggregate

		result_reg.read(tmp, 0); // read the aggregated data into tmp variable

		// when bos reached we want to setup the packet to be forwarded
		if(hdr.p4inc.bos == 1)
		{	
			// send the packet to the host
			// port and dstAddr are defined in the switch json file based on forwarding rules
			hdr.p4inc.result = tmp;
			standard_metadata.egress_spec = port;
			hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
			hdr.ethernet.dstAddr = dstAddr;
			hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
		}
	}

	// table used to forward packets to server
	table ipv4_tbl
	{
		key = 
		{
			hdr.ipv4.dstAddr: lpm;
		}
		actions = 
		{
			forward_to_host;
			drop_packet;
			NoAction;
		}
		size = 1024;
		default_action = drop_packet();
	}

	// table used to clear the result_reg when a bos is reached
	table bos_hash
	{
		key = 
		{
			hdr.p4inc.bos: exact;
		}
		actions = 
		{
			clear_reg;
			NoAction;
		}
		default_action = NoAction();
		const entries = 
		{
			0x0	:	NoAction();
			0x1	:	clear_reg();
		}
	}


	apply
	{	
		if(hdr.p4inc.isValid())
		{
			ipv4_tbl.apply();
			bos_hash.apply(); // apply both tables to the packet
		}
		else
		{
			drop_packet();
		}
	}

    
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
	apply{/*empty*/ }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {

    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4);
	packet.emit(hdr.p4inc); // emit the headers and send the packets off
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
