/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// IPv4の定義
const bit<16> TYPE_IPV4 = 0x800;
// MRIオプションの定義
const bit<5> IPV4_OPTION_MRI = 31;

/* IP protocols */
// プロトコルの定義
const bit<8> IP_PROTOCOLS_ICMP       =   1;
const bit<8> IP_PROTOCOLS_IGMP       =   2;
const bit<8> IP_PROTOCOLS_IPV4       =   4;
const bit<8> IP_PROTOCOLS_TCP        =   6;
const bit<8> IP_PROTOCOLS_UDP        =  17;
const bit<8> IP_PROTOCOLS_IPV6       =  41;
const bit<8> IP_PROTOCOLS_GRE        =  47;
const bit<8> IP_PROTOCOLS_IPSEC_ESP  =  50;
const bit<8> IP_PROTOCOLS_IPSEC_AH   =  51;
const bit<8> IP_PROTOCOLS_ICMPV6     =  58;
const bit<8> IP_PROTOCOLS_EIGRP      =  88;
const bit<8> IP_PROTOCOLS_OSPF       =  89;
const bit<8> IP_PROTOCOLS_PIM        = 103;
const bit<8> IP_PROTOCOLS_VRRP       = 112;

#define MAX_HOPS 9

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<32> qdepth_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header vlan_t {
    bit<3> priority;
    bit<1> dei;
    bit<12> id;
    bit<16> etherType;
}

// tos部分をdiffservとecnに分けて定義
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    //bit<8>    tos;
    bit<6>    diffserv;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

header mri_t {
    bit<16> count;
}

header switch_t {
    switchID_t swid;
    qdepth_t qdepth;
}

struct ingress_metadata_t {
    bit<16> count;
}

struct parser_metadata_t {
    bit<16> remaining;
}

struct metadata {
    ingress_metadata_t ingress_metadata;
    parser_metadata_t parser_metadata;
}

// ヘッダーが持つ型を定義
struct headers {
    ethernet_t   ethernet;
    vlan_t	 vlan;
    ipv4_t       ipv4;
    ipv4_option_t ipv4_option;
    mri_t	 mri;
    switch_t[MAX_HOPS] swtraces;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// パーサーとはパケットのヘッダーとメタデータをマッピングする機能のこと

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
	    0x8100: parse_vlan;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_vlan {
	packet.extract(hdr.vlan);
	transition select(hdr.vlan.etherType) {
	    TYPE_IPV4: parse_ipv4;
	    default: accept;
	}
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.ihl) {
	    5		: accept;
	    default	: parse_ipv4_option;
	}
    }

    state parse_ipv4_option {
	packet.extract(hdr.ipv4_option);
	transition select(hdr.ipv4_option.option) {
	    IPV4_OPTION_MRI: parse_mri;
	    default: accept;
	}
    }

    state parse_mri {
	packet.extract(hdr.mri);
	meta.parser_metadata.remaining = hdr.mri.count;
	transition select(meta.parser_metadata.remaining){
	    0 : accept;
	    default : parse_swtrace;
	}
    }

    state parse_swtrace {
	packet.extract(hdr.swtraces.next);
	meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
	transition select(meta.parser_metadata.remaining){
	    0 : accept;
	    default : parse_swtrace;
	}
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
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action switching(bit<9> port) {
	standard_metadata.egress_spec = port;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

/* TODO: Implement actions for different traffic classes */

    action default_forwarding(){
	hdr.ipv4.diffserv = 0;
    }

    action expedited_forwarding(){
	hdr.ipv4.diffserv = 46;
    }

    action voice_admit(){
	hdr.ipv4.diffserv = 44;
    }

    action af_11(){
	hdr.ipv4.diffserv = 10;
    }

    action af_12(){
	hdr.ipv4.diffserv = 12;
    }

    action af_13(){
	hdr.ipv4.diffserv = 14;
    }

    action af_21(){
	hdr.ipv4.diffserv = 18;
    }

    action af_22(){
	hdr.ipv4.diffserv = 20;
    }

    action af_23(){
	hdr.ipv4.diffserv = 22;
    }

    action af_31(){
	hdr.ipv4.diffserv = 26;
    }

    action af_32(){
	hdr.ipv4.diffserv = 28;
    }

    action af_33(){
	hdr.ipv4.diffserv = 30;
    }

    action af_41(){
	hdr.ipv4.diffserv = 34;
    }

    action af_42(){
	hdr.ipv4.diffserv = 36;
    }

    action af_43(){
	hdr.ipv4.diffserv = 38;
    }

    table mac_exact {
	key = { hdr.ethernet.dstAddr: exact; }
	actions = {
	    switching;
	    drop;
	}
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


/* TODO: set hdr.ipv4.diffserv on the basis of protocol */
    apply {

        if ( !hdr.vlan.isValid() ) {
            mac_exact.apply();
        } else {
            drop();
        }

        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.protocol == IP_PROTOCOLS_UDP){
		expedited_forwarding();
	    }
	    else if (hdr.ipv4.protocol == IP_PROTOCOLS_TCP){
		voice_admit();
	    }
	    ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action add_swtrace(switchID_t swid){
	hdr.mri.count = hdr.mri.count + 1;
	hdr.swtraces.push_front(1);
	hdr.swtraces[0].setValid();
	hdr.swtraces[0].swid = swid;
	hdr.swtraces[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth;

	hdr.ipv4.ihl = hdr.ipv4.ihl + 2;
	hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 8;
	hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
    }

    table swtrace {
	actions = {
	    add_swtrace;
	    NoAction;
	}
	default_action = NoAction();
    }

    apply {
	if (hdr.mri.isValid()) {
	    swtrace.apply();
	}
    }
}


/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        /* TODO: replace tos with diffserv and ecn */
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              //hdr.ipv4.tos,
	      hdr.ipv4.diffserv,
	      hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
	packet.emit(hdr.vlan);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.ipv4_option);
	packet.emit(hdr.mri);
	packet.emit(hdr.swtraces);
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
