/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "includes/headers.p4"
#include "includes/parser.p4"

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    	input {
        	ipv4_checksum_list;
    	}
    	algorithm : csum16;
    	output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    	verify ipv4_checksum;
    	update ipv4_checksum;
}

action _drop() {
    	drop();
}

header_type custom_metadata_t {
    	fields {
        	nhop_ipv4: 32;
    	}
}

metadata custom_metadata_t custom_metadata;

header_type meta_t {
	fields {
		meter_tag : 32;
	}
}

metadata meta_t meter_meta;

action set_nhop(nhop_ipv4, port) {
    	modify_field(custom_metadata.nhop_ipv4, nhop_ipv4);
    	modify_field(standard_metadata.egress_spec, port);
    	add_to_field(ipv4.ttl, -1);
}

action set_dmac(dmac) {
    	modify_field(ethernet.dstAddr, dmac);
}

meter ip_meter {
   	type: packets;
   	static: meter_table;
    	instance_count: 1024;
}

action meter_action(index) {
	execute_meter(ip_meter, index, meter_meta.meter_tag);
}

table meter_table {
    	reads {
		ipv4.srcAddr : lpm;
    	}
    	actions {
        	meter_action;
        	_drop;
    	}
    	size : 1024;
}

counter ip_src_counter {
    type: packets;
    static: count_table;
    instance_count: 1024;
}

action count_action(index) {
        count(ip_src_counter, index);
}

table count_table {
    reads {
        ipv4.srcAddr : lpm;
	meter_meta.meter_tag : exact;
    }
    actions {
        count_action;
        _drop;
    }
    size : 1024;
}

table ipv4_lpm {
    	reads {
        	ipv4.dstAddr : lpm;
    	}
    	actions {
        	set_nhop;
        	_drop;
    	}
    	size: 1024;
}

table forward {
    	reads {
        	custom_metadata.nhop_ipv4 : exact;
    	}
    	actions {
        	set_dmac;
        	_drop;
    	}
    	size: 512;
}

action rewrite_mac(smac) {
    	modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    	reads {
        	standard_metadata.egress_port: exact;
    	}
    	actions {
        	rewrite_mac;
        	_drop;
    	}
    	size: 256;
}

control ingress {
    	apply(meter_table);
	apply(ipv4_lpm);
  	apply(forward);
	apply(count_table);
}

control egress {
    	apply(send_frame);
}
