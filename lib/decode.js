var dns_util = require('./dns').dns_util,
    unpack   = require('./unpack').unpack;

var decode = {}; // convert raw packet data into JavaScript objects with friendly names

exports.decode = decode;

decode.packet = function (raw_packet) {
    var packet = {};

    packet.link_type = raw_packet.pcap_header.link_type;
    switch (packet.link_type) {
        case "LINKTYPE_ETHERNET":
            packet.link = decode.ethernet(raw_packet, 0);
            break;
        case "LINKTYPE_NULL":
            packet.link = decode.nulltype(raw_packet, 0);
            break;
        case "LINKTYPE_RAW":
            packet.link = decode.rawtype(raw_packet, 0);
            break;
        case "LINKTYPE_IEEE802_11_RADIO":
            packet.link = decode.ieee802_11_radio(raw_packet, 0);
            break;
        default:
            console.log("pcap.js: decode.packet() - Don't yet know how to decode link type " + raw_packet.pcap_header.link_type);
    }

    packet.pcap_header = raw_packet.pcap_header; // TODO - merge values here instead of putting ref on packet buffer

    return packet;
};

decode.rawtype = function (raw_packet, offset) {
    var ret = {};

    ret.ip = decode.ip(raw_packet, 0);

    return ret;
};

decode.nulltype = function (raw_packet, offset) {
    var ret = {};

    // an oddity about nulltype is that it starts with a 4 byte header, but I can't find a
    // way to tell which byte order is used.  The good news is that all address family
    // values are 8 bits or less.

    if (raw_packet[0] === 0 && raw_packet[1] === 0) { // must be one of the endians
        ret.pftype = raw_packet[3];
    } else {                                          // and this is the other one
        ret.pftype = raw_packet[0];
    }

    if (ret.pftype === 2) {         // AF_INET, at least on my Linux and OSX machines right now
        ret.ip = decode.ip(raw_packet, 4);
    } else if (ret.pftype === 30) { // AF_INET6, often
        ret.ip = decode.ip6(raw_packet, 4);
    } else {
        console.log("pcap.js: decode.nulltype() - Don't know how to decode protocol family " + ret.pftype);
    }

    return ret;
};

decode.ethernet = function (raw_packet, offset) {
    var ret = {};

    ret.dhost = unpack.ethernet_addr(raw_packet, 0);
    ret.shost = unpack.ethernet_addr(raw_packet, 6);
    ret.ethertype = unpack.uint16(raw_packet, 12);
    offset = 14;

    // Check for a tagged frame
    switch (ret.ethertype) {
        case 0x8100: // VLAN-tagged (802.1Q)
            ret.vlan = decode.vlan(raw_packet, 14);

            // Update the ethertype
            ret.ethertype = unpack.uint16(raw_packet, 16);
            offset = 18;
            break;
    }

    if (ret.ethertype < 1536) {
        // this packet is actually some 802.3 type without an ethertype
        ret.ethertype = 0;
    } else {
        // http://en.wikipedia.org/wiki/EtherType
        switch (ret.ethertype) {
            case 0x800: // IPv4
                ret.ip = decode.ip(raw_packet, offset);
                break;
            case 0x806: // ARP
                ret.arp = decode.arp(raw_packet, offset);
                break;
            case 0x86dd: // IPv6 - http://en.wikipedia.org/wiki/IPv6
                ret.ipv6 = decode.ip6(raw_packet, offset);
                break;
            case 0x88cc: // LLDP - http://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol
                ret.lldp = "need to implement LLDP";
                break;
            default:
                console.log("pcap.js: decode.ethernet() - Don't know how to decode ethertype " + ret.ethertype);
        }
    }

    return ret;
};

decode.ieee802_11_radio = function (raw_packet, offset) {
    var ret = {};
    var original_offset = offset;

    ret.headerRevision = raw_packet[offset++];
    ret.headerPad = raw_packet[offset++];
    ret.headerLength = unpack.uint16_be(raw_packet, offset); offset += 2;

    offset = original_offset + ret.headerLength;

    ret.ieee802_11Frame = decode.ieee802_11_frame(raw_packet, offset);

    if(ret.ieee802_11Frame && ret.ieee802_11Frame.llc && ret.ieee802_11Frame.llc.ip) {
        ret.ip = ret.ieee802_11Frame.llc.ip;
        delete ret.ieee802_11Frame.llc.ip;
        ret.shost = ret.ieee802_11Frame.shost;
        delete ret.ieee802_11Frame.shost;
        ret.dhost = ret.ieee802_11Frame.dhost;
        delete ret.ieee802_11Frame.dhost
    }

    return ret;
};

decode.ieee802_11_frame = function (raw_packet, offset) {
    var ret = {};

    ret.frameControl = unpack.uint16_be(raw_packet, offset); offset += 2;
    ret.type = (ret.frameControl >> 2) & 0x0003;
    ret.subType = (ret.frameControl >> 4) & 0x000f;
    ret.flags = (ret.frameControl >> 8) & 0xff;
    ret.duration = unpack.uint16_be(raw_packet, offset); offset += 2;
    ret.bssid = unpack.ethernet_addr(raw_packet, offset); offset += 6;
    ret.shost = unpack.ethernet_addr(raw_packet, offset); offset += 6;
    ret.dhost = unpack.ethernet_addr(raw_packet, offset); offset += 6;
    ret.fragSeq = unpack.uint16_be(raw_packet, offset); offset += 2;

    switch(ret.subType) {
        case 8: // QoS Data
            ret.qosPriority = raw_packet[offset++];
            ret.txop = raw_packet[offset++];
            break;
    }

    if(ret.type == 2 && ret.subType == 4) {
        // skip this is Null function (No data)
    }
    else if(ret.type == 2 && ret.subType == 12) {
        // skip this is QoS Null function (No data)
    }
    else if(ret.type == 2 && ret.subType == 7) {
        // skip this is CF-Ack/Poll
    }
    else if(ret.type == 2 && ret.subType == 6) {
        // skip this is CF-Poll (No data)
    }
    else if(ret.type == 2) { // data
        ret.llc = decode.logicalLinkControl(raw_packet, offset);
    }

    return ret;
};

decode.logicalLinkControl = function (raw_packet, offset) {
    var ret = {};

    ret.dsap = raw_packet[offset++];
    ret.ssap = raw_packet[offset++];
    if(((ret.dsap == 0xaa) && (ret.ssap == 0xaa))
            || ((ret.dsap == 0x00) && (ret.ssap == 0x00))) {
                ret.controlField = raw_packet[offset++];
                ret.orgCode = [
                    raw_packet[offset++],
                    raw_packet[offset++],
                    raw_packet[offset++]
                        ];
                ret.type = unpack.uint16(raw_packet, offset); offset += 2;

                switch(ret.type) {
                    case 0x0800: // ip
                        ret.ip = decode.ip(raw_packet, offset);
                        break;
                }
            } else {
                throw new Error("Unknown LLC types: DSAP: " + ret.dsap + ", SSAP: " + ret.ssap);
            }

    return ret;
}

decode.vlan = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/IEEE_802.1Q
    ret.priority = (raw_packet[offset] & 0xE0) >> 5;
    ret.canonical_format = (raw_packet[offset] & 0x10) >> 4;
    ret.id = ((raw_packet[offset] & 0x0F) << 8) | raw_packet[offset + 1];

    return ret;
};

decode.arp = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/Address_Resolution_Protocol
    ret.htype = unpack.uint16(raw_packet, offset); // 0, 1
    ret.ptype = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.hlen = raw_packet[offset + 4];
    ret.plen = raw_packet[offset + 5];
    ret.operation = unpack.uint16(raw_packet, offset + 6); // 6, 7
    if (ret.operation === 1) {
        ret.operation = "request";
    }
    else if (ret.operation === 2) {
        ret.operation = "reply";
    }
    else {
        ret.operation = "unknown";
    }
    if (ret.hlen === 6 && ret.plen === 4) { // ethernet + IPv4
        ret.sender_ha = unpack.ethernet_addr(raw_packet, offset + 8); // 8, 9, 10, 11, 12, 13
        ret.sender_pa = unpack.ipv4_addr(raw_packet, offset + 14); // 14, 15, 16, 17
        ret.target_ha = unpack.ethernet_addr(raw_packet, offset + 18); // 18, 19, 20, 21, 22, 23
        ret.target_pa = unpack.ipv4_addr(raw_packet, offset + 24); // 24, 25, 26, 27
    }
    // don't know how to decode more exotic ARP types

    return ret;
};

decode.ip = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/IPv4
    ret.version = (raw_packet[offset] & 240) >> 4; // first 4 bits
    ret.header_length = raw_packet[offset] & 15; // second 4 bits
    ret.header_bytes = ret.header_length * 4;
    ret.diffserv = raw_packet[offset + 1];
    ret.total_length = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.identification = unpack.uint16(raw_packet, offset + 4); // 4, 5
    ret.flags = {};
    ret.flags.reserved = (raw_packet[offset + 6] & 128) >> 7;
    ret.flags.df = (raw_packet[offset + 6] & 64) >> 6;
    ret.flags.mf = (raw_packet[offset + 6] & 32) >> 5;
    ret.fragment_offset = ((raw_packet[offset + 6] & 31) * 256) + raw_packet[offset + 7]; // 13-bits from 6, 7
    ret.ttl = raw_packet[offset + 8];
    ret.protocol = raw_packet[offset + 9];
    ret.header_checksum = unpack.uint16(raw_packet, offset + 10); // 10, 11
    ret.saddr = unpack.ipv4_addr(raw_packet, offset + 12); // 12, 13, 14, 15
    ret.daddr = unpack.ipv4_addr(raw_packet, offset + 16); // 16, 17, 18, 19

    // TODO - parse IP "options" if header_length > 5
    switch (ret.protocol) {
        case 1:
            ret.protocol_name = "ICMP";
            ret.icmp = decode.icmp(raw_packet, offset + (ret.header_length * 4));
            break;
        case 2:
            ret.protocol_name = "IGMP";
            ret.igmp = decode.igmp(raw_packet, offset + (ret.header_length * 4));
            break;
        case 6:
            ret.protocol_name = "TCP";
            ret.tcp = decode.tcp(raw_packet, offset + (ret.header_length * 4), ret);
            break;
        case 17:
            ret.protocol_name = "UDP";
            ret.udp = decode.udp(raw_packet, offset + (ret.header_length * 4));
            break;
        default:
            ret.protocol_name = "Unknown";
    }
    return ret;
};

decode.ip6_header = function(raw_packet, next_header, ip, offset) {
    switch (next_header) {
        case 1:
            ip.protocol_name = "ICMP";
            ip.icmp = decode.icmp(raw_packet, offset);
            break;
        case 2:
            ip.protocol_name = "IGMP";
            ip.igmp = decode.igmp(raw_packet, offset);
            break;
        case 6:
            ip.protocol_name = "TCP";
            ip.tcp = decode.tcp(raw_packet, offset, ip);
            break;
        case 17:
            ip.protocol_name = "UDP";
            ip.udp = decode.udp(raw_packet, offset);
            break;
        default:
            // TODO: capture the extensions
            //decode.ip6_header(raw_packet, raw_packet[offset], offset + raw_packet[offset+1]);
    }
};

decode.ip6 = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/IPv6
    ret.version = (raw_packet[offset] & 240) >> 4; // first 4 bits
    ret.traffic_class = ((raw_packet[offset] & 15) << 4) + ((raw_packet[offset+1] & 240) >> 4);
    ret.flow_label = ((raw_packet[offset + 1] & 15) << 16) +
        (raw_packet[offset + 2] << 8) +
        raw_packet[offset + 3];
    ret.payload_length = unpack.uint16(raw_packet, offset+4);
    ret.total_length = ret.payload_length + 40;
    ret.next_header = raw_packet[offset+6];
    ret.hop_limit = raw_packet[offset+7];
    ret.saddr = unpack.ipv6_addr(raw_packet, offset+8);
    ret.daddr = unpack.ipv6_addr(raw_packet, offset+24);
    ret.header_bytes = 40;

    decode.ip6_header(raw_packet, ret.next_header, ret, offset+40);
    return ret;
};

decode.icmp = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    ret.type = raw_packet[offset];
    ret.code = raw_packet[offset + 1];
    ret.checksum = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.id = unpack.uint16(raw_packet, offset + 4); // 4, 5
    ret.sequence = unpack.uint16(raw_packet, offset + 6); // 6, 7

    switch (ret.type) {
        case 0:
            ret.type_desc = "Echo Reply";
            break;
        case 1:
        case 2:
            ret.type_desc = "Reserved";
            break;
        case 3:
            switch (ret.code) {
                case 0:
                    ret.type_desc = "Destination Network Unreachable";
                    break;
                case 1:
                    ret.type_desc = "Destination Host Unreachable";
                    break;
                case 2:
                    ret.type_desc = "Destination Protocol Unreachable";
                    break;
                case 3:
                    ret.type_desc = "Destination Port Unreachable";
                    break;
                case 4:
                    ret.type_desc = "Fragmentation required, and DF flag set";
                    break;
                case 5:
                    ret.type_desc = "Source route failed";
                    break;
                case 6:
                    ret.type_desc = "Destination network unknown";
                    break;
                case 7:
                    ret.type_desc = "Destination host unknown";
                    break;
                case 8:
                    ret.type_desc = "Source host isolated";
                    break;
                case 9:
                    ret.type_desc = "Network administratively prohibited";
                    break;
                case 10:
                    ret.type_desc = "Host administratively prohibited";
                    break;
                case 11:
                    ret.type_desc = "Network unreachable for TOS";
                    break;
                case 12:
                    ret.type_desc = "Host unreachable for TOS";
                    break;
                case 13:
                    ret.type_desc = "Communication administratively prohibited";
                    break;
                default:
                    ret.type_desc = "Destination Unreachable (unknown code " + ret.code + ")";
            }
            break;
        case 4:
            ret.type_desc = "Source Quench";
            break;
        case 5:
            switch (ret.code) {
                case 0:
                    ret.type_desc = "Redirect Network";
                    break;
                case 1:
                    ret.type_desc = "Redirect Host";
                    break;
                case 2:
                    ret.type_desc = "Redirect TOS and Network";
                    break;
                case 3:
                    ret.type_desc = "Redirect TOS and Host";
                    break;
                default:
                    ret.type_desc = "Redirect (unknown code " + ret.code + ")";
                    break;
            }
            break;
        case 6:
            ret.type_desc = "Alternate Host Address";
            break;
        case 7:
            ret.type_desc = "Reserved";
            break;
        case 8:
            ret.type_desc = "Echo Request";
            break;
        case 9:
            ret.type_desc = "Router Advertisement";
            break;
        case 10:
            ret.type_desc = "Router Solicitation";
            break;
        case 11:
            switch (ret.code) {
                case 0:
                    ret.type_desc = "TTL expired in transit";
                    break;
                case 1:
                    ret.type_desc = "Fragment reassembly time exceeded";
                    break;
                default:
                    ret.type_desc = "Time Exceeded (unknown code " + ret.code + ")";
            }
            break;
            // TODO - decode the rest of the well-known ICMP messages
        default:
            ret.type_desc = "type " + ret.type + " code " + ret.code;
    }

    // There are usually more exciting things hiding in ICMP packets after the headers
    return ret;
};

decode.igmp = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
    ret.type = raw_packet[offset];
    ret.max_response_time = raw_packet[offset + 1];
    ret.checksum = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.group_address = unpack.ipv4_addr(raw_packet, offset + 4); // 4, 5, 6, 7

    switch (ret.type) {
        case 0x11:
            ret.version = ret.max_response_time > 0 ? 2 : 1;
            ret.type_desc = "Membership Query"
                break;
        case 0x12:
            ret.version = 1;
            ret.type_desc = "Membership Report"
                break;
        case 0x16:
            ret.version = 2;
            ret.type_desc = "Membership Report"
                break;
        case 0x17:
            ret.version = 2;
            ret.type_desc = "Leave Group"
                break;
        case 0x22:
            ret.version = 3;
            ret.type_desc = "Membership Report"
                // TODO: Decode v3 message
                break;
        default:
            ret.type_desc = "type " + ret.type;
            break;
    }

    return ret;
}

decode.udp = function (raw_packet, offset) {
    var ret = {};

    // http://en.wikipedia.org/wiki/User_Datagram_Protocol
    ret.sport       = unpack.uint16(raw_packet, offset);        // 0, 1
    ret.dport       = unpack.uint16(raw_packet, offset + 2);    // 2, 3
    ret.length      = unpack.uint16(raw_packet, offset + 4);    // 4, 5
    ret.checksum    = unpack.uint16(raw_packet, offset + 6);    // 6, 7

    ret.data_offset = offset + 8;
    ret.data_end    = ret.length + ret.data_offset - 8;
    ret.data_bytes  = ret.data_end - ret.data_offset;

    // Follow tcp pattern and don't make a copy of the data payload
    // Therefore its only valid for this pass throught the capture loop
    if (ret.data_bytes > 0) {
        ret.data = raw_packet.slice(ret.data_offset, ret.data_end);
        ret.data.length = ret.data_bytes;
    }

    if (ret.sport === 53 || ret.dport === 53) {
        ret.dns = decode.dns(raw_packet, offset + 8);
    }

    return ret;
};

decode.tcp = function (raw_packet, offset, ip) {
    var ret = {}, option_offset, options_end;

    // http://en.wikipedia.org/wiki/Transmission_Control_Protocol
    ret.sport          = unpack.uint16(raw_packet, offset); // 0, 1
    ret.dport          = unpack.uint16(raw_packet, offset + 2); // 2, 3
    ret.seqno          = unpack.uint32(raw_packet, offset + 4); // 4, 5, 6, 7
    ret.ackno          = unpack.uint32(raw_packet, offset + 8); // 8, 9, 10, 11
    ret.data_offset    = (raw_packet[offset + 12] & 0xf0) >> 4; // first 4 bits of 12
    ret.header_bytes   = ret.data_offset * 4; // convenience for using data_offset
    ret.reserved       = raw_packet[offset + 12] & 15; // second 4 bits of 12
    ret.flags          = {};
    ret.flags.cwr      = (raw_packet[offset + 13] & 128) >> 7; // all flags packed into 13
    ret.flags.ece      = (raw_packet[offset + 13] & 64) >> 6;
    ret.flags.urg      = (raw_packet[offset + 13] & 32) >> 5;
    ret.flags.ack      = (raw_packet[offset + 13] & 16) >> 4;
    ret.flags.psh      = (raw_packet[offset + 13] & 8) >> 3;
    ret.flags.rst      = (raw_packet[offset + 13] & 4) >> 2;
    ret.flags.syn      = (raw_packet[offset + 13] & 2) >> 1;
    ret.flags.fin      = raw_packet[offset + 13] & 1;
    ret.window_size    = unpack.uint16(raw_packet, offset + 14); // 14, 15
    ret.checksum       = unpack.uint16(raw_packet, offset + 16); // 16, 17
    ret.urgent_pointer = unpack.uint16(raw_packet, offset + 18); // 18, 19
    ret.options        = {};

    option_offset = offset + 20;
    options_end = offset + (ret.data_offset * 4);
    while (option_offset < options_end) {
        switch (raw_packet[option_offset]) {
            case 0:
                option_offset += 1;
                break;
            case 1:
                option_offset += 1;
                break;
            case 2:
                ret.options.mss = unpack.uint16(raw_packet, option_offset + 2);
                option_offset += 4;
                break;
            case 3:
                ret.options.window_scale = Math.pow(2, (raw_packet[option_offset + 2]));
                option_offset += 3;
                break;
            case 4:
                ret.options.sack_ok = true;
                option_offset += 2;
                break;
            case 5:
                ret.options.sack = [];
                switch (raw_packet[option_offset + 1]) {
                    case 10:
                        ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
                        option_offset += 10;
                        break;
                    case 18:
                        ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
                        ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 10), unpack.uint32(raw_packet, option_offset + 14)]);
                        option_offset += 18;
                        break;
                    case 26:
                        ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
                        ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 10), unpack.uint32(raw_packet, option_offset + 14)]);
                        ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 18), unpack.uint32(raw_packet, option_offset + 22)]);
                        option_offset += 26;
                        break;
                    case 34:
                        ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 2), unpack.uint32(raw_packet, option_offset + 6)]);
                        ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 10), unpack.uint32(raw_packet, option_offset + 14)]);
                        ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 18), unpack.uint32(raw_packet, option_offset + 22)]);
                        ret.options.sack.push([unpack.uint32(raw_packet, option_offset + 26), unpack.uint32(raw_packet, option_offset + 30)]);
                        option_offset += 34;
                        break;
                    default:
                        console.log("Invalid TCP SACK option length " + raw_packet[option_offset + 1]);
                        option_offset = options_end;
                }
                break;
            case 8:
                ret.options.timestamp = unpack.uint32(raw_packet, option_offset + 2);
                ret.options.echo = unpack.uint32(raw_packet, option_offset + 6);
                option_offset += 10;
                break;
            default:
                throw new Error("Don't know how to process TCP option " + raw_packet[option_offset]);
        }
    }

    ret.data_offset = offset + ret.header_bytes;
    ret.data_end = offset + ip.total_length - ip.header_bytes;
    ret.data_bytes = ret.data_end - ret.data_offset;
    if (ret.data_bytes > 0) {
        // add a buffer slice pointing to the data area of this TCP packet.
        // Note that this does not make a copy, so ret.data is only valid for this current
        // trip through the capture loop.
        ret.data = raw_packet.slice(ret.data_offset, ret.data_end);
        ret.data.length = ret.data_bytes;
    }

    // automatic protocol decode ends here.  Higher level protocols can be decoded by using payload.
    return ret;
};

decode.dns = function (raw_packet, offset) {
    var ret = {}, i, internal_offset, question_done, len, parts;

    // http://tools.ietf.org/html/rfc1035
    ret.header = {};
    ret.header.id = unpack.uint16(raw_packet, offset); // 0, 1
    ret.header.qr = (raw_packet[offset + 2] & 128) >> 7;
    ret.header.opcode = (raw_packet[offset + 2] & 120) >> 3;
    ret.header.aa = (raw_packet[offset + 2] & 4) >> 2;
    ret.header.tc = (raw_packet[offset + 2] & 2) >> 1;
    ret.header.rd = raw_packet[offset + 2] & 1;
    ret.header.ra = (raw_packet[offset + 3] & 128) >> 7;
    ret.header.z = 0; // spec says this MUST always be 0
    ret.header.rcode = raw_packet[offset + 3] & 15;
    ret.header.qdcount = unpack.uint16(raw_packet, offset + 4); // 4, 5
    ret.header.ancount = unpack.uint16(raw_packet, offset + 6); // 6, 7
    ret.header.nscount = unpack.uint16(raw_packet, offset + 8); // 8, 9
    ret.header.arcount = unpack.uint16(raw_packet, offset + 10); // 10, 11

    internal_offset = offset + 12;

    ret.question = [];
    for (i = 0; i < ret.header.qdcount ; i += 1) {
        ret.question[i] = {};
        question_done = false;
        parts = [];
        while (!question_done && internal_offset < raw_packet.pcap_header.caplen) {
            len = raw_packet[internal_offset];
            if (len > 0) {
                parts.push(raw_packet.toString("ascii", internal_offset + 1, internal_offset + 1 + len));
            } else {
                question_done = true;
            }
            internal_offset += (len + 1);
        }
        ret.question[i].qname = parts.join('.');
        ret.question[i].qtype = dns_util.qtype_to_string(unpack.uint16(raw_packet, internal_offset));
        internal_offset += 2;
        ret.question[i].qclass = dns_util.qclass_to_string(unpack.uint16(raw_packet, internal_offset));
        internal_offset += 2;
    }

    ret.answer = [];
    if(ret.header.ancount > 100) {
        throw new Error("Malformed DNS record. Too many answers.");
    }
    internal_offset = dns_util.decodeRRs(raw_packet, offset, internal_offset, ret.header.ancount, ret.answer);

    ret.authority = [];
    if(ret.header.ancount > 100) {
        throw new Error("Malformed DNS record. Too many authorities.");
    }
    internal_offset = dns_util.decodeRRs(raw_packet, offset, internal_offset, ret.header.nscount, ret.authority);

    ret.additional = [];
    if(ret.header.ancount > 100) {
        throw new Error("Malformed DNS record. Too many additional.");
    }
    internal_offset = dns_util.decodeRRs(raw_packet, offset, internal_offset, ret.header.arcount, ret.additional);

    return ret;
};

