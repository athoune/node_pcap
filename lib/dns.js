// helpers for DNS decoder
var dns_util = {
    type_to_string: function (type_num) {
        switch (type_num) {
        case 1:
            return "A";
        case 2:
            return "NS";
        case 3:
            return "MD";
        case 4:
            return "MF";
        case 5:
            return "CNAME";
        case 6:
            return "SOA";
        case 7:
            return "MB";
        case 8:
            return "MG";
        case 9:
            return "MR";
        case 10:
            return "NULL";
        case 11:
            return "WKS";
        case 12:
            return "PTR";
        case 13:
            return "HINFO";
        case 14:
            return "MINFO";
        case 15:
            return "MX";
        case 16:
            return "TXT";
        default:
            return ("Unknown (" + type_num + ")");
        }
    },
    qtype_to_string: function (qtype_num) {
        switch (qtype_num) {
        case 252:
            return "AXFR";
        case 253:
            return "MAILB";
        case 254:
            return "MAILA";
        case 255:
            return "*";
        default:
            return dns_util.type_to_string(qtype_num);
        }
    },
    class_to_string: function (class_num) {
        switch (class_num) {
        case 1:
            return "IN";
        case 2:
            return "CS";
        case 3:
            return "CH";
        case 4:
            return "HS";
        default:
            return "Unknown (" + class_num + ")";
        }
    },
    qclass_to_string: function (qclass_num) {
        if (qclass_num === 255) {
            return "*";
        } else {
            return dns_util.class_to_string(qclass_num);
        }
    },
    expandRRData: function(raw_packet, offset, rrRecord) {
        if(rrRecord.rrtype == 'A' && rrRecord.rrclass == 'IN' && rrRecord.rdlength == 4) {
            var data = {};
            data.ipAddress = raw_packet[offset] + '.' + raw_packet[offset+1] + '.' + raw_packet[offset+2] + '.' + raw_packet[offset+3];
            return data;
        }

        return null;
    },48a7c112ab898a8584bb028f6df452f73be666a2
    readName: function(raw_packet, offset, internal_offset, result) {
        if(offset + internal_offset > raw_packet.pcap_header.len) {
            throw new Error("Malformed DNS RR. Offset is larger than the size of the packet (readName).");
        }

        var lenOrPtr = raw_packet[offset + internal_offset];
        internal_offset++;
        if(lenOrPtr == 0x00) {
            return result;
        }

        if((lenOrPtr & 0xC0) == 0xC0) {
            var nameOffset = ((lenOrPtr & ~0xC0) << 8) | raw_packet[offset + internal_offset];
            internal_offset++;
            return dns_util.readName(raw_packet, offset, nameOffset, result);
        }

        for(var i=0; i<lenOrPtr; i++) {
            var ch = raw_packet[offset + internal_offset];
            internal_offset++;
            result += String.fromCharCode(ch);
        }
        result += '.';
        return dns_util.readName(raw_packet, offset, internal_offset, result);
    },
    decodeRR: function(raw_packet, offset, internal_offset, result) {
        if(internal_offset > raw_packet.pcap_header.len) {
            throw new Error("Malformed DNS RR. Offset is larger than the size of the packet (decodeRR). offset: " + offset + ", internal_offset: " + internal_offset + ", packet length: " + raw_packet.pcap_header.len);
        }
        var compressedName = raw_packet[internal_offset];
        if((compressedName & 0xC0) == 0xC0) {
            result.name = "";
            result.name = dns_util.readName(raw_packet, offset, internal_offset - offset, result.name);
            result.name = result.name.replace(/\.$/, '');
            internal_offset += 2;
        } else {
            result.name = "";
            var ch;
            while((ch = raw_packet[internal_offset++]) != 0x00) {
                result.name += String.fromCharCode(ch);
            }
        }

        result.rrtype = dns_util.qtype_to_string(unpack.uint16(raw_packet, internal_offset));
        internal_offset += 2;
        result.rrclass = dns_util.qclass_to_string(unpack.uint16(raw_packet, internal_offset));
        internal_offset += 2;
        result.ttl = unpack.uint32(raw_packet, internal_offset);
        internal_offset += 4;
        result.rdlength = unpack.uint16(raw_packet, internal_offset);
        internal_offset += 2;

        var data = dns_util.expandRRData(raw_packet, internal_offset, result);
        if(data) {
            result.data = data;
        }

        // skip rdata. TODO: store the rdata somewhere?
        internal_offset += result.rdlength;
        return internal_offset;
    },
    decodeRRs: function(raw_packet, offset, internal_offset, count, results) {
        for (i = 0; i < count; i++) {
            results[i] = {};
            internal_offset = dns_util.decodeRR(raw_packet, offset, internal_offset, results[i]);
        }
        return internal_offset;
    }
};

exports.dns_util = dns_util;

// cache reverse DNS lookups for the life of the program
var dns_cache = (function () {
    var cache = {},
        requests = {};

    function lookup_ptr(ip, callback) {
        if (cache[ip]) {
            return cache[ip];
        }
        else {
            if (! requests[ip]) {
                requests[ip] = true;
                dns.reverse(ip, function (err, domains) {
                    if (err) {
                        cache[ip] = ip;
                        // TODO - check for network and broadcast addrs, since we have iface info
                    } else {
                        cache[ip] = domains[0];
                        if (typeof callback === 'function') {
                            callback(domains[0]);
                        }
                    }
                    delete requests[ip];
                });
            }
            return ip;
        }
    }

    return {
        ptr: function (ip, callback) {
            return lookup_ptr(ip, callback);
        }
    };
}());
exports.dns_cache = dns_cache;


