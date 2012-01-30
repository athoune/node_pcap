var print = {}; // simple printers for common types

print.dns = function (packet) {
    var ret = " DNS", dns = packet.link.ip.udp.dns;

    if (dns.header.qr === 0) {
        ret += " question";
    } else if (dns.header.qr === 1) {
        ret += " answer";
    } else {
        return " DNS format invalid: qr = " + dns.header.qr;
    }

    ret += " " + dns.question[0].qname + " " + dns.question[0].qtype;

    return ret;
};

print.ip = function (packet) {
    var ret = "",
        ip = packet.link.ip;

    switch (ip.protocol_name) {
    case "TCP":
        ret += " " + dns_cache.ptr(ip.saddr) + ":" + ip.tcp.sport + " -> " + dns_cache.ptr(ip.daddr) + ":" + ip.tcp.dport +
            " TCP len " + ip.total_length + " [" +
            Object.keys(ip.tcp.flags).filter(function (v) {
                if (ip.tcp.flags[v] === 1) {
                    return true;
                }
                return false;
            }).join(",") + "]";
        break;
    case "UDP":
        ret += " " + dns_cache.ptr(ip.saddr) + ":" + ip.udp.sport + " -> " + dns_cache.ptr(ip.daddr) + ":" + ip.udp.dport;
        if (ip.udp.sport === 53 || ip.udp.dport === 53) {
            ret += print.dns(packet);
        } else {
            ret += " UDP len " + ip.total_length;
        }
        break;
    case "ICMP":
        ret += " " + dns_cache.ptr(ip.saddr) + " -> " + dns_cache.ptr(ip.daddr) + " ICMP " + ip.icmp.type_desc + " " +
            ip.icmp.sequence;
        break;
    case "IGMP":
        ret += " " + dns_cache.ptr(ip.saddr) + " -> " + dns_cache.ptr(ip.daddr) + " IGMP " + ip.igmp.type_desc + " " +
            ip.igmp.group_address;
        break;
    default:
        ret += " proto " + ip.protocol_name;
        break;
    }

    return ret;
};

print.arp = function (packet) {
    var ret = "",
        arp = packet.link.arp;

    if (arp.htype === 1 && arp.ptype === 0x800 && arp.hlen === 6 && arp.plen === 4) {
        ret += " " + arp.sender_pa + " ARP " + arp.operation + " " + arp.target_pa;
        if (arp.operation === "reply") {
            ret += " hwaddr " + arp.target_ha;
        }
    } else {
        ret = " unknown arp type";
        ret += util.inspect(arp);
    }

    return ret;
};

print.ethernet = function (packet) {
    var ret = packet.link.shost + " -> " + packet.link.dhost;

    switch (packet.link.ethertype) {
    case 0x0:
        ret += " 802.3 type ";
        break;
    case 0x800:
        ret += print.ip(packet);
        break;
    case 0x806:
        ret += print.arp(packet);
        break;
    case 0x86dd:
        ret += " IPv6 ";
        break;
    case 0x88cc:
        ret += " LLDP ";
        break;
    default:
        console.log("pcap.js: print.ethernet() - Don't know how to print ethertype " + packet.link.ethertype);
    }

    return ret;
};

print.rawtype = function (packet) {
    var ret = "raw";

    ret += print.ip(packet);

    return ret;
};

print.nulltype = function (packet) {
    var ret = "loopback";

    if (packet.link.pftype === 2) { // AF_INET, at least on my Linux and OSX machines right now
        ret += print.ip(packet);
    } else if (packet.link.pftype === 30) { // AF_INET6, often
        console.log("pcap.js: print.nulltype() - Don't know how to print IPv6 packets.");
    } else {
        console.log("pcap.js: print.nulltype() - Don't know how to print protocol family " + packet.link.pftype);
    }

    return ret;
};

print.packet = function (packet_to_print) {
    var ret = "";
    switch (packet_to_print.link_type) {
    case "LINKTYPE_ETHERNET":
        ret += print.ethernet(packet_to_print);
        break;
    case "LINKTYPE_NULL":
        ret += print.nulltype(packet_to_print);
        break;
    case "LINKTYPE_RAW":
        ret += print.rawtype(packet_to_print);
        break;
    default:
        console.log("Don't yet know how to print link_type " + packet_to_print.link_type);
    }

    return ret;
};

exports.print = print;


