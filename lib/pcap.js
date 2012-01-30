/*global process require exports console */

var util, IOWatcher,
    dns        = require('dns'),
    Buffer     = require('buffer').Buffer,
    events     = require('events'),
    binding    = require('./build/Release/pcap_binding'),
    HTTPParser = process.binding('http_parser').HTTPParser,
    url        = require('url'),
    decode     = require('./decode').decode,
    unpack     = require('./unpack').unpack;

exports.unpack = unpack;

if (process.versions && process.versions.node && process.versions.node.split('.')[1] >= 3) {
    util = require("util");
    IOWatcher  = process.binding('io_watcher').IOWatcher;
} else {
    util = require("sys");
    IOWatcher = process.IOWatcher;
}

function Pcap() {
    this.opened = false;
    this.fd = null;

    events.EventEmitter.call(this);
}
util.inherits(Pcap, events.EventEmitter);

exports.lib_version = binding.lib_version();

Pcap.prototype.findalldevs = function () {
    return binding.findalldevs();
};

Pcap.prototype.open = function (live, device, filter, buffer_size, pcap_output_filename) {
    var me = this;

    if (typeof buffer_size === 'number' && !isNaN(buffer_size)) {
        this.buffer_size = Math.round(buffer_size);
    } else {
        this.buffer_size = 10 * 1024 * 1024; // Default buffer size is 10MB
    }

    this.live = live;

    if (live) {
        this.device_name = device || binding.default_device();
        this.link_type = binding.open_live(this.device_name, filter || "", this.buffer_size, pcap_output_filename || "");
    } else {
        this.device_name = device;
        this.link_type = binding.open_offline(this.device_name, filter || "", this.buffer_size, pcap_output_filename || "");
    }

    this.fd = binding.fileno();
    this.opened = true;
    this.readWatcher = new IOWatcher();
    this.empty_reads = 0;
    this.buf = new Buffer(65535);

    // called for each packet read by pcap
    function packet_ready(header) {
        header.link_type = me.link_type;
        header.time_ms = (header.tv_sec * 1000) + (header.tv_usec / 1000);
        me.buf.pcap_header = header;
        me.emit('packet', me.buf);
    }

    // readWatcher gets a callback when pcap has data to read. multiple packets may be readable.
    this.readWatcher.callback = function pcap_read_callback() {
        var packets_read = binding.dispatch(me.buf, packet_ready);
        if (packets_read < 1) {
            // according to pcap_dispatch documentation if 0 is returned when reading
            // from a savefile there will be no more packets left. this check ensures
            // we stop reading. Under certain circumstances IOWatcher will get caught
            // in a loop and continue to signal us causing the program to be flooded
            // with events.
            if(!me.live) {
                me.readWatcher.stop();
                me.emit('complete');
            }

            // TODO - figure out what is causing this, and if it is bad.
            me.empty_reads += 1;
        }
    };
    this.readWatcher.set(this.fd, true, false);
    this.readWatcher.start();
};

Pcap.prototype.close = function () {
    this.opened = false;
    binding.close();
    // TODO - remove listeners so program will exit I guess?
};

Pcap.prototype.stats = function () {
    return binding.stats();
};

exports.Pcap = Pcap;

exports.createSession = function (device, filter, buffer_size) {
    var session = new Pcap();
    session.open(true, device, filter, buffer_size);
    return session;
};

exports.createOfflineSession = function (path, filter) {
    var session = new Pcap();
    session.open(false, path, filter, 0);
    return session;
};

//
// Decoding functions
//
function lpad(str, len) {
    while (str.length < len) {
        str = "0" + str;
    }
    return str;
}

function dump_bytes(raw_packet, offset) {
    for (var i = offset; i < raw_packet.pcap_header.caplen ; i += 1) {
        console.log(i + ": " + raw_packet[i]);
    }
}

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
    },
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

exports.decode = decode;

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

// Meaningfully hold the different types of frames at some point
function WebSocketFrame() {
    this.type = null;
    this.data = "";
}

function WebSocketParser(flag) {
    this.buffer = new Buffer(64 * 1024); // 64KB is the max message size
    this.buffer.end = 0;
    if (flag === "draft76") {
        this.state = "skip_response";
        this.skipped_bytes = 0;
    } else {
        this.state = "frame_type";
    }
    this.frame = new WebSocketFrame();

    events.EventEmitter.call(this);
}
util.inherits(WebSocketParser, events.EventEmitter);

WebSocketParser.prototype.execute = function (incoming_buf) {
    var pos = 0;

    while (pos < incoming_buf.length) {
        switch (this.state) {
        case "skip_response":
            this.skipped_bytes += 1;
            if (this.skipped_bytes === 16) {
                this.state = "frame_type";
            }
            pos += 1;
            break;
        case "frame_type":
            this.frame.type = incoming_buf[pos];
            pos += 1;
            this.state = "read_until_marker";
            break;
        case "read_until_marker":
            if (incoming_buf[pos] !== 255) {
                this.buffer[this.buffer.end] = incoming_buf[pos];
                this.buffer.end += 1;
                pos += 1;
            } else {
                this.frame.data = this.buffer.toString('utf8', 0, this.buffer.end);
                this.emit("message", this.frame.data); // this gets converted to "websocket message" in TCP_Tracker
                this.state = "frame_type";
                this.buffer.end = 0;
                pos += 1;
            }
            break;
        default:
            throw new Error("invalid state " + this.state);
        }
    }
};

function TCP_tracker() {
    this.sessions = {};
    events.EventEmitter.call(this);
}
util.inherits(TCP_tracker, events.EventEmitter);
exports.TCP_tracker = TCP_tracker;

TCP_tracker.prototype.make_session_key = function (src, dst) {
    return [ src, dst ].sort().join("-");
};

TCP_tracker.prototype.detect_http_request = function (buf) {
    var str = buf.toString('utf8', 0, buf.length);

    return (/^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|COPY|LOCK|MKCOL|MOVE|PROPFIND|PROPPATCH|UNLOCK) [^\s\r\n]+ HTTP\/\d\.\d\r\n/.test(str));
};

TCP_tracker.prototype.session_stats = function (session) {
    var send_acks = Object.keys(session.send_acks),
        recv_acks = Object.keys(session.recv_acks),
        total_time = session.close_time - session.syn_time,
        stats = {};

    send_acks.sort();
    recv_acks.sort();

    stats.recv_times = {};
    send_acks.forEach(function (v) {
        if (session.recv_packets[v]) {
            stats.recv_times[v] = session.send_acks[v] - session.recv_packets[v];
        } else {
//            console.log("send ACK with missing recv seqno: " + v);
        }
    });

    stats.send_times = {};
    recv_acks.forEach(function (v) {
        if (session.send_packets[v]) {
            stats.send_times[v] = session.recv_acks[v] - session.send_packets[v];
        } else {
//            console.log("recv ACK with missing send seqno: " + v);
        }
    });

    stats.recv_retrans = {};
    Object.keys(session.recv_retrans).forEach(function (v) {
        stats.recv_retrans[v] = session.recv_retrans[v];
    });

    stats.total_time = total_time;
    stats.send_overhead = session.send_bytes_ip + session.send_bytes_tcp;
    stats.send_payload = session.send_bytes_payload;
    stats.send_total = stats.send_overhead + stats.send_payload;
    stats.recv_overhead = session.recv_bytes_ip + session.recv_bytes_tcp;
    stats.recv_payload = session.recv_bytes_payload;
    stats.recv_total = stats.recv_overhead + stats.recv_payload;

    if (session.http.request) {
        stats.http_request = session.http.request;
    }

    return stats;
};

TCP_tracker.prototype.setup_http_tracking = function (session) {
  var self = this, http = {
    request : {
      headers : {},
      url : "",
      method : "",
      body_len : 0,
      http_version : null
    },
    response : {
      headers : {},
      status_code : null,
      body_len : 0,
      http_version : null
    },
    request_parser : new HTTPParser(HTTPParser.REQUEST),
    response_parser : new HTTPParser(HTTPParser.RESPONSE)
  };

  http.request_parser.url = '';
  http.request_parser.onHeaders = function(headers, url) {
    http.request_parser.headers = (http.request_parser.headers || []).concat(headers);
    http.request_parser.url += url;
  };

  http.request_parser.onHeadersComplete = function(info) {
    http.request.method = info.method;
    http.request.url = info.url || http.request_parser.url;
    http.request.http_version = info.versionMajor + "." + info.versionMinor;

    var headers = info.headers || http.request_parser.headers;
    for ( var i = 0; i < headers.length; i += 2) {
      http.request.headers[headers[i]] = headers[i + 1];
    }

    self.emit("http request", session, http);
  };

  http.request_parser.onBody = function(buf, start, len) {
    http.request.body_len += len;
    self.emit("http request body", session, http, buf.slice(start, start + len));
  };

  http.request_parser.onMessageComplete = function() {
    self.emit("http request complete", session, http);
  };

  http.response_parser.onHeaders = function(headers, url) {
    http.response_parser.headers = (http.response_parser.headers || []).concat(headers);
  };

  http.response_parser.onHeadersComplete = function(info) {
    http.response.status_code = info.statusCode;
    http.response.http_version = info.versionMajor + "." + info.versionMinor;

    var headers = info.headers || http.response_parser.headers;
    for ( var i = 0; i < headers.length; i += 2) {
      http.response.headers[headers[i]] = headers[i + 1];
    }

    if (http.response.status_code === 101 && http.response.headers.Upgrade === "WebSocket") {
      if (http.response.headers["Sec-WebSocket-Location"]) {
        self.setup_websocket_tracking(session, "draft76");
      } else {
        self.setup_websocket_tracking(session);
      }
      self.emit('websocket upgrade', session, http);
      session.http_detect = false;
      session.websocket_detect = true;
      delete http.response_parser.onMessageComplete;
    } else {
      self.emit('http response', session, http);
    }
  };

  http.response_parser.onBody = function(buf, start, len) {
    http.response.body_len += len;
    self.emit('http response body', session, http, buf.slice(start, start + len));
  };

  http.response_parser.onMessageComplete = function() {
    self.emit('http response complete', session, http);
  };

  session.http = http;
};

TCP_tracker.prototype.setup_websocket_tracking = function (session, flag) {
    var self = this;

    session.websocket_parser_send = new WebSocketParser();
    session.websocket_parser_send.on("message", function (message_string) {
        self.emit("websocket message", session, "send", message_string);
    });
    session.websocket_parser_recv = new WebSocketParser(flag);
    session.websocket_parser_recv.on("message", function (message_string) {
        self.emit("websocket message", session, "recv", message_string);
    });
};

TCP_tracker.prototype.track_states = {};

TCP_tracker.prototype.track_states.SYN_SENT = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    if (src === session.dst && tcp.flags.syn && tcp.flags.ack) {
        session.recv_bytes_ip += ip.header_bytes;
        session.recv_bytes_tcp += tcp.header_bytes;
        session.recv_packets[tcp.seqno + 1] = packet.pcap_header.time_ms;
        session.recv_acks[tcp.ackno] = packet.pcap_header.time_ms;
        session.recv_isn = tcp.seqno;
        session.recv_window_scale = tcp.options.window_scale || 1; // multiplier, not bit shift value
        session.state = "SYN_RCVD";
    } else if (tcp.flags.rst) {
        session.state = "CLOSED";
        delete this.sessions[session.key];
        this.emit('reset', session, "recv"); // TODO - check which direction did the reset, probably recv
    } else {
//        console.log("Didn't get SYN-ACK packet from dst while handshaking: " + util.inspect(tcp, false, 4));
    }
};

TCP_tracker.prototype.track_states.SYN_RCVD = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    if (src === session.src && tcp.flags.ack) { // TODO - make sure SYN flag isn't set, also match src and dst
        session.send_bytes_ip += ip.header_bytes;
        session.send_bytes_tcp += tcp.header_bytes;
        session.send_acks[tcp.ackno] = packet.pcap_header.time_ms;
        session.handshake_time = packet.pcap_header.time_ms;
        this.emit('start', session);
        session.state = "ESTAB";
    } else {
//        console.log("Didn't get ACK packet from src while handshaking: " + util.inspect(tcp, false, 4));
    }
};

TCP_tracker.prototype.track_states.ESTAB = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

// TODO - actually implement SACK decoding and tracking
// if (tcp.options.sack) {
//     console.log("SACK magic, handle this: " + util.inspect(tcp.options.sack));
//     console.log(util.inspect(ip, false, 5));
// }

    // TODO - check for tcp.flags.rst and emit reset event

    if (src === session.src) { // this packet came from the active opener / client
        session.send_bytes_ip += ip.header_bytes;
        session.send_bytes_tcp += tcp.header_bytes;
        if (tcp.data_bytes) {
            if (session.send_bytes_payload === 0) {
                session.http_detect = this.detect_http_request(tcp.data);
                if (session.http_detect) {
                    this.setup_http_tracking(session);
                }
            }
            session.send_bytes_payload += tcp.data_bytes;
            if (session.send_packets[tcp.seqno + tcp.data_bytes]) {
                this.emit('retransmit', session, "send", tcp.seqno + tcp.data_bytes);
            } else {
                if (session.http_detect) {
                    try {
                        session.http.request_parser.execute(tcp.data, 0, tcp.data.length);
                    } catch (request_err) {
                        this.emit('http error', session, "send", request_err);
                    }
                } else if (session.websocket_detect) {
                    session.websocket_parser_send.execute(tcp.data);
                    // TODO - check for WS parser errors
                }
            }
            session.send_packets[tcp.seqno + tcp.data_bytes] = packet.pcap_header.time_ms;
        }
        if (session.recv_packets[tcp.ackno]) {
            if (session.send_acks[tcp.ackno]) {
                // console.log("Already sent this ACK, which perhaps is fine.");
            } else {
                session.send_acks[tcp.ackno] = packet.pcap_header.time_ms;
            }
        } else {
            // console.log("sending ACK for packet we didn't see received: " + tcp.ackno);
        }
        if (tcp.flags.fin) {
            session.state = "FIN_WAIT";
        }
    } else if (src === session.dst) { // this packet came from the passive opener / server
        session.recv_bytes_ip += ip.header_bytes;
        session.recv_bytes_tcp += tcp.header_bytes;
        if (tcp.data_bytes) {
            session.recv_bytes_payload += tcp.data_bytes;
            if (session.recv_packets[tcp.seqno + tcp.data_bytes]) {
                this.emit('retransmit', session, "recv", tcp.seqno + tcp.data_bytes);
                if (session.recv_retrans[tcp.seqno + tcp.data_bytes]) {
                    session.recv_retrans[tcp.seqno + tcp.data_bytes] += 1;
                } else {
                    session.recv_retrans[tcp.seqno + tcp.data_bytes] = 1;
                }
            } else {
                if (session.http_detect) {
                    try {
                        session.http.response_parser.execute(tcp.data, 0, tcp.data.length);
                    } catch (response_err) {
                        this.emit('http error', session, "recv", response_err);
                    }
                } else if (session.websocket_detect) {
                    session.websocket_parser_recv.execute(tcp.data);
                    // TODO - check for WS parser errors
                }
            }
            session.recv_packets[tcp.seqno + tcp.data_bytes] = packet.pcap_header.time_ms;
        }
        if (session.send_packets[tcp.ackno]) {
            if (session.recv_acks[tcp.ackno]) {
                //                    console.log("Already received this ACK, which I'm guessing is fine.");
            } else {
                session.recv_acks[tcp.ackno] = packet.pcap_header.time_ms;
            }
        } else {
            // console.log("receiving ACK for packet we didn't see sent: " + tcp.ackno);
        }
        if (tcp.flags.fin) {
            session.state = "CLOSE_WAIT";
        }
    } else {
        console.log("non-matching packet in session: " + util.inspect(packet));
    }
};

TCP_tracker.prototype.track_states.FIN_WAIT = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    // TODO - need to track half-closed data
    if (src === session.dst && tcp.flags.fin) {
        session.state = "CLOSING";
    }
};

TCP_tracker.prototype.track_states.CLOSE_WAIT = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    // TODO - need to track half-closed data
    if (src === session.src && tcp.flags.fin) {
        session.state = "LAST_ACK";
    }
};

TCP_tracker.prototype.track_states.LAST_ACK = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    // TODO - need to track half-closed data
    if (src === session.dst) {
        session.close_time = packet.pcap_header.time_ms;
        session.state = "CLOSED";
        delete this.sessions[session.key];
        this.emit('end', session);
    }
};

TCP_tracker.prototype.track_states.CLOSING = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    // TODO - need to track half-closed data
    if (src === session.src) {
        session.close_time = packet.pcap_header.time_ms;
        session.state = "CLOSED";
        delete this.sessions[session.key];
        this.emit('end', session);
    }
};

TCP_tracker.prototype.track_states.CLOSED = function (packet, session) {
    var ip  = packet.link.ip,
        tcp = ip.tcp,
        src = ip.saddr + ":" + tcp.sport;

    // The states aren't quite right here.  All possible states of FIN and FIN/ACKs aren't handled.
    // So some of the bytes of the session may not be properly accounted for.
};

TCP_tracker.prototype.track_next = function (key, packet) {
    var session = this.sessions[key];

    if (typeof session !== 'object') {
        throw new Error("track_next: couldn't find session for " + key);
    }

    if (typeof this.track_states[session.state] === 'function') {
        this.track_states[session.state].call(this, packet, session);
    } else {
        console.log(util.debug(session));
        throw new Error("Don't know how to handle session state " + session.state);
    }
};

TCP_tracker.prototype.track_packet = function (packet) {
    var ip, tcp, src, src_mac, dst, dst_mac, key, session, self = this;

    if (packet.link && packet.link.ip && packet.link.ip.tcp) {
        ip  = packet.link.ip;
        tcp = ip.tcp;
        src = ip.saddr + ":" + tcp.sport;
        src_mac = packet.link.shost;
        dst = ip.daddr + ":" + tcp.dport;
        dst_mac = packet.link.dhost;
        key = this.make_session_key(src, dst);
        session = this.sessions[key];

        if (tcp.flags.syn && !tcp.flags.ack) {
            if (session === undefined) {
                this.sessions[key] = {
                    src: src, // the side the sent the initial SYN
                    src_mac: src_mac,
                    dst: dst, // the side that the initial SYN was sent to
                    dst_mac: dst_mac,
                    syn_time: packet.pcap_header.time_ms,
                    state: "SYN_SENT",
                    key: key, // so we can easily remove ourselves

                    send_isn: tcp.seqno,
                    send_window_scale: tcp.options.window_scale || 1, // multipler, not bit shift value
                    send_packets: {}, // send_packets is indexed by the expected ackno: seqno + length
                    send_acks: {},
                    send_retrans: {},
                    send_next_seq: tcp.seqno + 1,
                    send_acked_seq: null,
                    send_bytes_ip: ip.header_bytes,
                    send_bytes_tcp: tcp.header_bytes,
                    send_bytes_payload: 0,

                    recv_isn: null,
                    recv_window_scale: null,
                    recv_packets: {},
                    recv_acks: {},
                    recv_retrans: {},
                    recv_next_seq: null,
                    recv_acked_seq: null,
                    recv_bytes_ip: 0,
                    recv_bytes_tcp: 0,
                    recv_bytes_payload: 0
                };
                session = this.sessions[key];
                session.send_packets[tcp.seqno + 1] = packet.pcap_header.time_ms;
                session.src_name = dns_cache.ptr(ip.saddr, function (name) {
                    session.src_name = name + ":" + tcp.sport;
                    self.emit("reverse", ip.saddr, name);
                }) + ":" + tcp.sport;
                session.dst_name = dns_cache.ptr(ip.daddr, function (name) {
                    session.dst_name = name + ":" + tcp.dport;
                    self.emit("reverse", ip.daddr, name);
                }) + ":" + tcp.dport;
                session.current_cap_time = packet.pcap_header.time_ms;
            } else { // SYN retry
                this.emit('syn retry', session);
            }
        } else { // not a SYN
            if (session) {
                session.current_cap_time = packet.pcap_header.time_ms;
                this.track_next(key, packet);
            } else {
                // silently ignore session in progress

                // TODO - for sessions in progress, we should pretend that this is the first packet from
                //        the sender, go into ESTAB, and run HTTP detector.  That way we might see HTTP
                //        requests on keepalive connections
            }
        }
    } else {
        // silently ignore any non IPv4 TCP packets
        // user should filter these out with their pcap filter, but oh well.
    }

    return session;
};
