var events = require('events'),
    util = require('util'),
    HTTPParser = process.binding('http_parser').HTTPParser,
    dns_cache = require('./dns').dns_cache;

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
