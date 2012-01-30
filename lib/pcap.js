/*global process require exports console */

var util, IOWatcher,
    dns        = require('dns'),
    Buffer     = require('buffer').Buffer,
    events     = require('events'),
    binding    = require('../build/Release/pcap_binding'),
    url        = require('url'),
    decode     = require('./decode').decode,
    unpack     = require('./unpack').unpack,
    dns_util    = require('./dns').dns_util,
    dns_cache  = require('./dns').dns_cache,
    print      = require('./print').print,
    TCP_tracker= require('./tcp_tracker').TCP_tracker;

exports.unpack = unpack;
exports.decode = decode;
exports.dns_cache = dns_cache;
exports.dns_util = dns_util;
exports.print = print;
exports.TCP_tracker = TCP_tracker;

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



function dump_bytes(raw_packet, offset) {
    for (var i = offset; i < raw_packet.pcap_header.caplen ; i += 1) {
        console.log(i + ": " + raw_packet[i]);
    }
}

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


