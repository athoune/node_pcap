var unpack = {
    ethernet_addr: function (raw_packet, offset) {
        return [
            lpad(raw_packet[offset].toString(16), 2),
        lpad(raw_packet[offset + 1].toString(16), 2),
        lpad(raw_packet[offset + 2].toString(16), 2),
        lpad(raw_packet[offset + 3].toString(16), 2),
        lpad(raw_packet[offset + 4].toString(16), 2),
        lpad(raw_packet[offset + 5].toString(16), 2)
            ].join(":");
    },
    uint16: function (raw_packet, offset) {
        return ((raw_packet[offset] * 256) + raw_packet[offset + 1]);
    },
    uint16_be: function (raw_packet, offset) {
        return ((raw_packet[offset+1] * 256) + raw_packet[offset]);
    },
    uint32: function (raw_packet, offset) {
        return (
                (raw_packet[offset] * 16777216) +
                (raw_packet[offset + 1] * 65536) +
                (raw_packet[offset + 2] * 256) +
                raw_packet[offset + 3]
               );
    },
    uint64: function (raw_packet, offset) {
        return (
                (raw_packet[offset] * 72057594037927936) +
                (raw_packet[offset + 1] * 281474976710656) +
                (raw_packet[offset + 2] * 1099511627776) +
                (raw_packet[offset + 3] * 4294967296) +
                (raw_packet[offset + 4] * 16777216) +
                (raw_packet[offset + 5] * 65536) +
                (raw_packet[offset + 6] * 256) +
                raw_packet[offset + 7]
               );
    },
    ipv4_addr: function (raw_packet, offset) {
        return [
            raw_packet[offset],
        raw_packet[offset + 1],
        raw_packet[offset + 2],
        raw_packet[offset + 3]
            ].join('.');
    },
    ipv6_addr: function (raw_packet, offset) {
        var ret = '';
        var octets = [];
        for (var i=offset; i<offset+16; i+=2) {
            octets.push(unpack.uint16(raw_packet,i).toString(16));
        }
        var curr_start, curr_len = undefined;
        var max_start, max_len = undefined;
        for(var i = 0; i < 8; i++){
            if(octets[i] == "0"){
                if(curr_start === undefined){
                    curr_len = 1;
                    curr_start = i;
                }else{
                    curr_len++;
                    if(!max_start || curr_len > max_len){
                        max_start = curr_start;
                        max_len = curr_len;
                    }
                }
            }else{
                curr_start = undefined;
            }
        }

        if(max_start !== undefined){
            var tosplice = max_start == 0 || (max_start + max_len > 7) ? ":" : "";
            octets.splice(max_start, max_len,tosplice);
            if(max_len == 8){octets.push("");}
        }
        ret = octets.join(":");
        return ret;
    }
};
exports.unpack = unpack;

