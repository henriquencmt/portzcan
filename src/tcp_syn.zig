const std = @import("std");
const posix = std.posix;
const os = std.os;
const shr = std.math.shr;
const shl = std.math.shl;

pub fn print(comptime message: []const u8, args: anytype) !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print(message, args);

    try bw.flush();
}

pub fn run(src_addr: u32, dest_addr: u32, port: u16) !void {
    const dest_addr_arr = .{
        @as(u8, @truncate(dest_addr)),
        @as(u8, @truncate(dest_addr >> 8)),
        @as(u8, @truncate(dest_addr >> 16)),
        @as(u8, @intCast(dest_addr >> 24)),
    };

    const ip_header = IPHeader{
        .version = 0x4,
        .ihl = 0x5,
        .type_of_service = 0x0,
        .total_length = 0x28,
        .identification = 0xABCD,
        .f_fo = 0x0,
        .ttl = 0x40,
        .protocol = 0x6,
        .header_checksum = 0x0,
        .saddr = src_addr,
        .daddr = dest_addr,
    };

    var ip_payload = [_]u8{
        ip_header.version << 4 | ip_header.ihl,
        ip_header.type_of_service,
        @as(u8, @intCast(ip_header.total_length >> 8)),
        @as(u8, @intCast(ip_header.total_length)),
        @as(u8, @intCast(ip_header.identification >> 8)),
        @as(u8, @truncate(ip_header.identification)),
        @as(u8, @intCast(ip_header.f_fo >> 8)),
        @as(u8, @intCast(ip_header.f_fo)),
        ip_header.ttl,
        ip_header.protocol,
        @as(u8, @intCast(ip_header.header_checksum >> 8)),
        @as(u8, @intCast(ip_header.header_checksum)),
        @as(u8, @intCast(ip_header.saddr >> 24)),
        @as(u8, @truncate(ip_header.saddr >> 16)),
        @as(u8, @truncate(ip_header.saddr >> 8)),
        @as(u8, @truncate(ip_header.saddr)),
        @as(u8, @truncate(ip_header.daddr)),
        @as(u8, @truncate(ip_header.daddr >> 8)),
        @as(u8, @truncate(ip_header.daddr >> 16)),
        @as(u8, @intCast(ip_header.daddr >> 24)),
    };

    const ip_cs = checksum(&ip_payload);
    const ip_checksum = [2]u8{ @as(u8, @truncate(ip_cs >> 8)), @as(u8, @truncate(ip_cs)) & 0xFF };

    const tcp_header = TCPHeader{
        .src_port = 0x3039,
        .dest_port = port,
        .seq_num = 0x0,
        .ack_num = 0x0,
        .data_offset_res_flags = 0x5 << 4,
        .flags = 0x2, // SYN flag
        .window_size = 0x7110,
        .checksum = 0x0,
        .urg_pointer = 0x0,
    };

    var pseudoheader: [12]u8 = undefined;
    pseudoheader[0] = @as(u8, @intCast(ip_header.saddr >> 24));
    pseudoheader[1] = @as(u8, @truncate(ip_header.saddr >> 16));
    pseudoheader[2] = @as(u8, @truncate(ip_header.saddr >> 8));
    pseudoheader[3] = @as(u8, @truncate(ip_header.saddr));
    pseudoheader[4] = @as(u8, @truncate(ip_header.daddr));
    pseudoheader[5] = @as(u8, @truncate(ip_header.daddr >> 8));
    pseudoheader[6] = @as(u8, @truncate(ip_header.daddr >> 16));
    pseudoheader[7] = @as(u8, @intCast(ip_header.daddr >> 24));
    pseudoheader[8] = 0x0;
    pseudoheader[9] = ip_header.protocol;
    pseudoheader[10] = 0x0;

    const tmp_tcp_header = [20]u8{
        @as(u8, @intCast(tcp_header.src_port >> 8)),
        @as(u8, @truncate(tcp_header.src_port)),
        @as(u8, @intCast(tcp_header.dest_port >> 8)),
        @as(u8, @truncate(tcp_header.dest_port)),
        shr(u8, @as(u8, @truncate(tcp_header.seq_num)), 24),
        shr(u8, @as(u8, @truncate(tcp_header.seq_num)), 16),
        shr(u8, @as(u8, @truncate(tcp_header.seq_num)), 8),
        @as(u8, @truncate(tcp_header.seq_num)),
        shr(u8, @as(u8, @truncate(tcp_header.ack_num)), 24),
        shr(u8, @as(u8, @truncate(tcp_header.ack_num)), 16),
        shr(u8, @as(u8, @truncate(tcp_header.ack_num)), 8),
        @as(u8, @truncate(tcp_header.ack_num)),
        @as(u8, @truncate(tcp_header.data_offset_res_flags)),
        @as(u8, @truncate(tcp_header.flags)),
        @as(u8, @intCast(tcp_header.window_size >> 8)),
        @as(u8, @truncate(tcp_header.window_size)),
        shr(u8, @as(u8, @truncate(tcp_header.checksum)), 8),
        @as(u8, @truncate(tcp_header.checksum)),
        shr(u8, @as(u8, @truncate(tcp_header.urg_pointer)), 8),
        @as(u8, @truncate(tcp_header.urg_pointer)),
    };

    pseudoheader[11] = tmp_tcp_header.len;

    var tcp_payload = pseudoheader ++ tmp_tcp_header;

    const tcp_cs = checksum(tcp_payload[0..]);
    const tcp_checksum = [2]u8{ @as(u8, @truncate(tcp_cs >> 8)), @as(u8, @truncate(tcp_cs)) & 0xFF };

    var packet = [_]u8{
        ip_header.version << 4 | ip_header.ihl,
        ip_header.type_of_service,
        @as(u8, @truncate(ip_header.total_length >> 8)),
        @as(u8, @truncate(ip_header.total_length)) & 0xFF,
        @as(u8, @truncate(ip_header.identification >> 8)),
        @as(u8, @truncate(ip_header.identification)) & 0xFF,
        @as(u8, @truncate(ip_header.f_fo >> 8)),
        @as(u8, @truncate(ip_header.f_fo)) & 0xFF,
        ip_header.ttl,
        ip_header.protocol,
        ip_checksum[0],
        ip_checksum[1],
        @as(u8, @truncate(ip_header.saddr >> 24)) & 0xFF,
        @as(u8, @truncate(ip_header.saddr >> 16)) & 0xFF,
        @as(u8, @truncate(ip_header.saddr >> 8)) & 0xFF,
        @as(u8, @truncate(ip_header.saddr)) & 0xFF,
        @as(u8, @truncate(ip_header.daddr)) & 0xFF,
        @as(u8, @truncate(ip_header.daddr >> 8)) & 0xFF,
        @as(u8, @truncate(ip_header.daddr >> 16)) & 0xFF,
        @as(u8, @truncate(ip_header.daddr >> 24)) & 0xFF,
        @as(u8, @truncate(tcp_header.src_port >> 8)),
        @as(u8, @truncate(tcp_header.src_port)) & 0xFF,
        @as(u8, @truncate(tcp_header.dest_port >> 8)),
        @as(u8, @truncate(tcp_header.dest_port)) & 0xFF,
        @as(u8, @truncate(tcp_header.seq_num >> 24)) & 0xFF,
        @as(u8, @truncate(tcp_header.seq_num >> 16)) & 0xFF,
        @as(u8, @truncate(tcp_header.seq_num >> 8)) & 0xFF,
        @as(u8, @truncate(tcp_header.seq_num)) & 0xFF,
        @as(u8, @truncate(tcp_header.ack_num >> 24)) & 0xFF,
        @as(u8, @truncate(tcp_header.ack_num >> 16)) & 0xFF,
        @as(u8, @truncate(tcp_header.ack_num >> 8)) & 0xFF,
        @as(u8, @truncate(tcp_header.ack_num)) & 0xFF,
        tcp_header.data_offset_res_flags,
        tcp_header.flags,
        @as(u8, @truncate(tcp_header.window_size >> 8)) & 0xFF,
        @as(u8, @truncate(tcp_header.window_size)) & 0xFF,
        tcp_checksum[0],
        tcp_checksum[1],
        @as(u8, @truncate(tcp_header.urg_pointer >> 8)) & 0xFF,
        @as(u8, @truncate(tcp_header.urg_pointer)) & 0xFF,
    };

    const socket = try setupSocket();
    defer std.posix.close(socket);
    try sendSyn(socket, &packet, dest_addr_arr);

    var buffer: [4096]u8 = undefined;
    var bytes: usize = undefined;
    if (std.posix.recv(socket, &buffer, std.os.linux.MSG.DONTWAIT)) |b| {
        bytes = b;
        if (getSrcPort(&buffer) == port) {
            if (isSynAck(&buffer)) {
                try print("port {} is open\n", .{port});
                // TODO if verbose
                // processPacket(bytes, &buffer);
                return;
            }
        }
    } else |err| switch (err) {
        error.WouldBlock => {
            const epollfd = try posix.epoll_create1(0);
            var ev: os.linux.epoll_event = .{
                .events = os.linux.EPOLL.IN,
                .data = .{ .fd = socket },
            };
            _ = try posix.epoll_ctl(epollfd, os.linux.EPOLL.CTL_ADD, socket, &ev);

            var events: [3]os.linux.epoll_event = undefined;
            const nfds = posix.epoll_wait(epollfd, &events, 1000);
            switch (nfds) {
                0 => try print("timeout trying to connect to port {}\n", .{port}),
                else => {
                    if (nfds == -1) {
                        try print("epoll_wait() failure trying to connect to port {}\n", .{port});
                    } else {
                        var so_error: i32 = undefined;
                        var size: u32 = @sizeOf(u32);
                        const rc = os.linux.getsockopt(socket, posix.SOL.SOCKET, posix.SO.ERROR, @as([*]u8, @ptrCast(&so_error)), &size);
                        switch (rc) {
                            0 => {
                                for (0..nfds + 1) |_| {
                                    bytes = try std.posix.recv(socket, &buffer, 0);
                                    if (getSrcPort(&buffer) == port) {
                                        if (isSynAck(&buffer)) {
                                            try print("port {} is open\n", .{port});
                                            // TODO if verbose
                                            // processPacket(bytes, &buffer);
                                            return;
                                        }
                                    }
                                }
                                try print("timeout trying to connect to port {}\n", .{port});
                            },
                            else => try print("socket not connected trying to connect to port {}\n", .{port}),
                        }
                    }
                },
            }
        },
        else => try print("failure trying to connect to port {}. error: {any}\n", .{ port, err }),
    }
}

fn getSrcPort(buffer: []const u8) u16 {
    // TCP segment header Source port
    const octets = buffer[20..22];
    const src_port = shl(u16, octets[0], 8) | octets[1];
    return src_port;
}

fn isSynAck(buffer: []const u8) bool {
    const tcp_header = buffer[20..40];
    const syn_flag = (tcp_header[13] & 2) != 0;
    const ack_flag = (tcp_header[13] & 16) != 0;
    return syn_flag and ack_flag;
}

fn sendSyn(socket: std.posix.fd_t, packet: []u8, ip: [4]u8) !void {
    const dest_addr = std.posix.sockaddr{ .family = std.posix.AF.INET, .data = [14]u8{ 0, 0, ip[0], ip[1], ip[2], ip[3], 0, 0, 0, 0, 0, 0, 0, 0 } };
    _ = try std.posix.sendto(socket, packet, 0, &dest_addr, @sizeOf(std.posix.sockaddr));
}

pub fn setupSocket() !std.posix.fd_t {
    const sockfd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.RAW, std.posix.IPPROTO.TCP);
    errdefer std.posix.close(sockfd);

    try std.posix.setsockopt(sockfd, std.posix.IPPROTO.IP, std.os.linux.IP.HDRINCL, &[_]u8{1});
    return sockfd;
}

fn checksum(arr: []u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    while (i < arr.len - 1) : (i += 2) {
        const upperByte = @as(u16, @intCast(arr[i])) << 8;
        const lowerByte = @as(u16, @intCast(arr[i + 1]));
        const combinedValue = upperByte + lowerByte;
        sum += combinedValue;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = ~sum & 0xFFFF;
    return @as(u16, @truncate(sum));
}

// fn processPacket(bytes: usize, buffer: []const u8) !void {
//     const ip_header = buffer[0..20];
//     const source_ip = ip_header[12..16];
//     const destination_ip = ip_header[16..20];
//
//     const tcp_header = buffer[20..40];
//     const syn_flag = (tcp_header[13] & 2) != 0;
//     const ack_flag = (tcp_header[13] & 16) != 0;
//
//     try print("Response received:\n", .{});
//     try print("Num of bytes: {any}\n", .{bytes});
//     try print("Buffer: {any}\n", .{buffer});
//     try print("TCP header: {any}\n", .{tcp_header});
//
//     try print("Source IP: {}.{}.{}.{}\n", .{ source_ip[0], source_ip[1], source_ip[2], source_ip[3] });
//     try print("Destination IP: {}.{}.{}.{}\n", .{ destination_ip[0], destination_ip[1], destination_ip[2], destination_ip[3] });
//     try print("SYN Flag: {}\n", .{syn_flag});
//     try print("ACK Flag: {}\n", .{ack_flag});
// }

const IPHeader = packed struct {
    version: u8,
    ihl: u8,
    type_of_service: u8,
    total_length: u16,
    identification: u16,
    f_fo: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    saddr: u32,
    daddr: u32,
};

const TCPHeader = packed struct {
    src_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset_res_flags: u8,
    flags: u8,
    window_size: u16,
    checksum: u16,
    urg_pointer: u16,
};