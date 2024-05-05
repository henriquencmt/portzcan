const std = @import("std");

pub fn main() !void {
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
        .saddr = 172 << 24 | 30 << 16 | 188 << 8 | 242,
        .daddr = 142 << 24 | 250 << 16 | 218 << 8 | 206,
    };
    const ip = [_]u8{ 142, 250, 218, 206 };

    var ip_payload = [_]u8{
        ip_header.version << 4 | ip_header.ihl,
        ip_header.type_of_service,
        ip_header.total_length >> 8,
        ip_header.total_length & 0xFF,
        ip_header.identification >> 8,
        ip_header.identification & 0xFF,
        ip_header.f_fo >> 8,
        ip_header.f_fo & 0xFF,
        ip_header.ttl,
        ip_header.protocol,
        ip_header.header_checksum >> 8,
        ip_header.header_checksum & 0xFF,
        ip_header.saddr >> 24 & 0xFF,
        ip_header.saddr >> 16 & 0xFF,
        ip_header.saddr >> 8 & 0xFF,
        ip_header.saddr & 0xFF,
        ip_header.daddr >> 24 & 0xFF,
        ip_header.daddr >> 16 & 0xFF,
        ip_header.daddr >> 8 & 0xFF,
        ip_header.daddr & 0xFF,
    };
    std.debug.print("IP payload: {any}\n", .{ip_payload});

    const ip_checksum = calc_checksum(&ip_payload);
    const ip_check = [2]u8{ @as(u8, @truncate(ip_checksum >> 8)), @as(u8, @truncate(ip_checksum)) & 0xFF };

    const tcp_header = TCPHeader{
        .src_port = 0x3039,
        .dest_port = 80, // TODO pass as arg
        .seq_num = 0x0,
        .ack_num = 0x0,
        .data_offset_res_flags = 0x5 << 4,
        .flags = 0x2, // SYN flag
        .window_size = 0x7110,
        .checksum = 0x0,
        .urg_pointer = 0x0,
    };

    var pseudoheader: [12]u8 = undefined;
    pseudoheader[0] = ip_header.saddr >> 24 & 0xFF;
    pseudoheader[1] = ip_header.saddr >> 16 & 0xFF;
    pseudoheader[2] = ip_header.saddr >> 8 & 0xFF;
    pseudoheader[3] = ip_header.saddr & 0xFF;
    pseudoheader[4] = ip_header.daddr >> 24 & 0xFF;
    pseudoheader[5] = ip_header.daddr >> 16 & 0xFF;
    pseudoheader[6] = ip_header.daddr >> 8 & 0xFF;
    pseudoheader[7] = ip_header.daddr & 0xFF;
    pseudoheader[8] = 0x0;
    pseudoheader[9] = ip_header.protocol;
    pseudoheader[10] = 0x0;

    const tmp_tcp_header = [20]u8{
        tcp_header.src_port >> 8,
        tcp_header.src_port & 0xFF,
        tcp_header.dest_port >> 8,
        tcp_header.dest_port & 0xFF,
        tcp_header.seq_num >> 24,
        tcp_header.seq_num >> 16,
        tcp_header.seq_num >> 8,
        tcp_header.seq_num & 0xFF,
        tcp_header.ack_num >> 24,
        tcp_header.ack_num >> 16,
        tcp_header.ack_num >> 8,
        tcp_header.ack_num & 0xFF,
        tcp_header.data_offset_res_flags,
        tcp_header.flags,
        tcp_header.window_size >> 8,
        tcp_header.window_size & 0xFF,
        tcp_header.checksum >> 8,
        tcp_header.checksum & 0xFF,
        tcp_header.urg_pointer >> 8,
        tcp_header.urg_pointer & 0xFF,
    };

    pseudoheader[11] = tmp_tcp_header.len;

    var tcp_payload = pseudoheader ++ tmp_tcp_header;
    std.debug.print("TCP payload: {any}\n", .{tcp_payload});

    const checksum = calc_checksum(tcp_payload[0..]);
    const check = [2]u8{ @as(u8, @truncate(checksum >> 8)), @as(u8, @truncate(checksum)) & 0xFF };

    var packet = [_]u8{
        ip_header.version << 4 | ip_header.ihl,
        ip_header.type_of_service,
        ip_header.total_length >> 8,
        ip_header.total_length & 0xFF,
        ip_header.identification >> 8,
        ip_header.identification & 0xFF,
        ip_header.f_fo >> 8,
        ip_header.f_fo & 0xFF,
        ip_header.ttl,
        ip_header.protocol,
        ip_check[0],
        ip_check[1],
        ip_header.saddr >> 24 & 0xFF,
        ip_header.saddr >> 16 & 0xFF,
        ip_header.saddr >> 8 & 0xFF,
        ip_header.saddr & 0xFF,
        ip_header.daddr >> 24 & 0xFF,
        ip_header.daddr >> 16 & 0xFF,
        ip_header.daddr >> 8 & 0xFF,
        ip_header.daddr & 0xFF,
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
        check[0],
        check[1],
        @as(u8, @truncate(tcp_header.urg_pointer >> 8)) & 0xFF,
        @as(u8, @truncate(tcp_header.urg_pointer)) & 0xFF,
    };

    const socket = try setup_socket();
    try send_syn(socket, &packet, ip);

    var buffer: [4096]u8 = undefined;
    const bytes = try std.posix.recv(socket, &buffer, 0);
    std.debug.print("Response received:\n", .{});
    process_packet(bytes, &buffer);
    std.posix.close(socket);
}

fn process_packet(bytes: usize, buffer: []const u8) void {
    const ip_header = buffer[0..20];
    const source_ip = ip_header[12..16];
    const destination_ip = ip_header[16..20];

    const tcp_header = buffer[20..40];
    const syn_flag = (tcp_header[13] & 2) != 0;
    const ack_flag = (tcp_header[13] & 16) != 0;

    std.debug.print("Num of bytes: {}\n", .{bytes});
    std.debug.print("Source IP: {}.{}.{}.{}\n", .{ source_ip[0], source_ip[1], source_ip[2], source_ip[3] });
    std.debug.print("Destination IP: {}.{}.{}.{}\n", .{ destination_ip[0], destination_ip[1], destination_ip[2], destination_ip[3] });
    std.debug.print("SYN Flag: {}\n", .{syn_flag});
    std.debug.print("ACK Flag: {}\n", .{ack_flag});
}

fn send_syn(socket: std.posix.fd_t, packet: []u8, ip: [4]u8) !void {
    const dest_addr = std.posix.sockaddr{ .family = std.posix.AF.INET, .data = [14]u8{ 0, 0, ip[0], ip[1], ip[2], ip[3], 0, 0, 0, 0, 0, 0, 0, 0 } };

    _ = try std.posix.sendto(socket, packet, 0, &dest_addr, @sizeOf(std.posix.sockaddr));
}

fn setup_socket() !std.posix.fd_t {
    const sockfd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.RAW, std.posix.IPPROTO.TCP);
    errdefer std.posix.close(sockfd);

    try std.posix.setsockopt(sockfd, std.posix.IPPROTO.IP, std.os.linux.IP.HDRINCL, &[_]u8{1});
    return sockfd;
}

fn calc_checksum(arr: []u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    while (i < arr.len - 1) : (i += 2) {
        const upperByte = @as(u16, @intCast(arr[i])) << 8;
        const lowerByte = @as(u16, @intCast(arr[i + 1]));
        const combinedValue = upperByte + lowerByte;
        sum += combinedValue;

        std.debug.print("Combined Value: {}\n", .{sum});
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    std.debug.print("{}\n", .{sum});

    sum = ~sum & 0xFFFF;
    std.debug.print("{}\n", .{sum});

    return @as(u16, @intCast(sum));
}

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
