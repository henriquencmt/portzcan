const std = @import("std");
const os = std.os;
const posix = std.posix;
const tcp_syn = @import("tcp_syn.zig");

pub fn print(comptime message: []const u8, args: anytype) !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print(message, args);

    try bw.flush();
}

pub fn connect(address: std.net.Address, port: u16) !void {
    var sockfd: posix.fd_t = undefined;
    sockfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    errdefer posix.close(sockfd);

    _ = try posix.fcntl(sockfd, posix.F.SETFL, os.linux.SOCK.NONBLOCK);

    if (posix.connect(sockfd, &address.any, address.getOsSockLen())) |_| {
        try print("1: port {} is open\n", .{port});
    } else |err| switch (err) {
        error.ConnectionRefused => try print("port {} is closed\n", .{port}),
        error.WouldBlock => {
            const epollfd = try posix.epoll_create1(0);
            var ev: os.linux.epoll_event = .{
                .events = os.linux.EPOLL.OUT,
                .data = .{ .fd = sockfd },
            };
            _ = try posix.epoll_ctl(epollfd, os.linux.EPOLL.CTL_ADD, sockfd, &ev);

            var events: [1]os.linux.epoll_event = undefined;
            const nfds = posix.epoll_wait(epollfd, &events, 1000);
            switch (nfds) {
                0 => try print("timeout trying to connect to port {}\n", .{port}),
                1 => {
                    var so_error: i32 = undefined;
                    var size: u32 = @sizeOf(u32);
                    const rc = os.linux.getsockopt(sockfd, posix.SOL.SOCKET, posix.SO.ERROR, @as([*]u8, @ptrCast(&so_error)), &size);
                    switch (rc) {
                        0 => try print("2: port {} is open\n", .{port}),
                        else => try print("socket not connected trying to connect to port {}\n", .{port}),
                    }
                },
                else => try print("epoll_wait() failure trying to connect to port {}\n", .{port}),
            }
        },
        else => try print("failure trying to connect to port {}. error: {any}\n", .{ port, err }),
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);

    var settings: Settings = .{};

    switch (args.len) {
        2 => {
            settings.address = args[1][0..args[1].len];
        },
        3 => {
            if (std.mem.eql(u8, args[1][0..args[1].len], "-s")) {
                settings.mode = "tcpsyn";
                settings.address = args[2][0..args[2].len];
            } else if (true) { // TODO match regex pattern
                settings.address = args[1][0..args[1].len];
                settings.ports = try parsePorts(args[2], allocator);
            } else {
                std.debug.print("Usage: {s} [OPTIONS] ADDRESS [PORTS]\n", .{args[0]});
                std.posix.exit(1);
            }
        },
        4 => {
            settings.address = args[2][0..args[2].len];
            if (std.mem.eql(u8, args[1][0..args[1].len], "-s") and true) { // TODO match regex pattern
                settings.mode = "synack";
                settings.address = args[2][0..args[2].len];
                settings.ports = try parsePorts(args[3], allocator);
            } else {
                std.debug.print("Usage: {s} [OPTIONS] ADDRESS [PORTS]\n", .{args[0]});
                std.posix.exit(1);
            }
        },
        else => {
            std.debug.print("Usage: {s} [OPTIONS] ADDRESS [PORTS]\n", .{args[0]});
            std.posix.exit(1);
        },
    }

    const addr_list = try std.net.getAddressList(allocator, settings.address, 0);
    defer addr_list.deinit();

    var addr = addr_list.addrs[0];

    const thr = try allocator.alloc(std.Thread, settings.ports.len);

    if (std.mem.eql(u8, settings.mode, "tcpsyn")) {
        const s_addr = 172 << 24 | 30 << 16 | 188 << 8 | 242;
        for (thr, 0..) |*item, i| {
            // TODO addr.setPort(ports[i]);
            item.* = try std.Thread.spawn(.{}, tcp_syn.run, .{ s_addr, addr.in.sa.addr, settings.ports[i] });
        }
    } else {
        for (thr, 0..) |*item, i| {
            addr.setPort(settings.ports[i]);
            item.* = try std.Thread.spawn(.{}, connect, .{ addr, settings.ports[i] });
        }
    }

    for (thr) |t| {
        t.join();
    }
}

fn parsePorts(ports_arg: [:0]u8, allocator: std.mem.Allocator) ![]u16 {
    var ports = std.ArrayList(u16).init(allocator);
    var curr: []u8 = try allocator.alloc(u8, 5);
    var byte_count: usize = 0;

    for (ports_arg) |port| {
        if (port == 44) { // comma
            try ports.append(try std.fmt.parseInt(u16, curr[0..byte_count], 10));
            allocator.free(curr);
            curr = try allocator.alloc(u8, 5);
            byte_count = 0;
        } else {
            curr[byte_count] = port;
            byte_count += 1;
        }
    }
    try ports.append(try std.fmt.parseInt(u16, curr[0..byte_count], 10));
    allocator.free(curr);

    return ports.items;
}

const Settings = struct {
    mode: []const u8 = "default",
    address: []u8 = undefined,
    ports: []const u16 = &[7]u16{ 22, 80, 443, 8080, 12017, 5432, 8081 },
};
