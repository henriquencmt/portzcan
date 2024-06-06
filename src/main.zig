const std = @import("std");
const os = std.os;
const posix = std.posix;
const tcp_syn = @import("tcp_syn.zig");

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
                settings.mode = "tcpsyn";
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

    if (std.mem.eql(u8, settings.mode, "tcpsyn")) {
        std.debug.print("stealth mode\n", .{});
        try tcp_syn.run(allocator, &addr, settings.ports);
    } else {
        std.debug.print("default mode\n", .{});
        const thr = try allocator.alloc(std.Thread, settings.ports.len);
        for (thr, 0..) |*item, i| {
            addr.setPort(settings.ports[i]);
            item.* = try std.Thread.spawn(.{}, connect, .{addr});
        }
        for (thr) |t| {
            t.join();
        }
    }
}

pub fn connect(address: std.net.Address) !void {
    var sockfd: posix.fd_t = undefined;
    sockfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    errdefer posix.close(sockfd);

    _ = try posix.fcntl(sockfd, posix.F.SETFL, os.linux.SOCK.NONBLOCK);

    if (posix.connect(sockfd, &address.any, address.getOsSockLen())) |_| {
        try print("port {} is open\n", .{address.getPort()});
    } else |err| switch (err) {
        error.ConnectionRefused => try print("port {} is closed\n", .{address.getPort()}),
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
                0 => try print("timeout trying to connect to port {}\n", .{address.getPort()}),
                1 => {
                    var so_error: i32 = undefined;
                    var size: u32 = @sizeOf(u32);
                    const rc = os.linux.getsockopt(sockfd, posix.SOL.SOCKET, posix.SO.ERROR, @as([*]u8, @ptrCast(&so_error)), &size);
                    switch (rc) {
                        0 => try print("port {} is open\n", .{address.getPort()}),
                        else => try print("socket not connected trying to connect to port {}\n", .{address.getPort()}),
                    }
                },
                else => try print("epoll_wait() failure trying to connect to port {}\n", .{address.getPort()}),
            }
        },
        else => try print("failure trying to connect to port {}. error: {any}\n", .{ address.getPort(), err }),
    }
}

fn parsePorts(ports_arg: [:0]u8, allocator: std.mem.Allocator) ![]u16 {
    var ports = std.ArrayList(u16).init(allocator);
    var curr: []u8 = try allocator.alloc(u8, 5);
    var byte_count: usize = 0;

    for (ports_arg) |char| {
        if (char == 44) { // comma
            try ports.append(try std.fmt.parseInt(u16, curr[0..byte_count], 10));
            allocator.free(curr);
            curr = try allocator.alloc(u8, 5);
            byte_count = 0;
        } else {
            curr[byte_count] = char;
            byte_count += 1;
        }
    }
    try ports.append(try std.fmt.parseInt(u16, curr[0..byte_count], 10));
    allocator.free(curr);

    return ports.items;
}

test parsePorts {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const p = try parsePorts(@as([:0]u8, @constCast("80,65535,8080")), allocator);

    const expected = [_]u16{ 80, 65535, 8080 };
    try std.testing.expect(std.mem.eql(u16, &expected, p));
}

pub fn print(comptime message: []const u8, args: anytype) !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print(message, args);

    try bw.flush();
}

pub const Settings = struct {
    mode: []const u8 = "default",
    address: []u8 = undefined,
    ports: []const u16 = &[7]u16{ 22, 80, 443, 8080, 12017, 5432, 8081 },
};
