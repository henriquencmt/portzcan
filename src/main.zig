const std = @import("std");
const os = std.os;
const posix = std.posix;

pub fn print(comptime message: []const u8, args: anytype) !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print(message, args);

    try bw.flush();
}

pub fn connect(address: std.net.Address, port: u16) !void {
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
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
                0 => try print("socket timeout trying to connect to port {}\n", .{port}),
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
    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: {s} <address>\n", .{args[0]});
        std.posix.exit(1);
    }

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const addr_list = try std.net.getAddressList(allocator, args[1], 80);
    defer addr_list.deinit();

    var addr = addr_list.addrs[0];
    const ports = [_]u16{ 22, 80, 443, 8080, 12017, 5432, 8081 };

    var thr: [ports.len]std.Thread = undefined;

    for (&thr, 0..) |*item, i| {
        addr.setPort(ports[i]);
        item.* = try std.Thread.spawn(.{}, connect, .{ addr, ports[i] });
    }

    for (thr) |t| {
        t.join();
    }
}
