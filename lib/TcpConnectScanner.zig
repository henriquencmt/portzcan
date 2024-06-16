const std = @import("std");
const posix = std.posix;
const os = std.os;

allocator: std.mem.Allocator,
addr: *std.net.Address,

pub fn init(allocator: std.mem.Allocator, addr: *std.net.Address) @This() {
    return .{
        .allocator = allocator,
        .addr = addr,
    };
}

pub fn scan(self: @This(), ports: []const u16) !void {
    const thr = try self.allocator.alloc(std.Thread, ports.len);
    for (thr, 0..) |*item, i| {
        self.addr.setPort(ports[i]);
        item.* = try std.Thread.spawn(.{}, connect, .{self.addr.*});
    }
    for (thr) |t| {
        t.join();
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

pub fn print(comptime message: []const u8, args: anytype) !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print(message, args);

    try bw.flush();
}
