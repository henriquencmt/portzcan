const std = @import("std");
const posix = std.posix;

const portzcan = @import("portzcan");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);

    var settings: Settings = .{};

    // TODO output to file
    // const file = try std.fs.cwd().createFile("<file-name-from-args>", .{});
    // defer file.close();
    // const settings.writer = file.writer();

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
        const scanner = portzcan.TcpSynScanner.init(allocator, &addr, settings.output);
        try scanner.scan(settings.ports);
    } else {
        std.debug.print("default mode\n", .{});
        const scanner = portzcan.TcpConnectScanner.init(allocator, &addr, settings.output);
        try scanner.scan(settings.ports);
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

const Settings = struct {
    mode: []const u8 = "default",
    address: []u8 = undefined,
    ports: []const u16 = &[7]u16{ 22, 80, 443, 8080, 12017, 5432, 8081 },
    output: std.fs.File.Writer = std.io.getStdOut().writer(),
};
