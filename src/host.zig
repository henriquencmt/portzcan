const std = @import("std");
const c = @cImport({
    @cInclude("ifaddrs.h");
    @cInclude("netdb.h");
});

pub fn main() !void {
    const addr = try getHostAddr();
    std.debug.print("{any}", .{addr});
}

pub fn getHostAddr() ![4]u8 {
    var host_addr: [4]u8 = undefined;
    var ifaddr: ?*c.struct_ifaddrs = undefined;
    var _host: [c.NI_MAXHOST]u8 = undefined;
    const host = _host[0..];

    if (c.getifaddrs(&ifaddr) == -1) {
        @panic("getifaddrs");
    }
    defer c.freeifaddrs(ifaddr);

    var ifa = ifaddr;
    while (ifa) |addr| : (ifa = addr.ifa_next) {
        if (addr.ifa_addr == null) continue;

        const family = addr.ifa_addr.*.sa_family;

        if (family == c.AF_INET or family == c.AF_INET6) {
            const s = c.getnameinfo(
                addr.ifa_addr,
                if (family == c.AF_INET) @sizeOf(c.struct_sockaddr_in) else @sizeOf(c.struct_sockaddr_in6),
                host,
                c.NI_MAXHOST,
                null,
                0,
                c.NI_NUMERICHOST,
            );
            if (s != 0) {
                std.debug.print("getnameinfo() failed: {}\n", .{s});
                @panic("getnameinfo() failed");
            }

            if (family == c.AF_INET) {
                var address: [4]u8 = undefined;
                var curr: usize = 0;
                var first_byte: usize = 0;
                for (host, 0..) |char, i| {
                    if (char == 0) {
                        address[curr] = try std.fmt.parseInt(u8, host[first_byte..i], 10);
                        break;
                    }
                    if (char == 46) { // dot
                        address[curr] = try std.fmt.parseInt(u8, host[first_byte..i], 10);
                        first_byte = i + 1;
                        curr += 1;
                    }
                }

                if (!std.mem.eql(u8, &address, &[_]u8{ 127, 0, 0, 1 })) host_addr = address;
            }
        }
    }

    return host_addr;
}
