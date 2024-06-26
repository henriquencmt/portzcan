portzcan :zap:
==============

Command-line tool and Zig library for port scanning.

Installation
------------

### As a command-line tool

Get the source code cloning the repo or downloading it from the [Releases page](https://github.com/henriquencmt/portzcan/releases).

Then build it with ```zig build```.

### As a library

Fetch the package.

```
zig fetch --save git+https://github.com/henriquencmt/portzcan
```

Update your _build.zig_.

```zig
const portzcan = b.dependency("portzcan", .{});
const portzcan_lib = b.addModule("lib", .{ .root_source_file = portzcan.path("lib/portzcan.zig") });

const exe = b.addExecutable(...);

exe.root_module.addImport("portzcan", portzcan_lib);
```

Usage
-----

### As a command-line tool

```
portzcan [-s] TARGET [PORTS]
```

Example

```
portzcan your-target.com 80,443,22
```

### As a library

Example

```zig
const std = @import("std");
const portzcan = @import("portzcan");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const addr_list = try std.net.getAddressList(allocator, "your-target.com", 0);

    var addr = addr_list.addrs[0];
    const ports = [_]u16{ 80, 8080, 22, 443 };

    const scanner = portzcan.TcpConnectScanner.init(allocator, &addr, null);   
    try scanner.scan(&ports);
}
```

Go to the [library API reference](https://henriquencmt.github.io/portzcan) for further documentation.

Contributing
------------

Contributions of any kind are welcome.
