pub const TcpConnectScanner = @import("TcpConnectScanner.zig");
pub const TcpSynScanner = @import("tcp_syn.zig").TcpSynScanner;

test "portzcan" {
    _ = TcpSynScanner;
    _ = TcpConnectScanner;
}
