const std = @import("std");
const ferret = @import("ferret");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const version_str = try ferret.versionString(allocator);
    defer allocator.free(version_str);

    std.log.info("Ferret v{s} - High-performance web framework for Zig", .{version_str});

    // Demo the framework's core features
    try demoDataStructures(allocator);
    try demoHttp();

    std.log.info("Framework demo complete", .{});
}

fn demoDataStructures(allocator: std.mem.Allocator) !void {
    std.log.info("=== Data Structures Demo ===", .{});

    // String demo
    var string = ferret.String.init(allocator);
    defer string.deinit();
    try string.appendSlice("Hello, Ferret!");
    std.log.info("String: {s}", .{string.slice()});

    // Array demo
    var numbers = ferret.Array(i32).init(allocator);
    defer numbers.deinit();
    try numbers.append(42);
    try numbers.append(84);
    std.log.info("Array length: {}, first: {}", .{ numbers.len(), numbers.first().? });

    // HashMap demo
    var map = ferret.HashMap([]const u8, u32).init(allocator);
    defer map.deinit();
    try map.put("answer", 42);
    std.log.info("HashMap value: {}", .{map.get("answer").?});
}

fn demoHttp() !void {
    std.log.info("=== HTTP Protocols Demo ===", .{});

    std.log.info("Supported protocols:", .{});
    std.log.info("  HTTP/1.1: Basic web serving", .{});
    std.log.info("  HTTP/2: Multiplexing and server push", .{});
    std.log.info("  HTTP/3: QUIC transport with reduced latency", .{});
    std.log.info("  WebSocket: Real-time bidirectional communication", .{});
}
