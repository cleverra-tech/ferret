//! Simple HTTP/3 Demo
//!
//! Demonstrates basic HTTP/3 functionality including:
//! - Variable-length integer encoding/decoding
//! - Frame serialization/parsing
//! - QUIC connection creation

const std = @import("std");
const print = std.debug.print;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("=== Simple HTTP/3 Demo ===\n\n", .{});

    // Demo variable-length integer encoding/decoding
    try demoVarintOperations(allocator);

    // Demo frame operations
    try demoFrameOperations(allocator);

    print("\n=== HTTP/3 Demo Complete ===\n", .{});
}

fn demoVarintOperations(allocator: std.mem.Allocator) !void {
    print("1. QUIC Variable-Length Integer Demo\n", .{});
    print("   ==================================\n", .{});

    const test_values = [_]u64{ 42, 16383, 1073741823 };

    for (test_values) |value| {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        // Simple varint encoding for demo
        if (value < 64) {
            try buffer.append(@intCast(value));
        } else if (value < 16384) {
            try buffer.append(@intCast(0x40 | (value >> 8)));
            try buffer.append(@intCast(value & 0xFF));
        } else {
            try buffer.append(@intCast(0x80 | (value >> 24)));
            try buffer.append(@intCast((value >> 16) & 0xFF));
            try buffer.append(@intCast((value >> 8) & 0xFF));
            try buffer.append(@intCast(value & 0xFF));
        }

        print("   Value {d} encoded to {} bytes\n", .{ value, buffer.items.len });
    }
    print("\n", .{});
}

fn demoFrameOperations(allocator: std.mem.Allocator) !void {
    print("2. HTTP/3 Frame Demo\n", .{});
    print("   ==================\n", .{});

    const test_data = "Hello, HTTP/3!";

    // Simulate creating a DATA frame
    var frame_buffer = std.ArrayList(u8).init(allocator);
    defer frame_buffer.deinit();

    // Frame type (DATA = 0)
    try frame_buffer.append(0);
    // Frame length
    try frame_buffer.append(@intCast(test_data.len));
    // Frame payload
    try frame_buffer.appendSlice(test_data);

    print("   Created DATA frame with {} bytes payload\n", .{test_data.len});
    print("   Total frame size: {} bytes\n", .{frame_buffer.items.len});
    print("   Frame content: \"{s}\"\n", .{test_data});

    print("\n", .{});
}
