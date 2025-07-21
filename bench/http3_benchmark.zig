//! HTTP/3 Performance Benchmark
//!
//! This benchmark measures the performance of HTTP/3 operations:
//! - QUIC packet processing
//! - Frame serialization/deserialization
//! - QPACK header compression/decompression
//! - Variable-length integer encoding/decoding
//! - Connection establishment simulation

const std = @import("std");
const ferret = @import("ferret");
const http3 = ferret.Http3;
const testing = std.testing;
const print = std.debug.print;

const ITERATIONS = 1000;
const WARMUP_ITERATIONS = 100;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("=== HTTP/3 Performance Benchmark ===\n\n", .{});

    // 1. QUIC Varint Encoding/Decoding
    try benchmarkVarintOperations();

    // 2. HTTP/3 Frame Operations
    try benchmarkFrameOperations(allocator);

    // 3. QPACK Header Compression
    try benchmarkQpackOperations(allocator);

    // 4. QUIC Connection Operations
    try benchmarkConnectionOperations(allocator);

    print("\n=== HTTP/3 Benchmark Complete ===\n", .{});
}

fn benchmarkVarintOperations() !void {
    print("1. QUIC Variable-Length Integer Operations\n", .{});
    print("   =======================================\n", .{});

    // Test values covering different varint lengths
    const test_values = [_]u64{ 42, 16383, 1073741823, 4611686018427387903 };

    // Encoding benchmark
    {
        var buffer = std.ArrayList(u8).init(std.heap.page_allocator);
        defer buffer.deinit();

        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            for (test_values) |value| {
                buffer.clearRetainingCapacity();
                http3.encodeVarint(buffer.writer(), value) catch unreachable;
            }
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            for (test_values) |value| {
                buffer.clearRetainingCapacity();
                http3.encodeVarint(buffer.writer(), value) catch unreachable;
            }
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const total_ops = ITERATIONS * test_values.len;
        const ops_per_sec = (@as(f64, @floatFromInt(total_ops)) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Varint encoding: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per encoding: {d:.2} ns\n", .{@as(f64, @floatFromInt(duration)) / @as(f64, @floatFromInt(total_ops))});
    }

    // Decoding benchmark
    {
        var encoded_values = std.ArrayList([]u8).init(std.heap.page_allocator);
        defer {
            for (encoded_values.items) |encoded| {
                std.heap.page_allocator.free(encoded);
            }
            encoded_values.deinit();
        }

        // Pre-encode test values
        for (test_values) |value| {
            var buffer = std.ArrayList(u8).init(std.heap.page_allocator);
            defer buffer.deinit();
            try http3.encodeVarint(buffer.writer(), value);
            try encoded_values.append(try std.heap.page_allocator.dupe(u8, buffer.items));
        }

        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            for (encoded_values.items) |encoded| {
                var pos: usize = 0;
                _ = http3.decodeVarint(encoded, &pos) catch unreachable;
            }
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            for (encoded_values.items) |encoded| {
                var pos: usize = 0;
                _ = http3.decodeVarint(encoded, &pos) catch unreachable;
            }
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const total_ops = ITERATIONS * encoded_values.items.len;
        const ops_per_sec = (@as(f64, @floatFromInt(total_ops)) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Varint decoding: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per decoding: {d:.2} ns\n\n", .{@as(f64, @floatFromInt(duration)) / @as(f64, @floatFromInt(total_ops))});
    }
}

fn benchmarkFrameOperations(allocator: std.mem.Allocator) !void {
    print("2. HTTP/3 Frame Operations\n", .{});
    print("   ========================\n", .{});

    const test_data = "This is test data for HTTP/3 frame operations benchmark";

    // Frame serialization benchmark
    {
        const frame = http3.Http3Frame.data(test_data);

        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();
            frame.serialize(buffer.writer()) catch unreachable;
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();
            frame.serialize(buffer.writer()) catch unreachable;
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, @floatFromInt(ITERATIONS)) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Frame serialization: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per serialization: {d:.2} μs\n", .{@as(f64, @floatFromInt(duration)) / (@as(f64, @floatFromInt(ITERATIONS)) * 1000.0)});
    }

    // Frame parsing benchmark
    {
        // Pre-serialize a frame
        const frame = http3.Http3Frame.data(test_data);
        var serialized = std.ArrayList(u8).init(allocator);
        defer serialized.deinit();
        try frame.serialize(serialized.writer());

        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            _ = http3.Http3Frame.parse(serialized.items) catch unreachable;
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            _ = http3.Http3Frame.parse(serialized.items) catch unreachable;
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, @floatFromInt(ITERATIONS)) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Frame parsing: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per parsing: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (@as(f64, @floatFromInt(ITERATIONS)) * 1000.0)});
    }
}

fn benchmarkQpackOperations(allocator: std.mem.Allocator) !void {
    print("3. QPACK Header Compression\n", .{});
    print("   =========================\n", .{});

    // Header encoding benchmark
    {
        var encoder = http3.QpackEncoder.init(allocator);
        defer encoder.deinit();

        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();
            encoder.encodeHeader(&buffer, ":method", "GET") catch unreachable;
            encoder.encodeHeader(&buffer, ":path", "/api/v1/data") catch unreachable;
            encoder.encodeHeader(&buffer, "user-agent", "ferret-benchmark/1.0") catch unreachable;
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();
            encoder.encodeHeader(&buffer, ":method", "GET") catch unreachable;
            encoder.encodeHeader(&buffer, ":path", "/api/v1/data") catch unreachable;
            encoder.encodeHeader(&buffer, "user-agent", "ferret-benchmark/1.0") catch unreachable;
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, @floatFromInt(ITERATIONS)) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   QPACK encoding (3 headers): {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per encoding: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (@as(f64, @floatFromInt(ITERATIONS)) * 1000.0)});
    }
}

fn benchmarkConnectionOperations(allocator: std.mem.Allocator) !void {
    print("4. QUIC Connection Operations\n", .{});
    print("   ===========================\n", .{});

    // Connection creation benchmark
    {
        const local_addr = try std.net.Address.parseIp("127.0.0.1", 443);
        const remote_addr = try std.net.Address.parseIp("127.0.0.1", 8080);

        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            var conn = http3.QuicConnection.init(allocator, false, local_addr, remote_addr);
            conn.deinit();
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            var conn = http3.QuicConnection.init(allocator, false, local_addr, remote_addr);
            conn.deinit();
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, @floatFromInt(ITERATIONS)) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Connection creation: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per connection: {d:.2} μs\n", .{@as(f64, @floatFromInt(duration)) / (@as(f64, @floatFromInt(ITERATIONS)) * 1000.0)});
    }

    // Stream creation benchmark
    {
        const local_addr = try std.net.Address.parseIp("127.0.0.1", 443);
        const remote_addr = try std.net.Address.parseIp("127.0.0.1", 8080);
        var conn = http3.QuicConnection.init(allocator, false, local_addr, remote_addr);
        defer conn.deinit();

        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            _ = conn.createNewStream() catch unreachable;
        }

        // Reset connection for clean benchmark
        conn.deinit();
        conn = http3.QuicConnection.init(allocator, false, local_addr, remote_addr);

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            _ = conn.createNewStream() catch unreachable;
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, @floatFromInt(ITERATIONS)) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Stream creation: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per stream: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (@as(f64, @floatFromInt(ITERATIONS)) * 1000.0)});
    }
}
