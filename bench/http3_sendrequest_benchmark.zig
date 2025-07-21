//! HTTP/3 sendRequest Benchmark
//!
//! This benchmark tests the HTTP/3 sendRequest implementation
//! and provides performance metrics for the core functionality.

const std = @import("std");
const ferret = @import("ferret");
const http3 = ferret.Http3;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== HTTP/3 sendRequest Benchmark ===\n", .{});

    // Test basic HTTP/3 sendRequest functionality
    try testSendRequestBasic(allocator);

    // Benchmark sendRequest performance
    try benchmarkSendRequest(allocator);

    std.log.info("=== HTTP/3 sendRequest Benchmark Complete ===", .{});
}

fn testSendRequestBasic(allocator: std.mem.Allocator) !void {
    std.log.info("Testing HTTP/3 sendRequest basic functionality...", .{});

    const local_addr = try std.net.Address.parseIp("127.0.0.1", 443);
    const remote_addr = try std.net.Address.parseIp("127.0.0.1", 8080);

    var conn = http3.QuicConnection.init(allocator, false, local_addr, remote_addr);
    defer conn.deinit();

    // Create test headers
    var headers = std.ArrayList(http3.QpackDecoder.QpackEntry).init(allocator);
    defer {
        for (headers.items) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        headers.deinit();
    }

    try headers.append(.{
        .name = try allocator.dupe(u8, "user-agent"),
        .value = try allocator.dupe(u8, "ferret-http3/1.0"),
    });
    try headers.append(.{
        .name = try allocator.dupe(u8, "accept"),
        .value = try allocator.dupe(u8, "application/json"),
    });

    // Test GET request
    const stream_id = try conn.sendRequest("GET", "/api/test", headers.items, null);
    std.log.info("GET request assigned stream ID: {}", .{stream_id});

    // Test POST request with body
    const body = "{'test': 'data'}";
    const post_stream_id = try conn.sendRequest("POST", "/api/create", headers.items, body);
    std.log.info("POST request assigned stream ID: {}", .{post_stream_id});

    if (post_stream_id == stream_id) {
        return error.InvalidStreamId;
    }

    std.log.info("[OK] HTTP/3 sendRequest basic functionality test passed", .{});
}

fn benchmarkSendRequest(allocator: std.mem.Allocator) !void {
    std.log.info("Running HTTP/3 sendRequest performance benchmark...", .{});

    const iterations = 10000;
    const start_time = std.time.nanoTimestamp();

    const local_addr = try std.net.Address.parseIp("127.0.0.1", 443);
    const remote_addr = try std.net.Address.parseIp("127.0.0.1", 8080);

    var conn = http3.QuicConnection.init(allocator, false, local_addr, remote_addr);
    defer conn.deinit();

    // Create reusable headers
    var headers = std.ArrayList(http3.QpackDecoder.QpackEntry).init(allocator);
    defer {
        for (headers.items) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        headers.deinit();
    }

    try headers.append(.{
        .name = try allocator.dupe(u8, "user-agent"),
        .value = try allocator.dupe(u8, "ferret-benchmark/1.0"),
    });
    try headers.append(.{
        .name = try allocator.dupe(u8, "content-type"),
        .value = try allocator.dupe(u8, "application/json"),
    });

    // Benchmark sendRequest operations
    var successful_requests: u32 = 0;
    for (0..iterations) |i| {
        const path = if (i % 2 == 0) "/api/get" else "/api/post";
        const method = if (i % 2 == 0) "GET" else "POST";
        const body: ?[]const u8 = if (i % 2 == 0) null else "{}";

        const stream_id = conn.sendRequest(method, path, headers.items, body) catch |err| {
            std.log.warn("Request {} failed: {}", .{ i, err });
            continue;
        };

        if (stream_id > 0) {
            successful_requests += 1;
        }

        // Prevent optimization and provide progress updates
        if (i % 1000 == 0) {
            std.log.info("Completed {} requests...", .{i});
        }
    }

    const end_time = std.time.nanoTimestamp();
    const duration_ns = end_time - start_time;
    const ops_per_second = @as(f64, @floatFromInt(successful_requests)) / (@as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0);
    const ns_per_op = @as(f64, @floatFromInt(duration_ns)) / @as(f64, @floatFromInt(successful_requests));

    std.log.info("[OK] HTTP/3 sendRequest benchmark complete:", .{});
    std.log.info("  - Total requests: {}", .{iterations});
    std.log.info("  - Successful requests: {}", .{successful_requests});
    std.log.info("  - Duration: {d:.2} ms", .{@as(f64, @floatFromInt(duration_ns)) / 1_000_000.0});
    std.log.info("  - Throughput: {d:.2} requests/sec", .{ops_per_second});
    std.log.info("  - Latency: {d:.2} ns/request", .{ns_per_op});

    // Performance expectations
    if (ops_per_second < 1000) {
        std.log.warn("Performance warning: Low throughput ({d:.2} req/sec)", .{ops_per_second});
    }

    if (ns_per_op > 1_000_000) {
        std.log.warn("Performance warning: High latency ({d:.2} ns/req)", .{ns_per_op});
    }

    if (successful_requests < iterations * 95 / 100) {
        std.log.warn("Reliability warning: High failure rate ({}/{} succeeded)", .{ successful_requests, iterations });
    }
}
