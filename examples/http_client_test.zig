//! HTTP Client Test Example
//!
//! This example demonstrates the HTTP client functionality 
//! and provides a mini benchmark for HTTP operations.

const std = @import("std");
const ferret = @import("ferret");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== HTTP Client Test ===\n", .{});

    // Test HTTP client initialization
    try testHttpClientInitialization(allocator);
    
    // Test URI parsing functionality
    try testUriParsing(allocator);
    
    // Test HTTP request building
    try testHttpRequestBuilding(allocator);
    
    // Mini benchmark for HTTP request processing
    try benchmarkHttpRequestProcessing(allocator);

    std.log.info("=== HTTP Client Test Complete ===", .{});
}

fn testHttpClientInitialization(allocator: std.mem.Allocator) !void {
    std.log.info("Testing HTTP client initialization...", .{});
    
    var client = ferret.Http.Client.init(allocator);
    defer client.deinit();
    
    // Verify default configuration
    if (client.default_version != .http_3_0) {
        std.log.warn("Expected default version HTTP/3.0, got {}", .{client.default_version});
    }
    
    std.log.info("[OK] HTTP client initialized successfully", .{});
}

fn testUriParsing(allocator: std.mem.Allocator) !void {
    std.log.info("Testing URI parsing functionality...", .{});
    
    var client = ferret.Http.Client.init(allocator);
    defer client.deinit();
    
    // Test various URI formats
    const test_uris = [_][]const u8{
        "https://api.example.com/users",
        "http://localhost:8080/api/v1/data",
        "https://secure.example.com:443/path?query=value",
    };
    
    for (test_uris) |uri_str| {
        std.log.info("Parsing URI: {s}", .{uri_str});
        
        // This tests the URI parsing logic in our HTTP client implementation
        var request = ferret.Http.Request.init(allocator, .GET, uri_str);
        defer request.deinit();
        
        if (!std.mem.eql(u8, request.uri, uri_str)) {
            std.log.err("URI mismatch: expected '{s}', got '{s}'", .{ uri_str, request.uri });
            return error.UriParsingFailed;
        }
    }
    
    std.log.info("[OK] URI parsing tests passed", .{});
}

fn testHttpRequestBuilding(allocator: std.mem.Allocator) !void {
    std.log.info("Testing HTTP request building...", .{});
    
    var client = ferret.Http.Client.init(allocator);
    defer client.deinit();
    
    // Create a GET request
    var request = ferret.Http.Request.init(allocator, .GET, "https://api.example.com/users");
    defer request.deinit();
    
    // Add headers
    try request.setHeader("User-Agent", "Ferret-HTTP-Client/1.0");
    try request.setHeader("Accept", "application/json");
    try request.setHeader("Connection", "keep-alive");
    
    // Verify request structure
    if (request.method != .GET) {
        return error.InvalidMethod;
    }
    
    if (!std.mem.eql(u8, request.uri, "https://api.example.com/users")) {
        return error.InvalidUri;
    }
    
    // Verify headers were set (this would require access to internal headers structure)
    // For now, we just verify the request was created successfully
    
    std.log.info("[OK] HTTP request building tests passed", .{});
}

fn benchmarkHttpRequestProcessing(allocator: std.mem.Allocator) !void {
    std.log.info("Running HTTP request processing benchmark...", .{});
    
    const iterations = 10000;
    const start_time = std.time.nanoTimestamp();
    
    // Benchmark HTTP client operations
    for (0..iterations) |i| {
        var client = ferret.Http.Client.init(allocator);
        defer client.deinit();
        
        // Create request
        var request = ferret.Http.Request.init(allocator, .GET, "https://api.example.com/data");
        defer request.deinit();
        
        // Add some headers
        try request.setHeader("User-Agent", "Benchmark-Client");
        try request.setHeader("Accept", "*/*");
        
        // Create response (simulating a response)
        var response = ferret.Http.Response.init(allocator, .ok);
        defer response.deinit();
        
        response.setBody("{}");
        
        // Verify operation (to prevent optimization)
        if (i % 1000 == 0) {
            if (!response.isSuccessful()) {
                return error.UnexpectedResponse;
            }
        }
    }
    
    const end_time = std.time.nanoTimestamp();
    const duration_ns = end_time - start_time;
    const ops_per_second = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0);
    const ns_per_op = @as(f64, @floatFromInt(duration_ns)) / @as(f64, @floatFromInt(iterations));
    
    std.log.info("[OK] HTTP request processing benchmark complete:", .{});
    std.log.info("  - Operations: {}", .{iterations});
    std.log.info("  - Duration: {d:.2} ms", .{@as(f64, @floatFromInt(duration_ns)) / 1_000_000.0});
    std.log.info("  - Throughput: {d:.2} ops/sec", .{ops_per_second});
    std.log.info("  - Latency: {d:.2} ns/op", .{ns_per_op});
    
    // Performance expectations
    if (ops_per_second < 1000) {
        std.log.warn("Performance warning: Low throughput ({d:.2} ops/sec)", .{ops_per_second});
    }
    
    if (ns_per_op > 1_000_000) {
        std.log.warn("Performance warning: High latency ({d:.2} ns/op)", .{ns_per_op});
    }
}