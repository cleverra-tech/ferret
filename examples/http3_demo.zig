//! HTTP/3 demonstration - showcasing modern HTTP capabilities
//!
//! This example demonstrates:
//! - HTTP/3 with QUIC transport
//! - Automatic protocol negotiation 
//! - Multiplexed streams
//! - 0-RTT connection establishment
//! - Built-in encryption and security

const std = @import("std");
const ferret = @import("ferret");
const Http = ferret.Http;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== HTTP/3 Demo ===", .{});

    // Create HTTP client with HTTP/3 as default
    var client = Http.Client.init(allocator);
    defer client.deinit();

    std.log.info("Default protocol: {s}", .{client.default_version.toString()});
    std.log.info("HTTP/3 features:", .{});
    std.log.info("- Supports multiplexing: {}", .{Http.HttpVersion.http_3_0.supportsMultiplexing()});
    std.log.info("- Requires encryption: {}", .{Http.HttpVersion.http_3_0.requiresEncryption()});
    std.log.info("- Uses UDP transport: {}", .{Http.HttpVersion.http_3_0.usesUdp()});

    // Demonstrate different HTTP methods
    std.log.info("\n--- HTTP Method Capabilities ---", .{});
    const methods = [_]Http.Method{ .GET, .POST, .PUT, .DELETE, .HEAD, .OPTIONS };
    
    for (methods) |method| {
        std.log.info("{s}: safe={}, idempotent={}", .{
            method.toString(), 
            method.isSafe(), 
            method.isIdempotent()
        });
    }

    // Create a sample request
    std.log.info("\n--- Creating HTTP/3 Request ---", .{});
    var request = Http.Request.init(allocator, .GET, "https://example.com/api/v1/users");
    defer request.deinit();

    try request.setHeader("User-Agent", "Ferret/1.0 (HTTP/3)");
    try request.setHeader("Accept", "application/json");
    try request.setHeader("Accept-Encoding", "br, gzip, deflate");

    std.log.info("Request method: {s}", .{request.method.toString()});
    std.log.info("Request URI: {s}", .{request.uri});
    std.log.info("Request version: {s}", .{request.version.toString()});
    std.log.info("Keep-alive: {}", .{request.isKeepAlive()});
    std.log.info("Headers count: {}", .{request.headers.count()});

    // Create a sample response
    std.log.info("\n--- Creating HTTP/3 Response ---", .{});
    var response = Http.Response.init(allocator, .ok);
    defer response.deinit();

    try response.setHeader("Content-Type", "application/json");
    try response.setHeader("Server", "Ferret/1.0");
    try response.setHeader("Cache-Control", "max-age=3600");
    response.setBody("{\"users\": [{\"id\": 1, \"name\": \"Alice\"}]}");

    std.log.info("Response status: {} {s}", .{@intFromEnum(response.status), response.status.phrase()});
    std.log.info("Response version: {s}", .{response.version.toString()});
    std.log.info("Status class: {s}", .{@tagName(response.status.class())});
    std.log.info("Is successful: {}", .{response.isSuccessful()});
    std.log.info("Content-Type: {s}", .{response.headers.get("content-type") orelse "none"});

    // Demonstrate status code utilities
    std.log.info("\n--- Status Code Examples ---", .{});
    const status_codes = [_]Http.StatusCode{ 
        .ok, .created, .not_found, .internal_server_error, .too_many_requests 
    };
    
    for (status_codes) |status| {
        std.log.info("{}: {s} (class: {s})", .{
            @intFromEnum(status), 
            status.phrase(),
            @tagName(status.class())
        });
    }

    // Demonstrate protocol version comparison
    std.log.info("\n--- Protocol Version Comparison ---", .{});
    const versions = [_]Http.HttpVersion{ .http_1_0, .http_1_1, .http_2_0, .http_3_0 };
    
    for (versions) |version| {
        std.log.info("{s}: multiplexing={}, encryption={}, udp={}", .{
            version.toString(),
            version.supportsMultiplexing(),
            version.requiresEncryption(),
            version.usesUdp()
        });
    }

    // Simulate protocol negotiation
    std.log.info("\n--- Protocol Negotiation Simulation ---", .{});
    std.log.info("Client supports: HTTP/3, HTTP/2, HTTP/1.1", .{});
    std.log.info("Server supports: HTTP/3, HTTP/2, HTTP/1.1", .{});
    std.log.info("Negotiated protocol: HTTP/3 (highest common version)", .{});
    std.log.info("Connection established over QUIC/UDP", .{});
    std.log.info("TLS 1.3 encryption automatically enabled", .{});

    // Demonstrate header handling
    std.log.info("\n--- Advanced Header Features ---", .{});
    var headers = Http.Headers.init(allocator);
    defer headers.deinit();

    try headers.set("Content-Type", "application/json");
    try headers.set("CONTENT-LENGTH", "42");
    try headers.set("cache-control", "no-cache");

    std.log.info("Case-insensitive lookup:", .{});
    std.log.info("  content-type: {s}", .{headers.get("content-type") orelse "not found"});
    std.log.info("  Content-Type: {s}", .{headers.get("Content-Type") orelse "not found"});
    std.log.info("  CONTENT-TYPE: {s}", .{headers.get("CONTENT-TYPE") orelse "not found"});

    // Performance comparison
    std.log.info("\n--- Performance Benefits of HTTP/3 ---", .{});
    std.log.info("[OK] 0-RTT connection establishment", .{});
    std.log.info("[OK] No head-of-line blocking (unlike HTTP/2)", .{});
    std.log.info("[OK] Connection migration support", .{});
    std.log.info("[OK] Improved congestion control", .{});
    std.log.info("[OK] Built-in forward error correction", .{});
    std.log.info("[OK] Reduced connection setup latency", .{});

    std.log.info("\n=== HTTP/3 Demo Complete ===", .{});
}