//! Unified HTTP API demonstration
//!
//! This example demonstrates:
//! - Unified HTTP API across all protocol versions
//! - Automatic protocol negotiation
//! - Consistent request/response handling
//! - Protocol-agnostic application development

const std = @import("std");
const ferret = @import("ferret");
const Http = ferret.Http;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Unified HTTP API Demo ===", .{});

    // Create unified HTTP client (defaults to HTTP/3)
    std.log.info("\n--- HTTP Client Creation ---", .{});
    var client = Http.Client.init(allocator);
    defer client.deinit();

    std.log.info("[OK] HTTP client initialized", .{});
    std.log.info("  Default protocol: {s}", .{client.default_version.toString()});
    std.log.info("  Timeout: {} ms", .{client.timeout_ms});
    std.log.info("  Automatic fallback: Enabled", .{});

    // Demonstrate unified request creation
    std.log.info("\n--- Unified Request Creation ---", .{});
    var request = Http.Request.init(allocator, .GET, "https://api.example.com/users");
    defer request.deinit();

    std.log.info("[OK] Request created with unified API", .{});
    std.log.info("  Method: {s}", .{request.method.toString()});
    std.log.info("  URI: {s}", .{request.uri});
    std.log.info("  Version: {s} (automatic)", .{request.version.toString()});

    // Add headers using unified API
    try request.setHeader("User-Agent", "Ferret-Client/1.0");
    try request.setHeader("Accept", "application/json");
    try request.setHeader("Accept-Encoding", "br, gzip, deflate");
    try request.setHeader("Connection", "keep-alive");

    std.log.info("  Headers added: {}", .{request.headers.count()});
    std.log.info("  Keep-alive: {}", .{request.isKeepAlive()});

    // Demonstrate different HTTP methods
    std.log.info("\n--- HTTP Methods Demonstration ---", .{});
    const methods = [_]Http.Method{ .GET, .POST, .PUT, .DELETE, .HEAD, .OPTIONS, .PATCH };

    for (methods) |method| {
        var test_request = Http.Request.init(allocator, method, "/api/endpoint");
        defer test_request.deinit();

        std.log.info("{s}:", .{method.toString()});
        std.log.info("  Safe: {}", .{method.isSafe()});
        std.log.info("  Idempotent: {}", .{method.isIdempotent()});
        std.log.info("  Default version: {s}", .{test_request.version.toString()});
    }

    // Demonstrate unified response handling
    std.log.info("\n--- Unified Response Handling ---", .{});
    var response = Http.Response.init(allocator, .ok);
    defer response.deinit();

    try response.setHeader("Content-Type", "application/json");
    try response.setHeader("Server", "Ferret-Server/1.0");
    try response.setHeader("Cache-Control", "max-age=3600");
    response.setBody("{\"message\": \"Hello from unified HTTP API!\"}");

    std.log.info("[OK] Response created with unified API", .{});
    std.log.info("  Status: {} {s}", .{ @intFromEnum(response.status), response.status.phrase() });
    std.log.info("  Version: {s}", .{response.version.toString()});
    std.log.info("  Class: {s}", .{@tagName(response.status.class())});
    std.log.info("  Successful: {}", .{response.isSuccessful()});

    // Protocol version capabilities
    std.log.info("\n--- Protocol Capabilities Matrix ---", .{});
    const versions = [_]Http.HttpVersion{ .http_1_1, .http_2_0, .http_3_0 };

    std.log.info("Protocol    │ Multiplex │ Encryption │ UDP Transport", .{});
    std.log.info("────────────┼───────────┼────────────┼──────────────", .{});
    for (versions) |version| {
        std.log.info("{s:<11} │ {s:<9} │ {s:<10} │ {s}", .{
            version.toString(),
            if (version.supportsMultiplexing()) "[OK]" else "[X]",
            if (version.requiresEncryption()) "Required" else "Optional",
            if (version.usesUdp()) "[OK]" else "[X]",
        });
    }

    // Status code demonstrations
    std.log.info("\n--- Status Code Handling ---", .{});
    const status_examples = [_]Http.StatusCode{
        .ok, .created, .accepted, .no_content,
        .moved_permanently, .found, .not_modified,
        .bad_request, .unauthorized, .forbidden, .not_found,
        .internal_server_error, .bad_gateway, .service_unavailable
    };

    for (status_examples) |status| {
        var test_response = Http.Response.init(allocator, status);
        defer test_response.deinit();

        std.log.info("{}: {s} ({s})", .{
            @intFromEnum(status),
            status.phrase(),
            @tagName(status.class())
        });
    }

    // Protocol negotiation simulation
    std.log.info("\n--- Protocol Negotiation Simulation ---", .{});
    
    const scenarios = [_]struct {
        name: []const u8,
        server_support: []const Http.HttpVersion,
        expected: Http.HttpVersion,
    }{
        .{
            .name = "Modern CDN",
            .server_support = &[_]Http.HttpVersion{ .http_3_0, .http_2_0, .http_1_1 },
            .expected = .http_3_0,
        },
        .{
            .name = "Corporate proxy",
            .server_support = &[_]Http.HttpVersion{ .http_2_0, .http_1_1 },
            .expected = .http_2_0,
        },
        .{
            .name = "Legacy system",
            .server_support = &[_]Http.HttpVersion{.http_1_1},
            .expected = .http_1_1,
        },
    };

    for (scenarios) |scenario| {
        const negotiated = scenario.server_support[0]; // Highest supported
        std.log.info("{s}:", .{scenario.name});
        std.log.info("  Server supports: {s}", .{scenario.server_support[0].toString()});
        std.log.info("  Negotiated: {s}", .{negotiated.toString()});
        std.log.info("  Benefits: {s}", .{
            switch (negotiated) {
                .http_3_0 => "0-RTT, no HOL blocking, migration",
                .http_2_0 => "Multiplexing, header compression, server push",
                .http_1_1 => "Wide compatibility, simplicity",
                else => "Basic HTTP functionality",
            }
        });
    }

    // Headers demonstration
    std.log.info("\n--- Case-Insensitive Headers ---", .{});
    var headers = Http.Headers.init(allocator);
    defer headers.deinit();

    try headers.set("Content-Type", "application/json");
    try headers.set("CACHE-CONTROL", "no-cache");
    try headers.set("accept-encoding", "gzip, br");

    std.log.info("Headers set with different cases:", .{});
    std.log.info("  content-type: {s}", .{headers.get("content-type") orelse "not found"});
    std.log.info("  Content-Type: {s}", .{headers.get("Content-Type") orelse "not found"});
    std.log.info("  CONTENT-TYPE: {s}", .{headers.get("CONTENT-TYPE") orelse "not found"});
    std.log.info("  Total headers: {}", .{headers.count()});

    // Client configuration
    std.log.info("\n--- Client Configuration ---", .{});
    std.log.info("Current configuration:", .{});
    std.log.info("  Default version: {s}", .{client.default_version.toString()});
    std.log.info("  Timeout: {} ms", .{client.timeout_ms});

    client.setDefaultVersion(.http_2_0);
    client.setTimeout(10000);

    std.log.info("After reconfiguration:", .{});
    std.log.info("  Default version: {s}", .{client.default_version.toString()});
    std.log.info("  Timeout: {} ms", .{client.timeout_ms});

    // Server initialization demo
    std.log.info("\n--- HTTP Server Configuration ---", .{});
    const server_addr = std.net.Address.parseIp("0.0.0.0", 8080) catch unreachable;
    var server = Http.Server.init(allocator, server_addr);
    defer server.deinit();

    std.log.info("[OK] Server initialized", .{});
    std.log.info("  Listen address: {any}", .{server.address});
    std.log.info("  Default version: {s}", .{server.default_version.toString()});
    std.log.info("  Supported versions: HTTP/3, HTTP/2, HTTP/1.1", .{});

    // Performance comparison
    std.log.info("\n--- Performance Benefits Summary ---", .{});
    std.log.info("Unified API provides:", .{});
    std.log.info("  [OK] Protocol-agnostic development", .{});
    std.log.info("  [OK] Automatic optimization selection", .{});
    std.log.info("  [OK] Graceful degradation", .{});
    std.log.info("  [OK] Future-proof architecture", .{});
    std.log.info("  [OK] Consistent error handling", .{});
    std.log.info("  [OK] Connection pooling and reuse", .{});

    std.log.info("\nHTTP/3 advantages when available:", .{});
    std.log.info("  • ~40% faster page loads", .{});
    std.log.info("  • 0-RTT reconnection", .{});
    std.log.info("  • Improved mobile performance", .{});
    std.log.info("  • No connection blocking", .{});

    // Migration path
    std.log.info("\n--- Application Migration Benefits ---", .{});
    std.log.info("Legacy HTTP/1.1 applications can:", .{});
    std.log.info("  1. Switch to Ferret's unified API", .{});
    std.log.info("  2. Instantly get HTTP/3 by default", .{});
    std.log.info("  3. Maintain compatibility with old servers", .{});
    std.log.info("  4. Future-proof for HTTP/4+", .{});

    std.log.info("\n=== Unified HTTP API Demo Complete ===", .{});
    std.log.info("Your applications are now ready for the future of HTTP!", .{});
}