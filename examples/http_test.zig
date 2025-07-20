//! Simple HTTP unified API test
const std = @import("std");
const ferret = @import("ferret");
const Http = ferret.Http;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== HTTP Unified API Test ===", .{});

    // Test HTTP client creation
    std.log.info("--- HTTP Client ---", .{});
    var client = Http.Client.init(allocator);
    defer client.deinit();

    std.log.info("[OK] Client created with default protocol: {s}", .{client.default_version.toString()});

    // Test request creation
    std.log.info("--- HTTP Request ---", .{});
    var request = Http.Request.init(allocator, .GET, "https://example.com/api/users");
    defer request.deinit();

    try request.setHeader("User-Agent", "Ferret-Test/1.0");
    try request.setHeader("Accept", "application/json");

    std.log.info("[OK] Request created:", .{});
    std.log.info("  Method: {s}", .{request.method.toString()});
    std.log.info("  URI: {s}", .{request.uri});
    std.log.info("  Version: {s}", .{request.version.toString()});
    std.log.info("  Headers: {}", .{request.headers.count()});

    // Test response creation
    std.log.info("--- HTTP Response ---", .{});
    var response = Http.Response.init(allocator, .ok);
    defer response.deinit();

    try response.setHeader("Content-Type", "application/json");
    try response.setHeader("Server", "Ferret-Server/1.0");
    response.setBody("{\"message\": \"Hello from HTTP test!\"}");

    std.log.info("[OK] Response created:", .{});
    std.log.info("  Status: {} {s}", .{ @intFromEnum(response.status), response.status.phrase() });
    std.log.info("  Version: {s}", .{response.version.toString()});
    std.log.info("  Successful: {}", .{response.isSuccessful()});
    std.log.info("  Body length: {}", .{if (response.body) |body| body.len else 0});

    // Test server creation
    std.log.info("--- HTTP Server ---", .{});
    const server_addr = std.net.Address.parseIp("127.0.0.1", 8080) catch unreachable;
    var server = Http.Server.init(allocator, server_addr);
    defer server.deinit();

    std.log.info("[OK] Server created:", .{});
    std.log.info("  Address: {any}", .{server.address});
    std.log.info("  Default version: {s}", .{server.default_version.toString()});

    // Test different HTTP methods
    std.log.info("--- HTTP Methods ---", .{});
    const methods = [_]Http.Method{ .GET, .POST, .PUT, .DELETE, .HEAD, .OPTIONS, .PATCH };

    for (methods) |method| {
        std.log.info("{s}: safe={}, idempotent={}", .{ method.toString(), method.isSafe(), method.isIdempotent() });
    }

    // Test status codes
    std.log.info("--- Status Codes ---", .{});
    const statuses = [_]Http.StatusCode{ .ok, .created, .not_found, .internal_server_error };

    for (statuses) |status| {
        std.log.info("{}: {s} ({s})", .{ @intFromEnum(status), status.phrase(), @tagName(status.class()) });
    }

    std.log.info("=== HTTP Test Complete ===", .{});
}
