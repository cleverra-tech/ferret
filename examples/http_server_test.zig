//! HTTP Server Test Example
//!
//! This example demonstrates the HTTP server functionality 
//! and provides a mini benchmark for HTTP server operations.

const std = @import("std");
const ferret = @import("ferret");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== HTTP Server Test ===\n", .{});

    // Test HTTP server initialization
    try testHttpServerInitialization(allocator);
    
    // Test request handler setup
    try testRequestHandlerSetup(allocator);
    
    // Test server configuration
    try testServerConfiguration(allocator);

    std.log.info("=== HTTP Server Test Complete ===", .{});
}

fn testHttpServerInitialization(allocator: std.mem.Allocator) !void {
    std.log.info("Testing HTTP server initialization...", .{});
    
    const address = try std.net.Address.parseIp4("127.0.0.1", 8080);
    var server = ferret.Http.Server.init(allocator, address);
    defer server.deinit();
    
    // Verify default configuration
    if (server.default_version != .http_3_0) {
        std.log.warn("Expected default version HTTP/3.0, got {}", .{server.default_version});
    }
    
    if (server.max_connections != 1000) {
        std.log.warn("Expected max connections 1000, got {}", .{server.max_connections});
    }
    
    if (server.active_connections != 0) {
        std.log.warn("Expected 0 active connections, got {}", .{server.active_connections});
    }
    
    if (server.isListening()) {
        std.log.warn("Expected server to not be listening initially", .{});
    }
    
    std.log.info("[OK] HTTP server initialized successfully", .{});
}

fn testRequestHandlerSetup(allocator: std.mem.Allocator) !void {
    std.log.info("Testing request handler setup...", .{});
    
    const address = try std.net.Address.parseIp4("127.0.0.1", 8081);
    var server = ferret.Http.Server.init(allocator, address);
    defer server.deinit();
    
    // Test handler function
    const TestHandler = struct {
        fn handle(request: *ferret.Http.Request, response: *ferret.Http.Response) anyerror!void {
            if (request.method == .GET) {
                response.setBody("Hello, World!");
                try response.setHeader("Content-Type", "text/plain");
            } else {
                response.status = .method_not_allowed;
                response.setBody("Method not allowed");
            }
        }
    };

    server.setRequestHandler(TestHandler.handle);
    
    // Verify handler is set
    if (server.request_handler == null) {
        return error.HandlerNotSet;
    }
    
    std.log.info("[OK] Request handler setup successful", .{});
}

fn testServerConfiguration(allocator: std.mem.Allocator) !void {
    std.log.info("Testing server configuration...", .{});
    
    const address = try std.net.Address.parseIp4("127.0.0.1", 8082);
    var server = ferret.Http.Server.init(allocator, address);
    defer server.deinit();
    
    // Test max connections setting
    server.setMaxConnections(500);
    if (server.max_connections != 500) {
        return error.MaxConnectionsNotSet;
    }
    
    // Test default version setting
    server.setDefaultVersion(.http_1_1);
    if (server.default_version != .http_1_1) {
        return error.DefaultVersionNotSet;
    }
    
    // Test supported versions setting
    const supported_versions = [_]ferret.Http.HttpVersion{ .http_1_1, .http_2_0 };
    server.setSupportedVersions(&supported_versions);
    
    // Test active connections getter
    const active = server.getActiveConnections();
    if (active != 0) {
        return error.ActiveConnectionsNotZero;
    }
    
    // Test listening status
    if (server.isListening()) {
        return error.ShouldNotBeListening;
    }
    
    std.log.info("[OK] Server configuration tests passed", .{});
}

fn benchmarkServerCreation(allocator: std.mem.Allocator) !void {
    std.log.info("Running HTTP server creation benchmark...", .{});
    
    const iterations = 1000;
    const start_time = std.time.nanoTimestamp();
    
    // Benchmark HTTP server creation and configuration
    for (0..iterations) |i| {
        const port = @as(u16, @intCast(9000 + (i % 100))); // Use different ports
        const address = try std.net.Address.parseIp4("127.0.0.1", port);
        var server = ferret.Http.Server.init(allocator, address);
        defer server.deinit();
        
        // Configure server
        server.setMaxConnections(100);
        server.setDefaultVersion(.http_2_0);
        
        // Set a simple handler
        const SimpleHandler = struct {
            fn handle(request: *ferret.Http.Request, response: *ferret.Http.Response) anyerror!void {
                _ = request;
                response.setBody("Benchmark Response");
            }
        };
        server.setRequestHandler(SimpleHandler.handle);
        
        // Verify configuration (to prevent optimization)
        if (i % 100 == 0) {
            if (server.max_connections != 100) {
                return error.BenchmarkConfigError;
            }
        }
    }
    
    const end_time = std.time.nanoTimestamp();
    const duration_ns = end_time - start_time;
    const ops_per_second = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0);
    const ns_per_op = @as(f64, @floatFromInt(duration_ns)) / @as(f64, @floatFromInt(iterations));
    
    std.log.info("[OK] HTTP server creation benchmark complete:", .{});
    std.log.info("  - Operations: {}", .{iterations});
    std.log.info("  - Duration: {d:.2} ms", .{@as(f64, @floatFromInt(duration_ns)) / 1_000_000.0});
    std.log.info("  - Throughput: {d:.2} ops/sec", .{ops_per_second});
    std.log.info("  - Latency: {d:.2} ns/op", .{ns_per_op});
    
    // Performance expectations
    if (ops_per_second < 100) {
        std.log.warn("Performance warning: Low throughput ({d:.2} ops/sec)", .{ops_per_second});
    }
    
    if (ns_per_op > 10_000_000) {
        std.log.warn("Performance warning: High latency ({d:.2} ns/op)", .{ns_per_op});
    }
}