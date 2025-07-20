//! HTTP Protocols Comparison Demo
//!
//! This example demonstrates:
//! - Comparison between HTTP/1.1, HTTP/2, and HTTP/3
//! - Protocol feature matrix
//! - Performance characteristics
//! - Use case recommendations
//! - Migration strategies

const std = @import("std");
const ferret = @import("ferret");
const Http = ferret.Http;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== HTTP Protocols Comparison ===", .{});

    // Protocol overview
    std.log.info("\n--- Protocol Overview ---", .{});
    const protocols = [_]Http.HttpVersion{ .http_1_1, .http_2_0, .http_3_0 };

    for (protocols) |protocol| {
        std.log.info("{s}:", .{protocol.toString()});
        std.log.info("  Transport: {s}", .{if (protocol.usesUdp()) "UDP (QUIC)" else "TCP"});
        std.log.info("  Multiplexing: {}", .{protocol.supportsMultiplexing()});
        std.log.info("  Encryption: {s}", .{if (protocol.requiresEncryption()) "Required" else "Optional"});
        std.log.info("", .{});
    }

    // Feature matrix
    std.log.info("--- Feature Matrix ---", .{});
    std.log.info("┌─────────────────────────┬─────────┬─────────┬─────────┐", .{});
    std.log.info("│ Feature                 │ HTTP/1.1│ HTTP/2  │ HTTP/3  │", .{});
    std.log.info("├─────────────────────────┼─────────┼─────────┼─────────┤", .{});
    std.log.info("│ Multiplexing            │   [X]     │   [OK]     │   [OK]     │", .{});
    std.log.info("│ Header Compression      │   [X]     │ HPACK   │ QPACK   │", .{});
    std.log.info("│ Server Push             │   [X]     │   [OK]     │   [OK]     │", .{});
    std.log.info("│ Binary Framing          │   [X]     │   [OK]     │   [OK]     │", .{});
    std.log.info("│ Built-in Encryption     │   [X]     │   [X]     │   [OK]     │", .{});
    std.log.info("│ Connection Migration    │   [X]     │   [X]     │   [OK]     │", .{});
    std.log.info("│ 0-RTT                   │   [X]     │   [X]     │   [OK]     │", .{});
    std.log.info("│ Head-of-line Blocking   │   [OK]     │ Partial │   [X]     │", .{});
    std.log.info("│ Flow Control            │   [X]     │   [OK]     │   [OK]     │", .{});
    std.log.info("│ Stream Prioritization   │   [X]     │   [OK]     │   [OK]     │", .{});
    std.log.info("└─────────────────────────┴─────────┴─────────┴─────────┘", .{});

    // Performance characteristics
    std.log.info("\n--- Performance Characteristics ---", .{});

    std.log.info("HTTP/1.1:", .{});
    std.log.info("  [OK] Simple and well-understood", .{});
    std.log.info("  [OK] Wide compatibility", .{});
    std.log.info("  [X] Limited parallelism (6-8 connections)", .{});
    std.log.info("  [X] Header overhead on every request", .{});
    std.log.info("  [X] Head-of-line blocking", .{});

    std.log.info("\nHTTP/2:", .{});
    std.log.info("  [OK] Request/response multiplexing", .{});
    std.log.info("  [OK] HPACK header compression", .{});
    std.log.info("  [OK] Server push capabilities", .{});
    std.log.info("  [OK] Stream prioritization", .{});
    std.log.info("  [WARN] TCP head-of-line blocking", .{});
    std.log.info("  [WARN] Complex connection management", .{});

    std.log.info("\nHTTP/3:", .{});
    std.log.info("  [OK] No head-of-line blocking", .{});
    std.log.info("  [OK] 0-RTT connection establishment", .{});
    std.log.info("  [OK] Connection migration", .{});
    std.log.info("  [OK] Built-in encryption (TLS 1.3)", .{});
    std.log.info("  [OK] Improved congestion control", .{});
    std.log.info("  [WARN] Newer protocol, limited support", .{});

    // Latency comparison simulation
    std.log.info("\n--- Latency Comparison (Simulated) ---", .{});

    // Simulate connection establishment times
    const conn_times = .{
        .http1 = 150, // TCP handshake + TLS handshake
        .http2 = 150, // Same as HTTP/1.1 but with protocol negotiation
        .http3_first = 200, // QUIC handshake with crypto
        .http3_resume = 0, // 0-RTT
    };

    std.log.info("Connection establishment latency (ms):", .{});
    std.log.info("  HTTP/1.1: {} ms", .{conn_times.http1});
    std.log.info("  HTTP/2:   {} ms", .{conn_times.http2});
    std.log.info("  HTTP/3 (first): {} ms", .{conn_times.http3_first});
    std.log.info("  HTTP/3 (0-RTT): {} ms", .{conn_times.http3_resume});

    // Request handling simulation
    std.log.info("\nConcurrent request handling (10 requests):", .{});
    std.log.info("  HTTP/1.1: ~{} ms (serial)", .{10 * 50});
    std.log.info("  HTTP/2:   ~{} ms (parallel)", .{50});
    std.log.info("  HTTP/3:   ~{} ms (parallel, optimized)", .{40});

    // Use case recommendations
    std.log.info("\n--- Use Case Recommendations ---", .{});

    std.log.info("[Mobile] Mobile Applications:", .{});
    std.log.info("  Recommended: HTTP/3", .{});
    std.log.info("  Reason: Connection migration, 0-RTT, reduced latency", .{});

    std.log.info("\n[Web] Web Applications:", .{});
    std.log.info("  Recommended: HTTP/3 with HTTP/2 fallback", .{});
    std.log.info("  Reason: Best performance with broad compatibility", .{});

    std.log.info("\n[IoT] IoT/Embedded:", .{});
    std.log.info("  Recommended: HTTP/1.1 or HTTP/2", .{});
    std.log.info("  Reason: Lower computational overhead", .{});

    std.log.info("\n[RT] Real-time Applications:", .{});
    std.log.info("  Recommended: HTTP/3", .{});
    std.log.info("  Reason: No head-of-line blocking, fast connection", .{});

    std.log.info("\n[Enterprise] Enterprise/Intranet:", .{});
    std.log.info("  Recommended: HTTP/2", .{});
    std.log.info("  Reason: Excellent performance with existing infrastructure", .{});

    // Migration strategy
    std.log.info("\n--- Migration Strategy ---", .{});

    std.log.info("Phase 1: HTTP/1.1 → HTTP/2", .{});
    std.log.info("  [OK] Enable HTTP/2 on server", .{});
    std.log.info("  [OK] Update client libraries", .{});
    std.log.info("  [OK] Optimize for multiplexing", .{});
    std.log.info("  [OK] Remove HTTP/1.1 workarounds", .{});

    std.log.info("\nPhase 2: HTTP/2 → HTTP/3", .{});
    std.log.info("  [OK] Deploy QUIC-capable load balancers", .{});
    std.log.info("  [OK] Update server to support HTTP/3", .{});
    std.log.info("  [OK] Implement graceful fallback", .{});
    std.log.info("  [OK] Monitor connection success rates", .{});

    // Ferret's approach
    std.log.info("\n--- Ferret's Unified Approach ---", .{});

    var client = Http.Client.init(allocator);
    defer client.deinit();

    std.log.info("Default protocol: {s}", .{client.default_version.toString()});
    std.log.info("Automatic fallback enabled: HTTP/3 → HTTP/2 → HTTP/1.1", .{});

    // Demonstrate protocol selection
    std.log.info("\nProtocol selection logic:", .{});
    const test_scenarios = [_]struct { name: []const u8, available: []const Http.HttpVersion }{
        .{ .name = "Modern server", .available = &[_]Http.HttpVersion{ .http_3_0, .http_2_0, .http_1_1 } },
        .{ .name = "HTTP/2 server", .available = &[_]Http.HttpVersion{ .http_2_0, .http_1_1 } },
        .{ .name = "Legacy server", .available = &[_]Http.HttpVersion{.http_1_1} },
    };

    for (test_scenarios) |scenario| {
        const selected = scenario.available[0]; // First available (highest priority)
        std.log.info("  {s}: {s}", .{ scenario.name, selected.toString() });
    }

    // Performance tips
    std.log.info("\n--- Performance Tips ---", .{});

    std.log.info("For HTTP/2:", .{});
    std.log.info("  • Combine small files to reduce overhead", .{});
    std.log.info("  • Use server push for critical resources", .{});
    std.log.info("  • Implement proper stream prioritization", .{});

    std.log.info("\nFor HTTP/3:", .{});
    std.log.info("  • Leverage 0-RTT for returning users", .{});
    std.log.info("  • Implement connection migration", .{});
    std.log.info("  • Optimize for mobile networks", .{});

    std.log.info("\nGeneral:", .{});
    std.log.info("  • Use appropriate compression (br > gzip > deflate)", .{});
    std.log.info("  • Implement proper caching strategies", .{});
    std.log.info("  • Monitor protocol adoption metrics", .{});

    // Future outlook
    std.log.info("\n--- Future Outlook ---", .{});
    std.log.info("[TREND] HTTP/3 adoption growing rapidly", .{});
    std.log.info("[STABLE] HTTP/2 remains stable and widely used", .{});
    std.log.info("[LEGACY] HTTP/1.1 legacy support still important", .{});
    std.log.info("[FUTURE] HTTP/4 research already underway", .{});

    std.log.info("\n=== HTTP Protocols Comparison Complete ===", .{});
}
