//! Socket performance benchmark and demonstration

const std = @import("std");
const ferret = @import("ferret");
const Socket = ferret.Socket;
const SocketManager = ferret.SocketManager;
const SocketAddress = ferret.SocketAddress;
const Protocol = ferret.Protocol;
const Reactor = ferret.Reactor;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Socket Performance Benchmark ===\n", .{});

    // Create reactor and socket manager
    var reactor = try Reactor.init(allocator);
    defer reactor.deinit();

    var socket_manager = SocketManager.init(allocator, &reactor);
    defer socket_manager.deinit();

    std.log.info("--- Socket Address Parsing Performance ---", .{});
    try benchmarkAddressParsing();

    std.log.info("\n--- Socket Creation Performance ---", .{});
    try benchmarkSocketCreation(allocator, &socket_manager);

    std.log.info("\n--- Socket API Demonstration ---", .{});
    try demonstrateSocketAPI(allocator, &socket_manager);

    std.log.info("\n=== Benchmark Complete ===", .{});
}

fn benchmarkAddressParsing() !void {
    const iterations = 100_000;

    // IPv4 parsing benchmark
    const start_ipv4 = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        const addr = try SocketAddress.parse("127.0.0.1", 8080);
        _ = addr;
    }
    const ipv4_time = std.time.nanoTimestamp() - start_ipv4;

    // IPv6 parsing benchmark
    const start_ipv6 = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        const addr = try SocketAddress.parse("::1", 8080);
        _ = addr;
    }
    const ipv6_time = std.time.nanoTimestamp() - start_ipv6;

    // Unix socket parsing benchmark
    const start_unix = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        const addr = try SocketAddress.parse("/tmp/socket", null);
        _ = addr;
    }
    const unix_time = std.time.nanoTimestamp() - start_unix;

    const ipv4_ns_per_op = @as(f64, @floatFromInt(ipv4_time)) / @as(f64, @floatFromInt(iterations));
    const ipv6_ns_per_op = @as(f64, @floatFromInt(ipv6_time)) / @as(f64, @floatFromInt(iterations));
    const unix_ns_per_op = @as(f64, @floatFromInt(unix_time)) / @as(f64, @floatFromInt(iterations));

    std.log.info("Address parsing ({} iterations):", .{iterations});
    std.log.info("  IPv4: {d:.2} ns/op ({d:.2} ops/sec)", .{ ipv4_ns_per_op, 1_000_000_000.0 / ipv4_ns_per_op });
    std.log.info("  IPv6: {d:.2} ns/op ({d:.2} ops/sec)", .{ ipv6_ns_per_op, 1_000_000_000.0 / ipv6_ns_per_op });
    std.log.info("  Unix: {d:.2} ns/op ({d:.2} ops/sec)", .{ unix_ns_per_op, 1_000_000_000.0 / unix_ns_per_op });
}

fn benchmarkSocketCreation(allocator: std.mem.Allocator, manager: *SocketManager) !void {
    const iterations = 10_000;

    // TCP socket creation benchmark
    const start = std.time.nanoTimestamp();
    var sockets = std.ArrayList(Socket).init(allocator);
    defer sockets.deinit();

    for (0..iterations) |_| {
        const addr = try SocketAddress.parse("127.0.0.1", 0);
        const socket = try manager.createSocket(.tcp, addr);
        try sockets.append(socket);
    }

    const creation_time = std.time.nanoTimestamp() - start;

    // Cleanup benchmark
    const cleanup_start = std.time.nanoTimestamp();
    for (sockets.items) |socket| {
        try socket.close();
    }
    const cleanup_time = std.time.nanoTimestamp() - cleanup_start;

    const creation_ns_per_op = @as(f64, @floatFromInt(creation_time)) / @as(f64, @floatFromInt(iterations));
    const cleanup_ns_per_op = @as(f64, @floatFromInt(cleanup_time)) / @as(f64, @floatFromInt(iterations));

    std.log.info("Socket lifecycle ({} iterations):", .{iterations});
    std.log.info("  Creation: {d:.2} ns/op ({d:.2} ops/sec)", .{ creation_ns_per_op, 1_000_000_000.0 / creation_ns_per_op });
    std.log.info("  Cleanup: {d:.2} ns/op ({d:.2} ops/sec)", .{ cleanup_ns_per_op, 1_000_000_000.0 / cleanup_ns_per_op });
}

fn demonstrateSocketAPI(allocator: std.mem.Allocator, manager: *SocketManager) !void {
    _ = allocator;

    // Demonstrate address parsing
    std.log.info("Creating socket addresses...", .{});
    const ipv4_addr = try SocketAddress.parse("127.0.0.1", 8080);
    const ipv6_addr = try SocketAddress.parse("::1", 8080);
    const unix_addr = try SocketAddress.parse("/tmp/test_socket", null);

    std.log.info("  IPv4 address: 127.0.0.1:8080", .{});
    std.log.info("  IPv6 address: [::1]:8080", .{});
    std.log.info("  Unix socket: /tmp/test_socket", .{});

    // Test address families
    std.log.info("Address families:", .{});
    std.log.info("  IPv4 family: {}", .{ipv4_addr.getFamily()});
    std.log.info("  IPv6 family: {}", .{ipv6_addr.getFamily()});
    std.log.info("  Unix family: {}", .{unix_addr.getFamily()});

    // Demonstrate socket creation
    std.log.info("\nCreating sockets...", .{});
    const tcp_socket = try manager.createSocket(.tcp, ipv4_addr);
    const udp_socket = try manager.createSocket(.udp, ipv4_addr);

    std.log.info("  TCP socket created: UUID={}, valid={}", .{ tcp_socket.uuid.id, tcp_socket.isValid() });
    std.log.info("  UDP socket created: UUID={}, valid={}", .{ udp_socket.uuid.id, udp_socket.isValid() });

    // Check socket states
    const tcp_state = try tcp_socket.getState();
    const udp_state = try udp_socket.getState();
    std.log.info("  TCP socket state: {}", .{tcp_state});
    std.log.info("  UDP socket state: {}", .{udp_state});

    // Demonstrate protocol structure
    std.log.info("\nDemonstrating protocol callbacks...", .{});
    const protocol = Protocol{
        .onData = testOnData,
        .onReady = testOnReady,
        .onClose = testOnClose,
        .onError = testOnError,
        .user_data = null,
    };

    std.log.info("  Protocol callbacks configured:", .{});
    std.log.info("    onData: {}", .{protocol.onData != null});
    std.log.info("    onReady: {}", .{protocol.onReady != null});
    std.log.info("    onClose: {}", .{protocol.onClose != null});
    std.log.info("    onError: {}", .{protocol.onError != null});

    // Demonstrate socket operations
    std.log.info("\nTesting socket operations...", .{});

    // Test write operations (will fail since socket is not connected)
    const test_data = "Hello, Socket!";
    const write_result = tcp_socket.write(test_data);
    std.log.info("  Write result (expected failure): {any}", .{write_result});

    // Test read operations
    var read_buffer: [1024]u8 = undefined;
    const read_result = tcp_socket.read(&read_buffer);
    std.log.info("  Read result: {any}", .{read_result});

    // Clean up
    std.log.info("\nCleaning up sockets...", .{});
    try tcp_socket.close();
    try udp_socket.close();

    std.log.info("  Sockets closed successfully", .{});
    std.log.info("  TCP socket valid after close: {}", .{tcp_socket.isValid()});
    std.log.info("  UDP socket valid after close: {}", .{udp_socket.isValid()});
}

// Test protocol callback functions
fn testOnData(socket: Socket, data: []const u8) void {
    std.log.info("Protocol onData: socket={}, data_len={}", .{ socket.uuid.id, data.len });
}

fn testOnReady(socket: Socket) void {
    std.log.info("Protocol onReady: socket={}", .{socket.uuid.id});
}

fn testOnClose(socket: Socket) void {
    std.log.info("Protocol onClose: socket={}", .{socket.uuid.id});
}

fn testOnError(socket: Socket, err: ferret.SocketError) void {
    std.log.info("Protocol onError: socket={}, error={}", .{ socket.uuid.id, err });
}
