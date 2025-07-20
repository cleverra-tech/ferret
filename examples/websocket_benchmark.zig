//! WebSocket Connection Upgrade and Message Processing Benchmark
//!
//! This benchmark measures the performance of WebSocket connection upgrade handling,
//! message processing, and frame serialization/deserialization.

const std = @import("std");
const ferret = @import("ferret");
const testing = std.testing;
const print = std.debug.print;

const ITERATIONS = 100_000;
const WARMUP_ITERATIONS = 10_000;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("=== WebSocket Connection Upgrade and Processing Benchmark ===\n\n", .{});

    // 1. WebSocket Handshake Benchmark
    try benchmarkHandshake(allocator);
    
    // 2. WebSocket Frame Parsing Benchmark
    try benchmarkFrameParsing(allocator);
    
    // 3. WebSocket Message Handling Benchmark
    try benchmarkMessageHandling(allocator);
    
    // 4. WebSocket Connection Upgrade Benchmark
    try benchmarkConnectionUpgrade(allocator);
    
    // 5. WebSocket Fragmentation Benchmark
    try benchmarkFragmentation(allocator);

    print("\n=== WebSocket Benchmark Complete ===\n", .{});
}

fn benchmarkHandshake(allocator: std.mem.Allocator) !void {
    print("1. WebSocket Handshake Performance\n", .{});
    print("   ================================\n", .{});

    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    
    // Warmup
    for (0..WARMUP_ITERATIONS) |_| {
        const accept_key = try ferret.WebSocket.Handshake.generateAcceptKey(allocator, client_key);
        allocator.free(accept_key);
    }
    
    // Benchmark
    const start_time = std.time.nanoTimestamp();
    for (0..ITERATIONS) |_| {
        const accept_key = try ferret.WebSocket.Handshake.generateAcceptKey(allocator, client_key);
        allocator.free(accept_key);
    }
    const end_time = std.time.nanoTimestamp();
    
    const duration = end_time - start_time;
    const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));
    
    print("   Handshake key generation: {d:.2} ops/sec\n", .{ops_per_sec});
    print("   Average time per handshake: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
}

fn benchmarkFrameParsing(allocator: std.mem.Allocator) !void {
    print("2. WebSocket Frame Parsing Performance\n", .{});
    print("   ==================================\n", .{});

    // Create a sample text frame
    const text_frame = ferret.WebSocket.Frame{
        .header = ferret.WebSocket.FrameHeader{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .masked = false,
            .payload_length = 13,
            .mask_key = null,
            .header_size = 2,
        },
        .payload = "Hello, World!",
    };
    
    const serialized = try text_frame.serialize(allocator);
    defer allocator.free(serialized);
    
    // Warmup
    for (0..WARMUP_ITERATIONS) |_| {
        var parser = ferret.WebSocket.Parser.init(allocator);
        defer parser.deinit();
        _ = try parser.parse(serialized);
    }
    
    // Benchmark
    const start_time = std.time.nanoTimestamp();
    for (0..ITERATIONS) |_| {
        var parser = ferret.WebSocket.Parser.init(allocator);
        defer parser.deinit();
        if (try parser.parse(serialized)) |frame| {
            if (frame.payload.len > 0) allocator.free(frame.payload);
        }
    }
    const end_time = std.time.nanoTimestamp();
    
    const duration = end_time - start_time;
    const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));
    const throughput_mbps = (ops_per_sec * @as(f64, @floatFromInt(serialized.len)) * 8.0) / (1024.0 * 1024.0);
    
    print("   Frame parsing: {d:.2} ops/sec\n", .{ops_per_sec});
    print("   Throughput: {d:.2} Mbps\n", .{throughput_mbps});
    print("   Average time per frame: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
}

fn benchmarkMessageHandling(allocator: std.mem.Allocator) !void {
    print("3. WebSocket Message Handling Performance\n", .{});
    print("   ======================================\n", .{});

    var connection = ferret.WebSocket.Connection.init(allocator, true);
    defer connection.deinit();
    connection.state = .connected;
    
    const test_message = "Hello, WebSocket world! This is a test message.";
    const text_frame = ferret.WebSocket.Frame{
        .header = ferret.WebSocket.FrameHeader{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .masked = false,
            .payload_length = test_message.len,
            .mask_key = null,
            .header_size = 2,
        },
        .payload = test_message,
    };
    
    const serialized = try text_frame.serialize(allocator);
    defer allocator.free(serialized);
    
    // Warmup
    for (0..WARMUP_ITERATIONS) |_| {
        const messages = try connection.handleData(serialized);
        for (messages) |*msg| {
            var mut_msg = msg;
            mut_msg.deinit();
        }
        allocator.free(messages);
    }
    
    // Benchmark
    const start_time = std.time.nanoTimestamp();
    for (0..ITERATIONS) |_| {
        const messages = try connection.handleData(serialized);
        for (messages) |*msg| {
            var mut_msg = msg;
            mut_msg.deinit();
        }
        allocator.free(messages);
    }
    const end_time = std.time.nanoTimestamp();
    
    const duration = end_time - start_time;
    const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));
    const throughput_mbps = (ops_per_sec * @as(f64, @floatFromInt(test_message.len)) * 8.0) / (1024.0 * 1024.0);
    
    print("   Message handling: {d:.2} ops/sec\n", .{ops_per_sec});
    print("   Throughput: {d:.2} Mbps\n", .{throughput_mbps});
    print("   Average time per message: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
}

fn benchmarkConnectionUpgrade(allocator: std.mem.Allocator) !void {
    print("4. WebSocket Connection Upgrade Performance\n", .{});
    print("   ========================================\n", .{});

    const MockHeaders = struct {
        data: std.StringHashMap([]const u8),
        
        const Self = @This();
        
        pub fn init(alloc: std.mem.Allocator) Self {
            return Self{ .data = std.StringHashMap([]const u8).init(alloc) };
        }
        
        pub fn deinit(self: *Self) void {
            self.data.deinit();
        }
        
        pub fn put(self: *Self, key: []const u8, value: []const u8) !void {
            try self.data.put(key, value);
        }
        
        pub fn get(self: Self, key: []const u8) ?[]const u8 {
            return self.data.get(key);
        }
    };
    
    var headers = MockHeaders.init(allocator);
    defer headers.deinit();
    
    try headers.put("upgrade", "websocket");
    try headers.put("connection", "upgrade");
    try headers.put("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
    try headers.put("sec-websocket-version", "13");
    
    // Warmup
    for (0..WARMUP_ITERATIONS) |_| {
        const response = try ferret.WebSocket.UpgradeHandler.performUpgrade(allocator, headers);
        allocator.free(response.accept_key);
        if (response.subprotocol) |subproto| allocator.free(subproto);
    }
    
    // Benchmark
    const start_time = std.time.nanoTimestamp();
    for (0..ITERATIONS) |_| {
        const response = try ferret.WebSocket.UpgradeHandler.performUpgrade(allocator, headers);
        allocator.free(response.accept_key);
        if (response.subprotocol) |subproto| allocator.free(subproto);
    }
    const end_time = std.time.nanoTimestamp();
    
    const duration = end_time - start_time;
    const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));
    
    print("   Connection upgrade: {d:.2} ops/sec\n", .{ops_per_sec});
    print("   Average time per upgrade: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
}

fn benchmarkFragmentation(allocator: std.mem.Allocator) !void {
    print("5. WebSocket Message Fragmentation Performance\n", .{});
    print("   ===========================================\n", .{});

    var connection = ferret.WebSocket.Connection.init(allocator, true);
    defer connection.deinit();
    connection.state = .connected;
    
    // Create 2-fragment message
    const fragment1 = ferret.WebSocket.Frame{
        .header = ferret.WebSocket.FrameHeader{
            .fin = false,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .text,
            .masked = false,
            .payload_length = 5,
            .mask_key = null,
            .header_size = 2,
        },
        .payload = "Hello",
    };
    
    const fragment2 = ferret.WebSocket.Frame{
        .header = ferret.WebSocket.FrameHeader{
            .fin = true,
            .rsv1 = false,
            .rsv2 = false,
            .rsv3 = false,
            .opcode = .continuation,
            .masked = false,
            .payload_length = 8,
            .mask_key = null,
            .header_size = 2,
        },
        .payload = ", World!",
    };
    
    const serialized1 = try fragment1.serialize(allocator);
    defer allocator.free(serialized1);
    const serialized2 = try fragment2.serialize(allocator);
    defer allocator.free(serialized2);
    
    // Warmup
    for (0..WARMUP_ITERATIONS) |_| {
        const messages1 = try connection.handleData(serialized1);
        allocator.free(messages1);
        
        const messages2 = try connection.handleData(serialized2);
        for (messages2) |*msg| {
            var mut_msg = msg;
            mut_msg.deinit();
        }
        allocator.free(messages2);
    }
    
    // Benchmark
    const start_time = std.time.nanoTimestamp();
    for (0..ITERATIONS) |_| {
        const messages1 = try connection.handleData(serialized1);
        allocator.free(messages1);
        
        const messages2 = try connection.handleData(serialized2);
        for (messages2) |*msg| {
            var mut_msg = msg;
            mut_msg.deinit();
        }
        allocator.free(messages2);
    }
    const end_time = std.time.nanoTimestamp();
    
    const duration = end_time - start_time;
    const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));
    
    print("   Fragmented message assembly: {d:.2} ops/sec\n", .{ops_per_sec});
    print("   Average time per fragmented message: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
}