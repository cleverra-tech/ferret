//! Integration tests for Ferret framework
//!
//! These tests verify that different components work together correctly
//! and that the system meets its performance and correctness requirements.

const std = @import("std");
const testing = std.testing;
const ferret = @import("ferret");
const TestFramework = ferret.testing;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Ferret Integration Tests ===\n", .{});

    // Run all integration test suites
    try runHttpStackIntegrationTests(allocator);
    try runDataStructureIntegrationTests(allocator);
    try runCryptoIntegrationTests(allocator);
    try runMemoryManagementTests(allocator);
    try runPerformanceTests(allocator);

    std.log.info("\n=== All Integration Tests Complete ===", .{});
}

fn runHttpStackIntegrationTests(allocator: std.mem.Allocator) !void {
    std.log.info("--- HTTP Stack Integration Tests ---", .{});

    // Test HTTP/1.1 to HTTP/3 interoperability
    try testHttpVersionNegotiation(allocator);
    
    // Test complete request/response cycle
    try testHttpRequestResponseCycle(allocator);
    
    // Test header handling across HTTP versions
    try testHeaderCompatibility(allocator);

    std.log.info("[OK] HTTP Stack integration tests passed\n", .{});
}

fn testHttpVersionNegotiation(allocator: std.mem.Allocator) !void {
    // Test HTTP version selection with unified API
    var client = ferret.Http.Client.init(allocator);
    defer client.deinit();

    try TestFramework.Assert.equals(ferret.Http.HttpVersion, .http_3_0, client.default_version);

    // Test version fallback logic
    const versions = [_]ferret.Http.HttpVersion{ .http_1_1, .http_2_0, .http_3_0 };
    for (versions) |version| {
        try TestFramework.Assert.isTrue(version.toString().len > 0);
    }
}

fn testHttpRequestResponseCycle(allocator: std.mem.Allocator) !void {
    // Create request
    var request = ferret.Http.Request.init(allocator, .GET, "https://api.example.com/users");
    defer request.deinit();

    try request.setHeader("User-Agent", "Ferret-Test/1.0");
    try request.setHeader("Accept", "application/json");

    // Verify request structure
    try TestFramework.Assert.stringEquals("https://api.example.com/users", request.uri);
    try TestFramework.Assert.equals(ferret.Http.Method, .GET, request.method);

    // Create response
    var response = ferret.Http.Response.init(allocator, .ok);
    defer response.deinit();

    try response.setHeader("Content-Type", "application/json");
    response.setBody("{\"users\":[{\"id\":1,\"name\":\"Alice\"}]}");

    // Verify response structure
    try TestFramework.Assert.equals(ferret.Http.StatusCode, .ok, response.status);
    try TestFramework.Assert.isTrue(response.isSuccessful());
}

fn testHeaderCompatibility(allocator: std.mem.Allocator) !void {
    var headers = ferret.Http.Headers.init(allocator);
    defer headers.deinit();

    // Test case-insensitive operations
    try headers.set("Content-Type", "application/json");
    try headers.set("content-length", "42");
    try headers.set("CACHE-CONTROL", "no-cache");

    try TestFramework.Assert.stringEquals("application/json", headers.get("content-type") orelse "");
    try TestFramework.Assert.stringEquals("42", headers.get("Content-Length") orelse "");
    try TestFramework.Assert.stringEquals("no-cache", headers.get("cache-control") orelse "");
}

fn runDataStructureIntegrationTests(allocator: std.mem.Allocator) !void {
    std.log.info("--- Data Structure Integration Tests ---", .{});

    // Test Array, HashMap, and String working together
    try testDataStructureInteroperability(allocator);
    
    // Test Queue integration with I/O operations
    try testQueueIntegration(allocator);

    std.log.info("[OK] Data structure integration tests passed\n", .{});
}

fn testDataStructureInteroperability(allocator: std.mem.Allocator) !void {
    // Create complex data structure using multiple Ferret types
    var users = ferret.HashMap([]const u8, ferret.String).init(allocator);
    defer {
        var iter = users.iterator();
        while (iter.next()) |_| {
            // Note: In a real implementation, we'd need to access the stored values
            // to deinit them. For now, just deinit the map.
        }
        users.deinit();
    }

    var names = ferret.Array([]const u8).init(allocator);
    defer names.deinit();

    // Add test data
    try names.append("Alice");
    try names.append("Bob");
    try names.append("Charlie");

    for (names.slice()) |name| {
        var user_data = ferret.String.init(allocator);
        try user_data.print("User: {s}, Active: true", .{name});
        try users.put(name, user_data);
    }

    // Verify integration
    try TestFramework.Assert.equals(usize, 3, users.len());
    try TestFramework.Assert.equals(usize, 3, names.len());

    const alice_data = users.get("Alice");
    try TestFramework.Assert.isNotNull(ferret.String, alice_data);
    try TestFramework.Assert.stringContains(alice_data.?.slice(), "Alice");
}

fn testQueueIntegration(allocator: std.mem.Allocator) !void {
    // Test queue with different data types
    var string_queue = ferret.Queue(ferret.String).init(allocator);
    defer {
        while (string_queue.dequeue()) |item| {
            var mut_item = item; // Make mutable copy
            mut_item.deinit();
        }
        string_queue.deinit();
    }

    // Add strings to queue
    for (0..5) |i| {
        var str = ferret.String.init(allocator);
        try str.print("Message {}", .{i});
        try string_queue.enqueue(str);
    }

    try TestFramework.Assert.equals(usize, 5, string_queue.len());

    // Process queue
    var processed: usize = 0;
    while (string_queue.dequeue()) |item| {
        defer {
            var mut_item = item; // Make mutable copy
            mut_item.deinit();
        }
        try TestFramework.Assert.stringContains(item.slice(), "Message");
        processed += 1;
    }

    try TestFramework.Assert.equals(usize, 5, processed);
    try TestFramework.Assert.isTrue(string_queue.isEmpty());
}

fn runCryptoIntegrationTests(allocator: std.mem.Allocator) !void {
    std.log.info("--- Cryptography Integration Tests ---", .{});

    // Test hash integration with other components
    try testHashIntegration(allocator);
    
    // Test encryption/decryption cycle
    try testEncryptionIntegration(allocator);

    std.log.info("[OK] Cryptography integration tests passed\n", .{});
}

fn testHashIntegration(allocator: std.mem.Allocator) !void {
    // Test hashing with String and Array types
    var message = ferret.String.init(allocator);
    defer message.deinit();

    try message.appendSlice("Hello, Ferret!");
    
    const hash1 = ferret.hash.Hash.sha256(message.slice());
    const hash2 = ferret.hash.Hash.sha256("Hello, Ferret!");

    // Verify hashes match
    for (hash1.bytes, hash2.bytes) |a, b| {
        try TestFramework.Assert.equals(u8, a, b);
    }

    // Test with different content
    try message.appendSlice(" Additional content");
    const hash3 = ferret.hash.Hash.sha256(message.slice());
    
    // Verify hashes are different
    var different = false;
    for (hash1.bytes, hash3.bytes) |a, b| {
        if (a != b) {
            different = true;
            break;
        }
    }
    try TestFramework.Assert.isTrue(different);
}

fn testEncryptionIntegration(allocator: std.mem.Allocator) !void {
    const plaintext = "Secret message for encryption testing";
    const key = ferret.cipher.Aes256GcmKey.random();

    // Encrypt
    const encrypted = try ferret.cipher.Cipher.encryptAes256Gcm(
        allocator,
        plaintext,
        null,
        key,
    );
    defer allocator.free(encrypted.ciphertext);

    // Decrypt using the specific algorithm implementation
    const decrypted = try ferret.cipher.Aes256Gcm.decrypt(
        allocator,
        encrypted.ciphertext,
        encrypted.tag,
        null,
        key,
        encrypted.nonce,
    );
    defer allocator.free(decrypted);

    // Verify roundtrip
    try TestFramework.Assert.stringEquals(plaintext, decrypted);
}

fn runMemoryManagementTests(allocator: std.mem.Allocator) !void {
    std.log.info("--- Memory Management Tests ---", .{});

    // Test memory leak detection
    try testMemoryLeakDetection(allocator);
    
    // Test allocator stress
    try testAllocatorStress(allocator);

    std.log.info("[OK] Memory management tests passed\n", .{});
}

fn testMemoryLeakDetection(allocator: std.mem.Allocator) !void {
    var tracker = TestFramework.MemoryTracker.init(allocator);
    defer tracker.deinit();

    // Simulate some allocations
    const mem1 = try allocator.alloc(u8, 100);
    const mem2 = try allocator.alloc(u8, 200);
    const ptr1 = @intFromPtr(mem1.ptr);
    const ptr2 = @intFromPtr(mem2.ptr);
    
    try tracker.trackAllocation(ptr1, 100);
    try tracker.trackAllocation(ptr2, 200);

    // Free one allocation
    allocator.free(mem1);
    tracker.trackFree(ptr1);

    // Check stats
    const stats = tracker.getStats();
    try TestFramework.Assert.equals(usize, 300, stats.allocated);
    try TestFramework.Assert.equals(usize, 100, stats.freed);
    try TestFramework.Assert.equals(usize, 200, stats.leaked);

    // Clean up
    allocator.free(mem2);
}

fn testAllocatorStress(allocator: std.mem.Allocator) !void {
    const num_allocations = 1000;
    var allocations = std.ArrayList([]u8).init(allocator);
    defer {
        for (allocations.items) |allocation| {
            allocator.free(allocation);
        }
        allocations.deinit();
    }

    // Allocate many small blocks
    for (0..num_allocations) |i| {
        const size = (i % 100) + 1;
        const memory = try allocator.alloc(u8, size);
        @memset(memory, @truncate(i));
        try allocations.append(memory);
    }

    try TestFramework.Assert.equals(usize, num_allocations, allocations.items.len);

    // Verify data integrity
    for (allocations.items, 0..) |allocation, i| {
        const expected_value: u8 = @truncate(i);
        for (allocation) |byte| {
            try TestFramework.Assert.equals(u8, expected_value, byte);
        }
    }
}

fn runPerformanceTests(allocator: std.mem.Allocator) !void {
    std.log.info("--- Performance Integration Tests ---", .{});

    // Test JSON performance with real data
    try testJsonPerformance(allocator);
    
    // Test HTTP parsing performance
    try testHttpParsingPerformance(allocator);
    
    // Test data structure performance
    try testDataStructurePerformance(allocator);

    std.log.info("[OK] Performance integration tests passed\n", .{});
}

fn testJsonPerformance(allocator: std.mem.Allocator) !void {
    const json_data = 
        \\{
        \\  "users": [
        \\    {"id": 1, "name": "Alice", "email": "alice@example.com", "active": true, "score": 95.5},
        \\    {"id": 2, "name": "Bob", "email": "bob@example.com", "active": false, "score": 87.2},
        \\    {"id": 3, "name": "Charlie", "email": "charlie@example.com", "active": true, "score": 92.8}
        \\  ],
        \\  "metadata": {
        \\    "total": 3,
        \\    "timestamp": "2024-01-01T00:00:00Z",
        \\    "version": "1.0.0",
        \\    "nested": {
        \\      "deep": {
        \\        "value": "test"
        \\      }
        \\    }
        \\  }
        \\}
    ;

    var benchmark = TestFramework.Benchmark.init(allocator, 1000);
    const metrics = try benchmark.run(parseJsonTest, .{json_data});

    // Verify performance expectations
    try TestFramework.Assert.isTrue(metrics.opsPerSecond() > 100); // At least 100 ops/sec
    try TestFramework.Assert.isTrue(metrics.nsPerOp() < 10_000_000); // Less than 10ms per op

    std.log.info("JSON parsing: {d:.2} ops/sec, {d:.2} ns/op", .{
        metrics.opsPerSecond(),
        metrics.nsPerOp(),
    });
}

fn parseJsonTest(allocator: std.mem.Allocator, args: anytype) !void {
    const json_data = args[0];
    var value = try ferret.Json.parseFromString(allocator, json_data);
    defer value.deinit(allocator);
    
    // Verify parsing worked
    const obj = try value.getObject();
    _ = obj.get("users");
    _ = obj.get("metadata");
}

fn testHttpParsingPerformance(allocator: std.mem.Allocator) !void {
    const http_request = 
        "GET /api/users?page=1&limit=10 HTTP/1.1\r\n" ++
        "Host: api.example.com\r\n" ++
        "User-Agent: Ferret-Test/1.0\r\n" ++
        "Accept: application/json\r\n" ++
        "Authorization: Bearer token123\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n"
    ;

    var benchmark = TestFramework.Benchmark.init(allocator, 5000);
    const metrics = try benchmark.run(parseHttpTest, .{http_request});

    // Verify performance expectations
    try TestFramework.Assert.isTrue(metrics.opsPerSecond() > 1000); // At least 1000 ops/sec
    
    std.log.info("HTTP parsing: {d:.2} ops/sec, {d:.2} ns/op", .{
        metrics.opsPerSecond(),
        metrics.nsPerOp(),
    });
}

fn parseHttpTest(allocator: std.mem.Allocator, args: anytype) !void {
    _ = allocator; // Unused for now
    const http_data = args[0];
    var parser = ferret.Http1.Parser.init();
    
    const result = try parser.parse(http_data);
    _ = result; // Use result to prevent optimization
}

fn testDataStructurePerformance(allocator: std.mem.Allocator) !void {
    var benchmark = TestFramework.Benchmark.init(allocator, 10000);
    const metrics = try benchmark.run(dataStructureTest, .{});

    // Verify performance expectations
    try TestFramework.Assert.isTrue(metrics.opsPerSecond() > 500); // At least 500 ops/sec
    
    std.log.info("Data structures: {d:.2} ops/sec, {d:.2} ns/op", .{
        metrics.opsPerSecond(),
        metrics.nsPerOp(),
    });
}

fn dataStructureTest(allocator: std.mem.Allocator, args: anytype) !void {
    _ = args;
    
    // Test Array performance
    var array = ferret.Array(i32).init(allocator);
    defer array.deinit();
    
    for (0..100) |i| {
        try array.append(@intCast(i));
    }
    
    // Test HashMap performance
    var map = ferret.HashMap(i32, i32).init(allocator);
    defer map.deinit();
    
    for (0..100) |i| {
        try map.put(@intCast(i), @intCast(i * 2));
    }
    
    // Test String performance
    var string = ferret.String.init(allocator);
    defer string.deinit();
    
    for (0..50) |_| {
        try string.appendSlice("test");
    }
}

// Unit tests for the integration test functions
test "HTTP version negotiation" {
    try testHttpVersionNegotiation(std.testing.allocator);
}

test "HTTP request/response cycle" {
    try testHttpRequestResponseCycle(std.testing.allocator);
}

test "Header compatibility" {
    try testHeaderCompatibility(std.testing.allocator);
}

test "Data structure interoperability" {
    try testDataStructureInteroperability(std.testing.allocator);
}

test "Hash integration" {
    try testHashIntegration(std.testing.allocator);
}

test "Encryption integration" {
    try testEncryptionIntegration(std.testing.allocator);
}