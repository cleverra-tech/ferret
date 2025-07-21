//! Configuration System Benchmark
//!
//! This benchmark tests the Ferret configuration system performance
//! and validates all configuration functionality.

const std = @import("std");
const ferret = @import("ferret");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Ferret Configuration System Benchmark ===\n", .{});

    // Test basic configuration functionality
    try testConfigValidation(allocator);

    // Test environment variable loading
    try testEnvironmentLoading(allocator);

    // Test JSON serialization/deserialization
    try testJsonSerialization(allocator);

    // Test global configuration management
    try testGlobalConfig(allocator);

    // Benchmark configuration operations
    try benchmarkConfigOperations(allocator);

    std.log.info("=== Configuration System Benchmark Complete ===", .{});
}

fn testConfigValidation(allocator: std.mem.Allocator) !void {
    std.log.info("Testing configuration validation...", .{});
    _ = allocator;

    // Test default configuration
    const default_config = ferret.Config.default();
    try default_config.validate();

    // Test individual module validation
    var server_config = ferret.config.ServerConfig{};
    try server_config.validate();

    // Test invalid server configuration
    server_config.max_connections = 0;
    if (server_config.validate()) {
        return error.ValidationShouldHaveFailed;
    } else |_| {
        // Expected error
    }

    // Test buffer configuration
    var buffer_config = ferret.config.BufferConfig{};
    try buffer_config.validate();

    buffer_config.growth_factor = 0.5; // Invalid growth factor
    if (buffer_config.validate()) {
        return error.ValidationShouldHaveFailed;
    } else |_| {
        // Expected error
    }

    // Test HTTP/2 configuration
    var http2_config = ferret.config.Http2Config{};
    try http2_config.validate();

    http2_config.max_frame_size = 8192; // Below minimum
    if (http2_config.validate()) {
        return error.ValidationShouldHaveFailed;
    } else |_| {
        // Expected error
    }

    std.log.info("[OK] Configuration validation tests passed", .{});
}

fn testEnvironmentLoading(allocator: std.mem.Allocator) !void {
    std.log.info("Testing environment variable loading...", .{});

    // Test environment loading with no variables set
    const config = try ferret.Config.fromEnvironment(allocator);
    try config.validate();

    // Verify default values are used
    const default_config = ferret.Config.default();
    if (config.server.max_connections != default_config.server.max_connections) {
        return error.UnexpectedConfigValue;
    }

    std.log.info("[OK] Environment variable loading test passed", .{});
}

fn testJsonSerialization(allocator: std.mem.Allocator) !void {
    std.log.info("Testing JSON serialization/deserialization...", .{});

    // Create a custom configuration
    var config = ferret.Config.default();
    config.server.max_connections = 2000;
    config.buffer.default_capacity = 8192;
    config.http.max_header_size = 16384;
    config.http2.header_table_size = 8192;
    config.json.max_parsing_depth = 256;

    // Serialize to JSON
    const json_string = try config.toJson(allocator);
    defer allocator.free(json_string);

    std.log.info("Generated JSON config ({} bytes)", .{json_string.len});

    // Deserialize from JSON
    const loaded_config = try ferret.Config.fromJson(allocator, json_string);
    try loaded_config.validate();

    // Verify values
    if (loaded_config.server.max_connections != 2000) {
        return error.SerializationMismatch;
    }
    if (loaded_config.buffer.default_capacity != 8192) {
        return error.SerializationMismatch;
    }
    if (loaded_config.http.max_header_size != 16384) {
        return error.SerializationMismatch;
    }
    if (loaded_config.http2.header_table_size != 8192) {
        return error.SerializationMismatch;
    }
    if (loaded_config.json.max_parsing_depth != 256) {
        return error.SerializationMismatch;
    }

    std.log.info("[OK] JSON serialization test passed", .{});
}

fn testGlobalConfig(allocator: std.mem.Allocator) !void {
    std.log.info("Testing global configuration management...", .{});
    _ = allocator;

    // Test initial state
    if (ferret.config.isInitialized()) {
        // Reset if already initialized from previous tests
    }

    // Test default retrieval
    const default_retrieved = ferret.config.get();
    try default_retrieved.validate();

    // Initialize with custom configuration
    var custom_config = ferret.Config.default();
    custom_config.server.max_connections = 3000;
    custom_config.buffer.default_capacity = 16384;

    try ferret.config.init(custom_config);

    if (!ferret.config.isInitialized()) {
        return error.ConfigNotInitialized;
    }

    // Retrieve and verify
    const retrieved = ferret.config.get();
    if (retrieved.server.max_connections != 3000) {
        return error.GlobalConfigMismatch;
    }
    if (retrieved.buffer.default_capacity != 16384) {
        return error.GlobalConfigMismatch;
    }

    std.log.info("[OK] Global configuration management test passed", .{});
}

fn benchmarkConfigOperations(allocator: std.mem.Allocator) !void {
    std.log.info("Running configuration operations benchmark...", .{});

    const iterations = 10000;
    var timer = try std.time.Timer.start();

    // Benchmark configuration creation and validation
    timer.reset();
    for (0..iterations) |_| {
        const config = ferret.Config.default();
        try config.validate();

        // Prevent optimization
        std.mem.doNotOptimizeAway(&config);
    }
    const validation_time = timer.read();

    // Benchmark JSON serialization
    const config = ferret.Config.default();
    timer.reset();
    var total_json_size: usize = 0;
    for (0..1000) |_| { // Fewer iterations due to allocation
        const json_string = try config.toJson(allocator);
        total_json_size += json_string.len;
        allocator.free(json_string);
    }
    const serialization_time = timer.read();

    // Benchmark JSON deserialization
    const json_template = try config.toJson(allocator);
    defer allocator.free(json_template);

    timer.reset();
    for (0..1000) |_| { // Fewer iterations due to allocation
        const loaded_config = try ferret.Config.fromJson(allocator, json_template);
        try loaded_config.validate();

        // Prevent optimization
        std.mem.doNotOptimizeAway(&loaded_config);
    }
    const deserialization_time = timer.read();

    // Calculate performance metrics
    const validation_ns_per_op = validation_time / iterations;
    const validation_ops_per_sec = 1_000_000_000.0 / @as(f64, @floatFromInt(validation_ns_per_op));

    const serialization_ns_per_op = serialization_time / 1000;
    const serialization_ops_per_sec = 1_000_000_000.0 / @as(f64, @floatFromInt(serialization_ns_per_op));

    const deserialization_ns_per_op = deserialization_time / 1000;
    const deserialization_ops_per_sec = 1_000_000_000.0 / @as(f64, @floatFromInt(deserialization_ns_per_op));

    std.log.info("[OK] Configuration benchmark results:", .{});
    std.log.info("  Validation:", .{});
    std.log.info("    - Operations: {}", .{iterations});
    std.log.info("    - Total time: {d:.2} ms", .{@as(f64, @floatFromInt(validation_time)) / 1_000_000.0});
    std.log.info("    - Throughput: {d:.2} ops/sec", .{validation_ops_per_sec});
    std.log.info("    - Latency: {} ns/op", .{validation_ns_per_op});

    std.log.info("  JSON Serialization:", .{});
    std.log.info("    - Operations: 1000", .{});
    std.log.info("    - Total time: {d:.2} ms", .{@as(f64, @floatFromInt(serialization_time)) / 1_000_000.0});
    std.log.info("    - Throughput: {d:.2} ops/sec", .{serialization_ops_per_sec});
    std.log.info("    - Latency: {} ns/op", .{serialization_ns_per_op});
    std.log.info("    - Average JSON size: {} bytes", .{total_json_size / 1000});

    std.log.info("  JSON Deserialization:", .{});
    std.log.info("    - Operations: 1000", .{});
    std.log.info("    - Total time: {d:.2} ms", .{@as(f64, @floatFromInt(deserialization_time)) / 1_000_000.0});
    std.log.info("    - Throughput: {d:.2} ops/sec", .{deserialization_ops_per_sec});
    std.log.info("    - Latency: {} ns/op", .{deserialization_ns_per_op});

    // Performance expectations
    if (validation_ops_per_sec < 100000) {
        std.log.warn("Performance warning: Low validation throughput ({d:.2} ops/sec)", .{validation_ops_per_sec});
    }

    if (serialization_ops_per_sec < 1000) {
        std.log.warn("Performance warning: Low serialization throughput ({d:.2} ops/sec)", .{serialization_ops_per_sec});
    }

    if (deserialization_ops_per_sec < 1000) {
        std.log.warn("Performance warning: Low deserialization throughput ({d:.2} ops/sec)", .{deserialization_ops_per_sec});
    }
}
