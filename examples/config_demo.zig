//! Configuration System Demo
//!
//! This example demonstrates how to use the Ferret configuration system
//! to customize framework behavior for different deployment scenarios.

const std = @import("std");
const ferret = @import("ferret");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Ferret Configuration System Demo ===\n", .{});

    // 1. Using default configuration
    try demonstrateDefaultConfig();
    
    // 2. Loading from environment variables
    try demonstrateEnvironmentConfig(allocator);
    
    // 3. Creating custom configuration programmatically
    try demonstrateCustomConfig();
    
    // 4. Loading from JSON file
    try demonstrateJsonConfig(allocator);
    
    // 5. Global configuration management
    try demonstrateGlobalConfig();

    std.log.info("=== Configuration System Demo Complete ===", .{});
}

fn demonstrateDefaultConfig() !void {
    std.log.info("1. Using Default Configuration", .{});
    std.log.info("   ===============================", .{});
    
    const config = ferret.Config.default();
    try config.validate();
    
    std.log.info("   Server max connections: {}", .{config.server.max_connections});
    std.log.info("   Default port: {}", .{config.server.default_port});
    std.log.info("   Buffer capacity: {} bytes", .{config.buffer.default_capacity});
    std.log.info("   HTTP max header size: {} bytes", .{config.http.max_header_size});
    std.log.info("   HTTP/2 header table size: {} bytes", .{config.http2.header_table_size});
    std.log.info("   JSON max parsing depth: {}", .{config.json.max_parsing_depth});
    std.log.info("", .{});
}

fn demonstrateEnvironmentConfig(allocator: std.mem.Allocator) !void {
    std.log.info("2. Environment Variable Configuration", .{});
    std.log.info("   ===================================", .{});
    
    // Demonstrate environment variable override (would work with actual env vars)
    std.log.info("   To override via environment variables:", .{});
    std.log.info("   export FERRET_MAX_CONNECTIONS=5000", .{});
    std.log.info("   export FERRET_PORT=9000", .{});
    std.log.info("   export FERRET_BUFFER_SIZE=16384", .{});
    
    const config = try ferret.Config.fromEnvironment(allocator);
    try config.validate();
    
    std.log.info("   Current config (using defaults if no env vars set):", .{});
    std.log.info("   Max connections: {}", .{config.server.max_connections});
    std.log.info("   Port: {}", .{config.server.default_port});
    std.log.info("   Buffer size: {} bytes", .{config.buffer.default_capacity});
    std.log.info("", .{});
}

fn demonstrateCustomConfig() !void {
    std.log.info("3. Custom Configuration (Programmatic)", .{});
    std.log.info("   ====================================", .{});
    
    // Create a high-performance configuration
    var high_perf_config = ferret.Config.default();
    
    // Server optimizations
    high_perf_config.server.max_connections = 10000;
    high_perf_config.server.worker_threads = 16;
    high_perf_config.server.timeout_ms = 15000; // Shorter timeout
    
    // Network optimizations
    high_perf_config.network.listen_backlog = 512;
    high_perf_config.network.send_buffer_size = 256 * 1024; // 256KB
    high_perf_config.network.recv_buffer_size = 256 * 1024; // 256KB
    
    // Buffer optimizations
    high_perf_config.buffer.default_capacity = 16384; // 16KB
    high_perf_config.buffer.pool_size = 64; // Larger pool
    high_perf_config.buffer.max_size = 128 * 1024 * 1024; // 128MB
    
    // HTTP optimizations
    high_perf_config.http.max_header_size = 32768; // 32KB
    high_perf_config.http.max_body_size = 100 * 1024 * 1024; // 100MB
    
    // Reactor optimizations
    high_perf_config.reactor.max_events = 4096;
    high_perf_config.reactor.batch_size = 256;
    high_perf_config.reactor.timeout_ms = 10; // More responsive
    
    try high_perf_config.validate();
    
    std.log.info("   High-Performance Configuration:", .{});
    std.log.info("   Max connections: {}", .{high_perf_config.server.max_connections});
    std.log.info("   Worker threads: {}", .{high_perf_config.server.worker_threads});
    std.log.info("   Buffer capacity: {} KB", .{high_perf_config.buffer.default_capacity / 1024});
    std.log.info("   Send buffer: {} KB", .{high_perf_config.network.send_buffer_size / 1024});
    std.log.info("   Max events: {}", .{high_perf_config.reactor.max_events});
    std.log.info("", .{});
}

fn demonstrateJsonConfig(allocator: std.mem.Allocator) !void {
    std.log.info("4. JSON Configuration File", .{});
    std.log.info("   ========================", .{});
    
    // Try to load the example configuration file
    const config = ferret.Config.fromJsonFile(allocator, "examples/ferret_config.json") catch |err| switch (err) {
        error.FileNotFound => {
            std.log.info("   ferret_config.json not found, creating a sample config...", .{});
            
            // Create a sample configuration
            var sample_config = ferret.Config.default();
            sample_config.server.max_connections = 2000;
            sample_config.server.default_port = 3000;
            sample_config.buffer.default_capacity = 8192;
            
            try sample_config.toJsonFile(allocator, "examples/sample_config.json");
            std.log.info("   Created sample_config.json", .{});
            
            return;
        },
        else => return err,
    };
    
    try config.validate();
    
    std.log.info("   Loaded configuration from ferret_config.json:", .{});
    std.log.info("   Max connections: {}", .{config.server.max_connections});
    std.log.info("   Port: {}", .{config.server.default_port});
    std.log.info("   Worker threads: {}", .{config.server.worker_threads});
    std.log.info("   Buffer capacity: {} KB", .{config.buffer.default_capacity / 1024});
    std.log.info("   HTTP max body size: {} MB", .{config.http.max_body_size / (1024 * 1024)});
    std.log.info("   HTTP/2 concurrent streams: {}", .{config.http2.max_concurrent_streams});
    std.log.info("", .{});
}

fn demonstrateGlobalConfig() !void {
    std.log.info("5. Global Configuration Management", .{});
    std.log.info("   ================================", .{});
    
    // Create a production configuration
    var prod_config = ferret.Config.default();
    prod_config.server.max_connections = 5000;
    prod_config.server.worker_threads = 12;
    prod_config.server.timeout_ms = 45000;
    prod_config.buffer.default_capacity = 12288; // 12KB
    prod_config.http.max_body_size = 50 * 1024 * 1024; // 50MB
    
    // Initialize global configuration
    try ferret.config.init(prod_config);
    
    std.log.info("   Initialized global configuration", .{});
    std.log.info("   Is initialized: {}", .{ferret.config.isInitialized()});
    
    // Retrieve and use global configuration
    const global_config = ferret.config.get();
    
    std.log.info("   Global config max connections: {}", .{global_config.server.max_connections});
    std.log.info("   Global config worker threads: {}", .{global_config.server.worker_threads});
    std.log.info("   Global config buffer capacity: {} KB", .{global_config.buffer.default_capacity / 1024});
    
    // Example: Using global config in application code
    std.log.info("", .{});
    std.log.info("   Example usage in application code:", .{});
    std.log.info("   const config = ferret.config.get();", .{});
    std.log.info("   const server = Server.init(config.server.max_connections);", .{});
    std.log.info("   const buffer = Buffer.init(config.buffer.default_capacity);", .{});
}