//! Ferret Configuration System
//!
//! This module provides a comprehensive configuration system for Ferret,
//! allowing users to customize behavior without modifying source code.
//! All hardcoded values are centralized here with sensible defaults.
//!
//! Features:
//! - Hierarchical configuration structure
//! - Environment variable overrides
//! - JSON/TOML configuration file support
//! - Runtime validation
//! - Type-safe configuration access

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

/// Server configuration
pub const ServerConfig = struct {
    /// Maximum number of concurrent connections
    max_connections: u32 = 1000,

    /// Default server port
    default_port: u16 = 8080,

    /// Number of worker threads
    worker_threads: u32 = 4,

    /// Request timeout in milliseconds
    timeout_ms: u32 = 30000,

    /// Enable keep-alive connections
    enable_keep_alive: bool = true,

    /// Keep-alive timeout in seconds
    keep_alive_timeout: u32 = 60,

    pub fn validate(self: ServerConfig) !void {
        if (self.max_connections == 0) return error.InvalidMaxConnections;
        if (self.default_port == 0) return error.InvalidPort;
        if (self.worker_threads == 0) return error.InvalidWorkerThreads;
        if (self.timeout_ms == 0) return error.InvalidTimeout;
    }
};

/// Network configuration
pub const NetworkConfig = struct {
    /// Socket listen backlog
    listen_backlog: u32 = 128,

    /// Default HTTP port
    default_http_port: u16 = 80,

    /// Default HTTPS port
    default_https_port: u16 = 443,

    /// Default test port for development
    default_test_port: u16 = 8080,

    /// TCP no-delay option
    tcp_nodelay: bool = true,

    /// Socket reuse address option
    reuse_address: bool = true,

    /// Send buffer size
    send_buffer_size: u32 = 65536,

    /// Receive buffer size
    recv_buffer_size: u32 = 65536,

    pub fn validate(self: NetworkConfig) !void {
        if (self.listen_backlog == 0) return error.InvalidListenBacklog;
        if (self.send_buffer_size == 0) return error.InvalidSendBufferSize;
        if (self.recv_buffer_size == 0) return error.InvalidRecvBufferSize;
    }
};

/// HTTP/1.1 configuration
pub const HttpConfig = struct {
    /// Maximum HTTP header size in bytes
    max_header_size: usize = 8192,

    /// Maximum number of headers per request
    max_headers_count: usize = 100,

    /// Maximum request body size in bytes (1MB default)
    max_body_size: usize = 1024 * 1024,

    /// Maximum URI length
    max_uri_length: usize = 2048,

    /// Enable HTTP/1.1 pipelining
    enable_pipelining: bool = false,

    /// Connection header processing
    strict_connection_header: bool = true,

    pub fn validate(self: HttpConfig) !void {
        if (self.max_header_size == 0) return error.InvalidMaxHeaderSize;
        if (self.max_headers_count == 0) return error.InvalidMaxHeadersCount;
        if (self.max_body_size == 0) return error.InvalidMaxBodySize;
        if (self.max_uri_length == 0) return error.InvalidMaxUriLength;
    }
};

/// HTTP/2 configuration
pub const Http2Config = struct {
    /// HPACK dynamic table size
    header_table_size: u32 = 4096,

    /// Initial flow control window size
    initial_window_size: u32 = 65535,

    /// Maximum frame size
    max_frame_size: u32 = 16384,

    /// Maximum number of concurrent streams
    max_concurrent_streams: u32 = 100,

    /// Enable server push
    enable_push: bool = false,

    /// Maximum header list size
    max_header_list_size: u32 = 8192,

    pub fn validate(self: Http2Config) !void {
        if (self.header_table_size == 0) return error.InvalidHeaderTableSize;
        if (self.initial_window_size == 0) return error.InvalidInitialWindowSize;
        if (self.max_frame_size < 16384 or self.max_frame_size > 16777215) return error.InvalidMaxFrameSize;
        if (self.max_concurrent_streams == 0) return error.InvalidMaxConcurrentStreams;
    }
};

/// HTTP/3 configuration
pub const Http3Config = struct {
    /// QPACK dynamic table capacity
    qpack_max_table_capacity: u64 = 4096,

    /// Maximum field section size
    max_field_section_size: u64 = 8192,

    /// Number of QPACK blocked streams
    qpack_blocked_streams: u64 = 0,

    /// Enable early data (0-RTT)
    enable_early_data: bool = false,

    /// Maximum UDP packet size
    max_udp_payload_size: u32 = 1200,

    /// Connection idle timeout in milliseconds
    idle_timeout_ms: u32 = 30000,

    pub fn validate(self: Http3Config) !void {
        if (self.qpack_max_table_capacity == 0) return error.InvalidQpackTableCapacity;
        if (self.max_field_section_size == 0) return error.InvalidMaxFieldSectionSize;
        if (self.max_udp_payload_size < 1200) return error.InvalidMaxUdpPayloadSize;
        if (self.idle_timeout_ms == 0) return error.InvalidIdleTimeout;
    }
};

/// Buffer management configuration
pub const BufferConfig = struct {
    /// Default buffer capacity
    default_capacity: usize = 4096,

    /// Buffer growth factor
    growth_factor: f64 = 2.0,

    /// Maximum buffer size
    max_size: usize = 64 * 1024 * 1024, // 64MB

    /// Pre-allocated buffer pool size
    pool_size: usize = 16,

    /// Enable buffer pooling
    enable_pooling: bool = true,

    /// Buffer alignment
    alignment: usize = 8,

    pub fn validate(self: BufferConfig) !void {
        if (self.default_capacity == 0) return error.InvalidDefaultCapacity;
        if (self.growth_factor <= 1.0) return error.InvalidGrowthFactor;
        if (self.max_size < self.default_capacity) return error.InvalidMaxSize;
        if (self.pool_size == 0) return error.InvalidPoolSize;
        if (self.alignment == 0 or (self.alignment & (self.alignment - 1)) != 0) return error.InvalidAlignment;
    }
};

/// Event reactor configuration
pub const ReactorConfig = struct {
    /// Maximum events per epoll_wait call
    max_events: u32 = 1024,

    /// Epoll timeout in milliseconds (-1 for blocking)
    timeout_ms: i32 = 100,

    /// Enable edge-triggered mode
    edge_triggered: bool = true,

    /// Enable one-shot mode
    oneshot: bool = false,

    /// Event batch processing size
    batch_size: u32 = 64,

    pub fn validate(self: ReactorConfig) !void {
        if (self.max_events == 0) return error.InvalidMaxEvents;
        if (self.batch_size == 0) return error.InvalidBatchSize;
        if (self.batch_size > self.max_events) return error.BatchSizeExceedsMaxEvents;
    }
};

/// Collections configuration
pub const CollectionsConfig = struct {
    /// HashMap maximum load factor
    hashmap_max_load_factor: f64 = 0.75,

    /// Initial HashMap capacity
    hashmap_initial_capacity: usize = 16,

    /// Array default capacity
    array_default_capacity: usize = 8,

    /// String default capacity
    string_default_capacity: usize = 32,

    /// Queue default capacity
    queue_default_capacity: usize = 16,

    pub fn validate(self: CollectionsConfig) !void {
        if (self.hashmap_max_load_factor <= 0.0 or self.hashmap_max_load_factor >= 1.0) return error.InvalidLoadFactor;
        if (self.hashmap_initial_capacity == 0) return error.InvalidInitialCapacity;
        if (self.array_default_capacity == 0) return error.InvalidArrayCapacity;
        if (self.string_default_capacity == 0) return error.InvalidStringCapacity;
        if (self.queue_default_capacity == 0) return error.InvalidQueueCapacity;
    }
};

/// JSON parsing configuration
pub const JsonConfig = struct {
    /// Maximum parsing depth to prevent stack overflow
    max_parsing_depth: u32 = 128,

    /// Maximum string length
    max_string_length: usize = 1024 * 1024, // 1MB

    /// Maximum number length
    max_number_length: usize = 64,

    /// Allow comments in JSON
    allow_comments: bool = false,

    /// Allow trailing commas
    allow_trailing_commas: bool = false,

    /// Strict mode (RFC 8259 compliance)
    strict_mode: bool = true,

    pub fn validate(self: JsonConfig) !void {
        if (self.max_parsing_depth == 0) return error.InvalidMaxParsingDepth;
        if (self.max_string_length == 0) return error.InvalidMaxStringLength;
        if (self.max_number_length == 0) return error.InvalidMaxNumberLength;
    }
};

/// Testing framework configuration
pub const TestingConfig = struct {
    /// Default test timeout in milliseconds
    default_timeout_ms: u32 = 5000,

    /// Benchmark warmup iterations
    benchmark_warmup_iterations: u32 = 1000,

    /// Benchmark measurement iterations
    benchmark_iterations: u32 = 10000,

    /// Enable detailed timing
    enable_timing: bool = true,

    /// Memory leak detection
    enable_leak_detection: bool = true,

    /// Test parallelism
    max_parallel_tests: u32 = 8,

    pub fn validate(self: TestingConfig) !void {
        if (self.default_timeout_ms == 0) return error.InvalidDefaultTimeout;
        if (self.benchmark_warmup_iterations == 0) return error.InvalidWarmupIterations;
        if (self.benchmark_iterations == 0) return error.InvalidBenchmarkIterations;
        if (self.max_parallel_tests == 0) return error.InvalidMaxParallelTests;
    }
};

/// Cryptography configuration
pub const CryptoConfig = struct {
    /// Random number generator seed (0 for time-based)
    rng_seed: u64 = 0,

    /// Default hash algorithm
    default_hash_algorithm: HashAlgorithm = .sha256,

    /// Default cipher algorithm
    default_cipher_algorithm: CipherAlgorithm = .aes256_gcm,

    /// Key derivation iterations
    pbkdf2_iterations: u32 = 100000,

    /// Salt length for password hashing
    salt_length: usize = 32,

    pub const HashAlgorithm = enum {
        sha256,
        sha512,
        blake3,
    };

    pub const CipherAlgorithm = enum {
        aes256_gcm,
        chacha20_poly1305,
        aes128_gcm,
    };

    pub fn validate(self: CryptoConfig) !void {
        if (self.pbkdf2_iterations < 10000) return error.WeakPbkdf2Iterations;
        if (self.salt_length < 16) return error.WeakSaltLength;
    }
};

/// Main Ferret configuration
pub const Config = struct {
    server: ServerConfig = .{},
    network: NetworkConfig = .{},
    http: HttpConfig = .{},
    http2: Http2Config = .{},
    http3: Http3Config = .{},
    buffer: BufferConfig = .{},
    reactor: ReactorConfig = .{},
    collections: CollectionsConfig = .{},
    json: JsonConfig = .{},
    testing: TestingConfig = .{},
    crypto: CryptoConfig = .{},

    const Self = @This();

    /// Get default configuration
    pub fn default() Self {
        return Self{};
    }

    /// Validate entire configuration
    pub fn validate(self: Self) !void {
        try self.server.validate();
        try self.network.validate();
        try self.http.validate();
        try self.http2.validate();
        try self.http3.validate();
        try self.buffer.validate();
        try self.reactor.validate();
        try self.collections.validate();
        try self.json.validate();
        try self.testing.validate();
        try self.crypto.validate();
    }

    /// Load configuration from environment variables
    pub fn fromEnvironment(allocator: Allocator) !Self {
        var config = Self.default();

        // Server configuration
        if (std.posix.getenv("FERRET_MAX_CONNECTIONS")) |value| {
            config.server.max_connections = try std.fmt.parseInt(u32, value, 10);
        }
        if (std.posix.getenv("FERRET_PORT")) |value| {
            config.server.default_port = try std.fmt.parseInt(u16, value, 10);
        }
        if (std.posix.getenv("FERRET_WORKER_THREADS")) |value| {
            config.server.worker_threads = try std.fmt.parseInt(u32, value, 10);
        }
        if (std.posix.getenv("FERRET_TIMEOUT_MS")) |value| {
            config.server.timeout_ms = try std.fmt.parseInt(u32, value, 10);
        }

        // Buffer configuration
        if (std.posix.getenv("FERRET_BUFFER_SIZE")) |value| {
            config.buffer.default_capacity = try std.fmt.parseInt(usize, value, 10);
        }
        if (std.posix.getenv("FERRET_BUFFER_POOL_SIZE")) |value| {
            config.buffer.pool_size = try std.fmt.parseInt(usize, value, 10);
        }

        // HTTP configuration
        if (std.posix.getenv("FERRET_MAX_HEADER_SIZE")) |value| {
            config.http.max_header_size = try std.fmt.parseInt(usize, value, 10);
        }
        if (std.posix.getenv("FERRET_MAX_BODY_SIZE")) |value| {
            config.http.max_body_size = try std.fmt.parseInt(usize, value, 10);
        }

        _ = allocator; // Reserved for future JSON/TOML parsing

        try config.validate();
        return config;
    }

    /// Load configuration from JSON file
    pub fn fromJsonFile(allocator: Allocator, file_path: []const u8) !Self {
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();

        const file_size = try file.getEndPos();
        const contents = try allocator.alloc(u8, file_size);
        defer allocator.free(contents);

        _ = try file.readAll(contents);

        return try fromJson(allocator, contents);
    }

    /// Load configuration from JSON string
    pub fn fromJson(allocator: Allocator, json_string: []const u8) !Self {
        const parsed = try std.json.parseFromSlice(Self, allocator, json_string, .{
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();

        const config = parsed.value;
        try config.validate();
        return config;
    }

    /// Save configuration to JSON file
    pub fn toJsonFile(self: Self, allocator: Allocator, file_path: []const u8) !void {
        const json_string = try self.toJson(allocator);
        defer allocator.free(json_string);

        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        try file.writeAll(json_string);
    }

    /// Convert configuration to JSON string
    pub fn toJson(self: Self, allocator: Allocator) ![]u8 {
        return try std.json.stringifyAlloc(allocator, self, .{ .whitespace = .indent_2 });
    }
};

/// Global configuration instance
var global_config: Config = Config.default();
var config_initialized: bool = false;

/// Initialize global configuration
pub fn init(config: Config) !void {
    try config.validate();
    global_config = config;
    config_initialized = true;
}

/// Get global configuration (must be initialized first)
pub fn get() Config {
    if (!config_initialized) {
        // Return default config if not explicitly initialized
        return Config.default();
    }
    return global_config;
}

/// Check if configuration is initialized
pub fn isInitialized() bool {
    return config_initialized;
}

// Tests
test "default configuration validation" {
    const config = Config.default();
    try config.validate();
}

test "server configuration validation" {
    var config = ServerConfig{};
    try config.validate();

    // Test invalid configurations
    config.max_connections = 0;
    try testing.expectError(error.InvalidMaxConnections, config.validate());

    config = ServerConfig{};
    config.default_port = 0;
    try testing.expectError(error.InvalidPort, config.validate());
}

test "buffer configuration validation" {
    var config = BufferConfig{};
    try config.validate();

    // Test invalid growth factor
    config.growth_factor = 0.5;
    try testing.expectError(error.InvalidGrowthFactor, config.validate());

    // Test invalid max size
    config = BufferConfig{};
    config.max_size = 100;
    config.default_capacity = 200;
    try testing.expectError(error.InvalidMaxSize, config.validate());
}

test "environment variable loading" {
    const config = try Config.fromEnvironment(testing.allocator);
    try config.validate();
}

test "JSON serialization roundtrip" {
    const original_config = Config.default();

    const json_string = try original_config.toJson(testing.allocator);
    defer testing.allocator.free(json_string);

    const loaded_config = try Config.fromJson(testing.allocator, json_string);
    try loaded_config.validate();

    // Verify some key values
    try testing.expectEqual(original_config.server.max_connections, loaded_config.server.max_connections);
    try testing.expectEqual(original_config.buffer.default_capacity, loaded_config.buffer.default_capacity);
    try testing.expectEqual(original_config.http.max_header_size, loaded_config.http.max_header_size);
}

test "global configuration management" {
    try testing.expect(!isInitialized());

    const config = Config.default();
    try init(config);

    try testing.expect(isInitialized());
    const retrieved = get();
    try testing.expectEqual(config.server.max_connections, retrieved.server.max_connections);
}
