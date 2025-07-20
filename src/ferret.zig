//! Ferret: A high-performance web framework for Zig
//!
//! Ferret is inspired by facil.io and designed to provide fast, memory-safe
//! networking and web application capabilities in Zig.

const std = @import("std");

// Core modules
pub const allocator = @import("core/allocator.zig");
pub const types = @import("core/types.zig");
pub const atomic = @import("core/atomic.zig");
pub const time = @import("core/time.zig");

// Atomic types
pub const AtomicCounter = @import("core/atomic.zig").AtomicCounter;
pub const AtomicFlag = @import("core/atomic.zig").AtomicFlag;
pub const LockFreeQueue = @import("core/atomic.zig").LockFreeQueue;
pub const SpinLock = @import("core/atomic.zig").SpinLock;
pub const RwLock = @import("core/atomic.zig").RwLock;

// Collections
pub const Array = @import("collections/array.zig").Array;
pub const HashMap = @import("collections/hashmap.zig").HashMap;
pub const String = @import("collections/string.zig").String;
pub const Queue = @import("collections/queue.zig").Queue;
pub const collections = struct {
    pub const queue = @import("collections/queue.zig");
};

// I/O and networking
pub const Reactor = @import("io/reactor.zig").Reactor;
pub const EventType = @import("io/reactor.zig").EventType;
pub const Event = @import("io/reactor.zig").Event;
pub const Socket = @import("io/socket.zig").Socket;
pub const SocketManager = @import("io/socket.zig").SocketManager;
pub const SocketError = @import("io/socket.zig").SocketError;
pub const SocketAddress = @import("io/socket.zig").SocketAddress;
pub const Protocol = @import("io/socket.zig").Protocol;
pub const Buffer = @import("io/buffer.zig").Buffer;
pub const io = struct {
    pub const buffer = @import("io/buffer.zig");
    pub const socket = @import("io/socket.zig");
};

// Protocols
pub const Http = @import("protocols/http_unified.zig"); // Unified HTTP API (defaults to HTTP/3)
pub const Http1 = @import("protocols/http.zig"); // HTTP/1.1 implementation
pub const Http2 = @import("protocols/http2.zig"); // HTTP/2 implementation
pub const Http3 = @import("protocols/http3.zig"); // HTTP/3 implementation
pub const WebSocket = @import("protocols/websocket.zig");
pub const Json = @import("protocols/json.zig");

// Cryptography
pub const hash = @import("crypto/hash.zig");
pub const cipher = @import("crypto/cipher.zig");
pub const rand = @import("crypto/rand.zig");

// CLI utilities
pub const Cli = @import("cli/args.zig").Cli;
pub const CliConfig = @import("cli/args.zig").CliConfig;
pub const CliError = @import("cli/args.zig").CliError;
pub const ParseResult = @import("cli/args.zig").ParseResult;
pub const ArgValue = @import("cli/args.zig").ArgValue;

// Testing framework
pub const testing = @import("testing/framework.zig");

// Error types
pub const Error = error{
    // Memory errors
    OutOfMemory,

    // I/O errors
    NetworkError,
    SocketError,
    ConnectionClosed,
    Timeout,

    // Protocol errors
    InvalidHttpRequest,
    InvalidJson,
    ProtocolError,

    // System errors
    SystemError,
    InvalidInput,
    PermissionDenied,
};

// Version information
pub const version = std.SemanticVersion{
    .major = 0,
    .minor = 1,
    .patch = 0,
    .pre = "alpha",
};

/// Get human-readable version string
pub fn versionString(alloc: std.mem.Allocator) ![]u8 {
    if (version.pre) |pre| {
        return std.fmt.allocPrint(alloc, "{}.{}.{}-{s}", .{ version.major, version.minor, version.patch, pre });
    } else {
        return std.fmt.allocPrint(alloc, "{}.{}.{}", .{ version.major, version.minor, version.patch });
    }
}

test {
    std.testing.refAllDecls(@This());
}
