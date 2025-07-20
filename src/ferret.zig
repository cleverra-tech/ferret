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

// Collections
pub const Array = @import("collections/array.zig").Array;
pub const HashMap = @import("collections/hashmap.zig").HashMap;
pub const String = @import("collections/string.zig").String;
pub const Queue = @import("collections/queue.zig").Queue;

// I/O and networking
pub const Reactor = @import("io/reactor.zig").Reactor;
pub const Socket = @import("io/socket.zig").Socket;
pub const Buffer = @import("io/buffer.zig").Buffer;

// Protocols
pub const Http = @import("protocols/http.zig");
pub const WebSocket = @import("protocols/websocket.zig");
pub const Json = @import("protocols/json.zig");

// Cryptography
pub const hash = @import("crypto/hash.zig");
pub const cipher = @import("crypto/cipher.zig");
pub const rand = @import("crypto/rand.zig");

// CLI utilities
pub const Cli = @import("cli/args.zig").Cli;

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
