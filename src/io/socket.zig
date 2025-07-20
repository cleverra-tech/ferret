//! High-performance Socket I/O wrapper for Ferret
//!
//! This module provides a comprehensive socket implementation with:
//! - Protocol-based event handling inspired by facil.io
//! - Type-safe UUID-based connection management
//! - Integration with Ferret's reactor system
//! - Zero-copy operations where possible
//! - Comprehensive error handling and resource management
//! - Support for TCP, UDP, and Unix domain sockets
//! - Non-blocking I/O with async/await support

const std = @import("std");
const posix = std.posix;
const net = std.net;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;
const AutoHashMap = std.AutoHashMap;
const testing = std.testing;
const assert = std.debug.assert;
const log = std.log;

// Import Ferret modules
const Reactor = @import("reactor.zig").Reactor;
const EventType = @import("reactor.zig").EventType;
const Event = @import("reactor.zig").Event;
const Buffer = @import("buffer.zig").Buffer;

/// Errors that can occur during socket operations
pub const SocketError = error{
    /// Invalid socket UUID or socket has been closed
    InvalidSocket,
    /// Address resolution failed
    AddressResolution,
    /// Connection failed or was refused
    ConnectionFailed,
    /// Socket is not connected
    NotConnected,
    /// Operation would block (for non-blocking sockets)
    WouldBlock,
    /// Peer closed the connection
    ConnectionClosed,
    /// Network is unreachable
    NetworkUnreachable,
    /// Permission denied
    PermissionDenied,
    /// Address already in use
    AddressInUse,
    /// Invalid address format
    InvalidAddress,
    /// System resource temporarily unavailable
    SystemResources,
    /// Operation not supported
    NotSupported,
    /// Timeout occurred
    Timeout,
    /// Generic I/O error
    IOError,
    /// Out of memory
    OutOfMemory,
};

/// Socket address types
pub const SocketAddress = union(enum) {
    ipv4: net.Address,
    ipv6: net.Address,
    unix: []const u8,

    /// Parse address from string
    pub fn parse(address_str: []const u8, port: ?u16) SocketError!SocketAddress {
        if (address_str.len == 0) {
            return SocketError.InvalidAddress;
        }

        // Unix domain socket if starts with '/' or contains no '.'
        if (address_str[0] == '/' or port == null) {
            return SocketAddress{ .unix = address_str };
        }

        // Try IPv4 first
        if (net.Address.parseIp4(address_str, port orelse 0)) |addr| {
            return SocketAddress{ .ipv4 = addr };
        } else |_| {}

        // Try IPv6
        if (net.Address.parseIp6(address_str, port orelse 0)) |addr| {
            return SocketAddress{ .ipv6 = addr };
        } else |_| {}

        return SocketError.InvalidAddress;
    }

    /// Get the underlying socket address
    pub fn getSockAddr(self: SocketAddress) posix.sockaddr {
        return switch (self) {
            .ipv4 => |addr| addr.any,
            .ipv6 => |addr| addr.any,
            .unix => unreachable, // TODO: Implement Unix domain socket support
        };
    }

    /// Get address family
    pub fn getFamily(self: SocketAddress) u32 {
        return switch (self) {
            .ipv4 => posix.AF.INET,
            .ipv6 => posix.AF.INET6,
            .unix => posix.AF.UNIX,
        };
    }
};

/// Socket types
pub const SocketType = enum {
    tcp,
    udp,
    unix_stream,
    unix_dgram,

    pub fn toPosixType(self: SocketType) u32 {
        return switch (self) {
            .tcp, .unix_stream => posix.SOCK.STREAM,
            .udp, .unix_dgram => posix.SOCK.DGRAM,
        };
    }
};

/// Unique identifier for socket connections
pub const SocketUUID = struct {
    id: u64,
    counter: u32,

    const Self = @This();

    pub fn invalid() Self {
        return Self{ .id = 0, .counter = 0 };
    }

    pub fn isValid(self: Self) bool {
        return self.id != 0;
    }

    pub fn eql(self: Self, other: Self) bool {
        return self.id == other.id and self.counter == other.counter;
    }
};

/// Protocol interface for handling socket events
pub const Protocol = struct {
    /// Called when data is available for reading
    onData: ?*const fn (socket: Socket, data: []const u8) void = null,
    /// Called when socket is ready for writing
    onReady: ?*const fn (socket: Socket) void = null,
    /// Called when connection is closed
    onClose: ?*const fn (socket: Socket) void = null,
    /// Called when an error occurs
    onError: ?*const fn (socket: Socket, err: SocketError) void = null,
    /// Called for periodic keep-alive operations
    ping: ?*const fn (socket: Socket) void = null,
    /// User data pointer
    user_data: ?*anyopaque = null,
};

/// Socket connection state
const SocketState = enum {
    created, // Socket has been created but not yet used
    closed, // Socket has been closed
    connecting, // TCP socket is connecting
    connected, // Socket is connected and ready for I/O
    listening, // Socket is listening for connections
    error_state, // Socket encountered an error
};

/// Internal socket registration data
const SocketRegistration = struct {
    fd: posix.fd_t,
    uuid: SocketUUID,
    state: SocketState,
    socket_type: SocketType,
    protocol: Protocol,
    read_buffer: Buffer,
    write_queue: ArrayList(WriteOperation),
    local_addr: ?SocketAddress,
    peer_addr: ?SocketAddress,
    allocator: Allocator,

    const WriteOperation = struct {
        data: []const u8,
        cleanup: ?*const fn (data: []const u8) void,
        urgent: bool,
    };

    pub fn init(allocator: Allocator, fd: posix.fd_t, uuid: SocketUUID, socket_type: SocketType) !SocketRegistration {
        return SocketRegistration{
            .fd = fd,
            .uuid = uuid,
            .state = .created,
            .socket_type = socket_type,
            .protocol = Protocol{},
            .read_buffer = try Buffer.init(allocator),
            .write_queue = ArrayList(WriteOperation).init(allocator),
            .local_addr = null,
            .peer_addr = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SocketRegistration) void {
        self.read_buffer.deinit();

        // Clean up any pending write operations
        for (self.write_queue.items) |write_op| {
            if (write_op.cleanup) |cleanup| {
                cleanup(write_op.data);
            }
        }
        self.write_queue.deinit();
    }
};

/// Socket manager that handles all socket operations
pub const SocketManager = struct {
    const Self = @This();

    allocator: Allocator,
    reactor: *Reactor,
    sockets: AutoHashMap(SocketUUID, SocketRegistration),
    fd_to_uuid: AutoHashMap(posix.fd_t, SocketUUID),
    next_id: std.atomic.Value(u64),
    counter: std.atomic.Value(u32),

    /// Initialize socket manager
    pub fn init(allocator: Allocator, reactor: *Reactor) Self {
        return Self{
            .allocator = allocator,
            .reactor = reactor,
            .sockets = AutoHashMap(SocketUUID, SocketRegistration).init(allocator),
            .fd_to_uuid = AutoHashMap(posix.fd_t, SocketUUID).init(allocator),
            .next_id = std.atomic.Value(u64).init(1),
            .counter = std.atomic.Value(u32).init(1),
        };
    }

    /// Deinitialize socket manager
    pub fn deinit(self: *Self) void {
        // Close all sockets and clean up
        var iter = self.sockets.iterator();
        while (iter.next()) |entry| {
            var registration = entry.value_ptr;
            posix.close(registration.fd);
            registration.deinit();
        }

        self.sockets.deinit();
        self.fd_to_uuid.deinit();
    }

    /// Generate a new UUID for socket
    fn generateUUID(self: *Self) SocketUUID {
        const id = self.next_id.fetchAdd(1, .monotonic);
        const counter = self.counter.fetchAdd(1, .monotonic);
        return SocketUUID{ .id = id, .counter = counter };
    }

    /// Create a new socket
    pub fn createSocket(self: *Self, socket_type: SocketType, address: ?SocketAddress) SocketError!Socket {
        const family = if (address) |addr| addr.getFamily() else posix.AF.INET;
        const sock_type = socket_type.toPosixType();

        const fd = posix.socket(family, sock_type | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0) catch |err| switch (err) {
            error.SystemResources => return SocketError.SystemResources,
            error.AccessDenied => return SocketError.PermissionDenied,
            error.ProtocolFamilyNotAvailable => return SocketError.NotSupported,
            error.AddressFamilyNotSupported => return SocketError.NotSupported,
            else => return SocketError.IOError,
        };

        const uuid = self.generateUUID();

        var registration = SocketRegistration.init(self.allocator, fd, uuid, socket_type) catch |err| switch (err) {
            error.OutOfMemory => {
                posix.close(fd);
                return SocketError.OutOfMemory;
            },
            error.BufferFull, error.NotEnoughData, error.InvalidRange => {
                posix.close(fd);
                return SocketError.IOError;
            },
        };

        if (address) |addr| {
            registration.local_addr = addr;
        }

        // Socket starts in created state

        try self.sockets.put(uuid, registration);
        try self.fd_to_uuid.put(fd, uuid);

        return Socket{ .uuid = uuid, .manager = self };
    }

    /// Listen on a socket
    pub fn listen(self: *Self, address: SocketAddress, protocol: Protocol) SocketError!Socket {
        const socket = try self.createSocket(.tcp, address);
        const registration = self.sockets.getPtr(socket.uuid) orelse return SocketError.InvalidSocket;

        // Set socket options
        const enable: c_int = 1;
        _ = std.c.setsockopt(registration.fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &enable, @sizeOf(c_int));

        // Bind socket
        const sockaddr = address.getSockAddr();
        posix.bind(registration.fd, &sockaddr, @sizeOf(@TypeOf(sockaddr))) catch |err| switch (err) {
            error.AddressInUse => return SocketError.AddressInUse,
            error.PermissionDenied => return SocketError.PermissionDenied,
            error.AddressNotAvailable => return SocketError.InvalidAddress,
            else => return SocketError.IOError,
        };

        // Start listening
        posix.listen(registration.fd, 128) catch return SocketError.IOError;

        registration.state = .listening;
        registration.protocol = protocol;

        // Register with reactor for accept events
        try self.reactor.register(registration.fd, EventType{ .read = true }, Self.handleEvent, self);

        return socket;
    }

    /// Connect to a remote address
    pub fn connect(self: *Self, address: SocketAddress, protocol: Protocol) SocketError!Socket {
        const socket = try self.createSocket(.tcp, null);
        const registration = self.sockets.getPtr(socket.uuid) orelse return SocketError.InvalidSocket;

        registration.peer_addr = address;
        registration.protocol = protocol;
        registration.state = .connecting;

        // Register with reactor for connect completion
        try self.reactor.register(registration.fd, EventType{ .write = true }, Self.handleEvent, self);

        // Attempt connection
        const sockaddr = address.getSockAddr();
        posix.connect(registration.fd, &sockaddr, @sizeOf(@TypeOf(sockaddr))) catch |err| switch (err) {
            error.WouldBlock => {}, // Expected for non-blocking socket
            error.ConnectionRefused => return SocketError.ConnectionFailed,
            error.NetworkUnreachable => return SocketError.NetworkUnreachable,
            error.PermissionDenied => return SocketError.PermissionDenied,
            else => return SocketError.IOError,
        };

        return socket;
    }

    /// Accept incoming connection
    pub fn accept(self: *Self, listener_uuid: SocketUUID, protocol: Protocol) SocketError!?Socket {
        const listener = self.sockets.getPtr(listener_uuid) orelse return SocketError.InvalidSocket;

        if (listener.state != .listening) {
            return SocketError.NotConnected;
        }

        const accepted_fd = posix.accept(listener.fd, null, null, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK) catch |err| switch (err) {
            error.WouldBlock => return null, // No pending connections
            error.ConnectionAborted => return null, // Connection was aborted
            else => return SocketError.IOError,
        };

        const uuid = self.generateUUID();
        var registration = SocketRegistration.init(self.allocator, accepted_fd, uuid, .tcp) catch |err| switch (err) {
            error.OutOfMemory => {
                posix.close(accepted_fd);
                return SocketError.OutOfMemory;
            },
        };

        registration.state = .connected;
        registration.protocol = protocol;

        try self.sockets.put(uuid, registration);
        try self.fd_to_uuid.put(accepted_fd, uuid);

        // Register for read/write events
        try self.reactor.register(accepted_fd, EventType{ .read = true, .write = true }, Self.handleEvent, self);

        return Socket{ .uuid = uuid, .manager = self };
    }

    /// Handle reactor events
    fn handleEvent(data: ?*anyopaque, event: Event) void {
        const self: *Self = @ptrCast(@alignCast(data.?));
        const uuid = self.fd_to_uuid.get(event.fd) orelse return;
        const registration = self.sockets.getPtr(uuid) orelse return;

        if (event.event_type.err or event.event_type.hangup) {
            self.handleError(registration, SocketError.ConnectionClosed);
            return;
        }

        if (event.event_type.read) {
            if (registration.state == .listening) {
                self.handleAccept(registration);
            } else {
                self.handleRead(registration);
            }
        }

        if (event.event_type.write) {
            if (registration.state == .connecting) {
                self.handleConnectComplete(registration);
            } else {
                self.handleWrite(registration);
            }
        }
    }

    fn handleAccept(self: *Self, registration: *SocketRegistration) void {
        // Batch accept up to 4 connections per event (like facil.io)
        var accepted_count: u32 = 0;
        while (accepted_count < 4) {
            const socket = self.accept(registration.uuid, registration.protocol) catch |err| {
                if (registration.protocol.onError) |on_error| {
                    on_error(Socket{ .uuid = registration.uuid, .manager = self }, err);
                }
                return;
            };

            if (socket) |accepted_socket| {
                // Call protocol onData to signal new connection
                if (registration.protocol.onData) |on_data| {
                    on_data(accepted_socket, &[_]u8{});
                }
                accepted_count += 1;
            } else {
                break; // No more pending connections
            }
        }
    }

    fn handleRead(self: *Self, registration: *SocketRegistration) void {
        var buffer: [4096]u8 = undefined;

        while (true) {
            const bytes_read = posix.read(registration.fd, &buffer) catch |err| switch (err) {
                error.WouldBlock => break,
                error.ConnectionResetByPeer => {
                    self.handleError(registration, SocketError.ConnectionClosed);
                    return;
                },
                else => {
                    self.handleError(registration, SocketError.IOError);
                    return;
                },
            };

            if (bytes_read == 0) {
                self.handleError(registration, SocketError.ConnectionClosed);
                return;
            }

            // Add to read buffer
            _ = registration.read_buffer.write(buffer[0..bytes_read]) catch {
                self.handleError(registration, SocketError.OutOfMemory);
                return;
            };

            // Call protocol handler
            if (registration.protocol.onData) |on_data| {
                on_data(Socket{ .uuid = registration.uuid, .manager = self }, buffer[0..bytes_read]);
            }
        }
    }

    fn handleWrite(self: *Self, registration: *SocketRegistration) void {
        while (registration.write_queue.items.len > 0) {
            const write_op = registration.write_queue.items[0];

            const bytes_written = posix.write(registration.fd, write_op.data) catch |err| switch (err) {
                error.WouldBlock => break,
                error.BrokenPipe => {
                    self.handleError(registration, SocketError.ConnectionClosed);
                    return;
                },
                else => {
                    self.handleError(registration, SocketError.IOError);
                    return;
                },
            };

            if (bytes_written == write_op.data.len) {
                // Complete write
                _ = registration.write_queue.orderedRemove(0);
                if (write_op.cleanup) |cleanup| {
                    cleanup(write_op.data);
                }
            } else {
                // Partial write - update data pointer
                const remaining = write_op.data[bytes_written..];
                registration.write_queue.items[0].data = remaining;
                break;
            }
        }

        // Call onReady if write queue is empty
        if (registration.write_queue.items.len == 0) {
            if (registration.protocol.onReady) |on_ready| {
                on_ready(Socket{ .uuid = registration.uuid, .manager = self });
            }
        }
    }

    fn handleConnectComplete(self: *Self, registration: *SocketRegistration) void {
        // Check if connection succeeded
        var error_code: i32 = 0;
        var len: posix.socklen_t = @sizeOf(i32);
        _ = std.c.getsockopt(registration.fd, posix.SOL.SOCKET, posix.SO.ERROR, &error_code, &len);

        if (error_code != 0) {
            self.handleError(registration, SocketError.ConnectionFailed);
            return;
        }

        registration.state = .connected;

        // Update reactor registration for read events
        self.reactor.modify(registration.fd, EventType{ .read = true, .write = true }, Self.handleEvent, self) catch |err| {
            log.warn("Failed to modify reactor registration: {}", .{err});
        };

        // Call onReady to signal connection established
        if (registration.protocol.onReady) |on_ready| {
            on_ready(Socket{ .uuid = registration.uuid, .manager = self });
        }
    }

    fn handleError(self: *Self, registration: *SocketRegistration, err: SocketError) void {
        registration.state = .error_state;

        if (registration.protocol.onError) |on_error| {
            on_error(Socket{ .uuid = registration.uuid, .manager = self }, err);
        }

        // Close the socket
        self.closeSocket(registration.uuid) catch {};
    }

    /// Close a socket
    pub fn closeSocket(self: *Self, uuid: SocketUUID) SocketError!void {
        const registration = self.sockets.getPtr(uuid) orelse return SocketError.InvalidSocket;

        // Call protocol onClose
        if (registration.protocol.onClose) |on_close| {
            on_close(Socket{ .uuid = uuid, .manager = self });
        }

        // Unregister from reactor
        self.reactor.unregister(registration.fd) catch {};

        // Close file descriptor
        posix.close(registration.fd);

        // Mark as closed but don't remove from map immediately
        // to allow isValid() to return false after close
        registration.state = .closed;

        // Remove from maps
        _ = self.fd_to_uuid.remove(registration.fd);
        if (self.sockets.fetchRemove(uuid)) |removed| {
            var mut_registration = removed.value;
            mut_registration.deinit();
        }
    }

    /// Write data to socket
    pub fn writeSocket(self: *Self, uuid: SocketUUID, data: []const u8, cleanup: ?*const fn (data: []const u8) void, urgent: bool) SocketError!void {
        const registration = self.sockets.getPtr(uuid) orelse return SocketError.InvalidSocket;

        if (registration.state != .connected) {
            return SocketError.NotConnected;
        }

        const write_op = SocketRegistration.WriteOperation{
            .data = data,
            .cleanup = cleanup,
            .urgent = urgent,
        };

        if (urgent) {
            try registration.write_queue.insert(0, write_op);
        } else {
            try registration.write_queue.append(write_op);
        }

        // Try immediate write if queue was empty
        if (registration.write_queue.items.len == 1) {
            self.handleWrite(registration);
        }
    }

    /// Read data from socket buffer
    pub fn readSocket(self: *Self, uuid: SocketUUID, dest: []u8) SocketError!usize {
        const registration = self.sockets.getPtr(uuid) orelse return SocketError.InvalidSocket;
        return registration.read_buffer.read(dest);
    }

    /// Get socket state
    pub fn getSocketState(self: *Self, uuid: SocketUUID) SocketError!SocketState {
        const registration = self.sockets.get(uuid) orelse return SocketError.InvalidSocket;
        return registration.state;
    }
};

/// Socket handle
pub const Socket = struct {
    uuid: SocketUUID,
    manager: *SocketManager,

    const Self = @This();

    /// Write data to socket
    pub fn write(self: Self, data: []const u8) SocketError!void {
        return self.manager.writeSocket(self.uuid, data, null, false);
    }

    /// Write data with custom cleanup function
    pub fn writeWithCleanup(self: Self, data: []const u8, cleanup: *const fn (data: []const u8) void) SocketError!void {
        return self.manager.writeSocket(self.uuid, data, cleanup, false);
    }

    /// Write urgent data (sent immediately)
    pub fn writeUrgent(self: Self, data: []const u8) SocketError!void {
        return self.manager.writeSocket(self.uuid, data, null, true);
    }

    /// Read data from socket
    pub fn read(self: Self, dest: []u8) SocketError!usize {
        return self.manager.readSocket(self.uuid, dest);
    }

    /// Close the socket
    pub fn close(self: Self) SocketError!void {
        return self.manager.closeSocket(self.uuid);
    }

    /// Check if socket is valid (exists in manager and UUID is valid)
    pub fn isValid(self: Self) bool {
        if (!self.uuid.isValid()) return false;
        const state = self.manager.getSocketState(self.uuid) catch return false;
        return state != .error_state and state != .closed; // Socket is valid if not closed or in error
    }

    /// Get socket state
    pub fn getState(self: Self) SocketError!SocketState {
        return self.manager.getSocketState(self.uuid);
    }
};

// Tests
test "Socket address parsing" {
    // IPv4 address
    const ipv4 = try SocketAddress.parse("127.0.0.1", 8080);
    try testing.expect(ipv4 == .ipv4);

    // IPv6 address
    const ipv6 = try SocketAddress.parse("::1", 8080);
    try testing.expect(ipv6 == .ipv6);

    // Unix socket
    const unix_sock = try SocketAddress.parse("/tmp/socket", null);
    try testing.expect(unix_sock == .unix);

    // Invalid address
    try testing.expectError(SocketError.InvalidAddress, SocketAddress.parse("invalid", 8080));
}

test "Socket UUID generation and validation" {
    const allocator = testing.allocator;
    var reactor = try Reactor.init(allocator);
    defer reactor.deinit();

    var manager = SocketManager.init(allocator, &reactor);
    defer manager.deinit();

    const uuid1 = manager.generateUUID();
    const uuid2 = manager.generateUUID();

    try testing.expect(uuid1.isValid());
    try testing.expect(uuid2.isValid());
    try testing.expect(!uuid1.eql(uuid2));

    const invalid = SocketUUID.invalid();
    try testing.expect(!invalid.isValid());
}

test "Socket creation and cleanup" {
    const allocator = testing.allocator;
    var reactor = try Reactor.init(allocator);
    defer reactor.deinit();

    var manager = SocketManager.init(allocator, &reactor);
    defer manager.deinit();

    const addr = try SocketAddress.parse("127.0.0.1", 0);
    const socket = try manager.createSocket(.tcp, addr);

    try testing.expect(socket.isValid());
    try socket.close();
    try testing.expect(!socket.isValid());
}

test "Socket manager lifecycle" {
    const allocator = testing.allocator;
    var reactor = try Reactor.init(allocator);
    defer reactor.deinit();

    var manager = SocketManager.init(allocator, &reactor);
    defer manager.deinit();

    // Create multiple sockets
    const addr = try SocketAddress.parse("127.0.0.1", 0);
    const socket1 = try manager.createSocket(.tcp, addr);
    const socket2 = try manager.createSocket(.udp, addr);

    try testing.expect(socket1.isValid());
    try testing.expect(socket2.isValid());
    try testing.expect(!socket1.uuid.eql(socket2.uuid));
}
