//! WebSocket implementation for Ferret
//!
//! This implementation provides:
//! - WebSocket handshake handling (RFC 6455)
//! - Frame parsing and generation
//! - Message fragmentation support
//! - Masking/unmasking for client frames
//! - Close frame handling with status codes
//! - Ping/pong frame support
//! - Binary and text message types

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const crypto = std.crypto;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

/// WebSocket handshake magic key for SHA-1 hash
const WEBSOCKET_MAGIC_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// WebSocket opcodes
pub const Opcode = enum(u8) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
    _,

    pub fn isControl(self: Opcode) bool {
        return @intFromEnum(self) >= 0x8;
    }

    pub fn isData(self: Opcode) bool {
        return @intFromEnum(self) <= 0x2;
    }
};

/// WebSocket close status codes
pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    no_status_rcvd = 1005,
    abnormal_closure = 1006,
    invalid_frame_payload_data = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_error = 1011,
    service_restart = 1012,
    try_again_later = 1013,
    bad_gateway = 1014,
    tls_handshake = 1015,
    _,
};

/// WebSocket per-message deflate compression implementation (RFC 7692)
pub const CompressionContext = struct {
    enabled: bool,
    server_max_window_bits: u4,
    client_max_window_bits: u4,
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .enabled = false,
            .server_max_window_bits = 15,
            .client_max_window_bits = 15,
            .server_no_context_takeover = false,
            .client_no_context_takeover = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Enable compression with specified parameters
    pub fn enable(self: *Self, server_max_window_bits: u4, client_max_window_bits: u4, server_no_context_takeover: bool, client_no_context_takeover: bool) !void {
        self.enabled = true;
        self.server_max_window_bits = server_max_window_bits;
        self.client_max_window_bits = client_max_window_bits;
        self.server_no_context_takeover = server_no_context_takeover;
        self.client_no_context_takeover = client_no_context_takeover;
    }

    /// Compress payload data using permessage-deflate
    pub fn compress(self: *Self, data: []const u8) ![]const u8 {
        if (!self.enabled) return data;

        var compressed_buf = ArrayList(u8).init(self.allocator);
        defer compressed_buf.deinit();

        // Use flate compress function for raw deflate data
        var input_stream = std.io.fixedBufferStream(data);
        try std.compress.flate.compress(input_stream.reader(), compressed_buf.writer(), .{ .level = .default });

        // Remove the trailing 0x00 0x00 0xFF 0xFF bytes as per RFC 7692
        var compressed = compressed_buf.items;
        if (compressed.len >= 4) {
            const tail = compressed[compressed.len - 4 ..];
            if (mem.eql(u8, tail, &[_]u8{ 0x00, 0x00, 0xFF, 0xFF })) {
                compressed = compressed[0 .. compressed.len - 4];
            }
        }

        return try self.allocator.dupe(u8, compressed);
    }

    /// Decompress payload data using permessage-deflate
    pub fn decompress(self: *Self, data: []const u8) ![]const u8 {
        if (!self.enabled) return try self.allocator.dupe(u8, data);

        // Add the trailing 0x00 0x00 0xFF 0xFF bytes back for decompression
        var decompress_data = ArrayList(u8).init(self.allocator);
        defer decompress_data.deinit();

        try decompress_data.appendSlice(data);
        try decompress_data.appendSlice(&[_]u8{ 0x00, 0x00, 0xFF, 0xFF });

        var decompressed_buf = ArrayList(u8).init(self.allocator);
        defer decompressed_buf.deinit();

        // Use flate decompress function for raw deflate data
        var input_stream = std.io.fixedBufferStream(decompress_data.items);
        try std.compress.flate.decompress(input_stream.reader(), decompressed_buf.writer());

        return decompressed_buf.toOwnedSlice();
    }

    /// Parse permessage-deflate extension parameters
    pub fn parseExtensionParams(self: *Self, params: []const u8) !void {
        var iter = mem.splitSequence(u8, params, ";");

        while (iter.next()) |param| {
            const trimmed = mem.trim(u8, param, " \t");

            if (mem.startsWith(u8, trimmed, "server_max_window_bits=")) {
                const value_str = trimmed[23..];
                const value = try std.fmt.parseInt(u4, value_str, 10);
                if (value >= 8 and value <= 15) {
                    self.server_max_window_bits = value;
                }
            } else if (mem.startsWith(u8, trimmed, "client_max_window_bits=")) {
                const value_str = trimmed[23..];
                const value = try std.fmt.parseInt(u4, value_str, 10);
                if (value >= 8 and value <= 15) {
                    self.client_max_window_bits = value;
                }
            } else if (mem.eql(u8, trimmed, "server_no_context_takeover")) {
                self.server_no_context_takeover = true;
            } else if (mem.eql(u8, trimmed, "client_no_context_takeover")) {
                self.client_no_context_takeover = true;
            }
        }
    }

    /// Generate extension parameters string for handshake
    pub fn generateExtensionParams(self: *const Self, allocator: Allocator) ![]u8 {
        var params = ArrayList(u8).init(allocator);

        try params.appendSlice("permessage-deflate");

        if (self.server_max_window_bits != 15) {
            try params.writer().print("; server_max_window_bits={}", .{self.server_max_window_bits});
        }

        if (self.client_max_window_bits != 15) {
            try params.writer().print("; client_max_window_bits={}", .{self.client_max_window_bits});
        }

        if (self.server_no_context_takeover) {
            try params.appendSlice("; server_no_context_takeover");
        }

        if (self.client_no_context_takeover) {
            try params.appendSlice("; client_no_context_takeover");
        }

        return params.toOwnedSlice();
    }
};

/// WebSocket frame header information
pub const FrameHeader = struct {
    fin: bool,
    rsv1: bool,
    rsv2: bool,
    rsv3: bool,
    opcode: Opcode,
    masked: bool,
    payload_length: u64,
    mask_key: ?[4]u8,
    header_size: u8,

    const Self = @This();

    /// Parse frame header from buffer
    pub fn parse(data: []const u8) ?Self {
        if (data.len < 2) return null;

        const byte1 = data[0];
        const byte2 = data[1];

        const fin = (byte1 & 0x80) != 0;
        const rsv1 = (byte1 & 0x40) != 0;
        const rsv2 = (byte1 & 0x20) != 0;
        const rsv3 = (byte1 & 0x10) != 0;
        const opcode: Opcode = @enumFromInt(byte1 & 0x0f);

        const masked = (byte2 & 0x80) != 0;
        const payload_len = byte2 & 0x7f;

        var pos: usize = 2;
        var payload_length: u64 = payload_len;

        // Extended payload length
        if (payload_len == 126) {
            if (data.len < pos + 2) return null;
            payload_length = mem.readInt(u16, data[pos .. pos + 2][0..2], .big);
            pos += 2;
        } else if (payload_len == 127) {
            if (data.len < pos + 8) return null;
            payload_length = mem.readInt(u64, data[pos .. pos + 8][0..8], .big);
            pos += 8;
        }

        // Mask key
        var mask_key: ?[4]u8 = null;
        if (masked) {
            if (data.len < pos + 4) return null;
            mask_key = data[pos .. pos + 4][0..4].*;
            pos += 4;
        }

        return Self{
            .fin = fin,
            .rsv1 = rsv1,
            .rsv2 = rsv2,
            .rsv3 = rsv3,
            .opcode = opcode,
            .masked = masked,
            .payload_length = payload_length,
            .mask_key = mask_key,
            .header_size = @intCast(pos),
        };
    }

    /// Generate frame header bytes
    pub fn generate(self: *const Self, allocator: Allocator) ![]u8 {
        var header = std.ArrayList(u8).init(allocator);
        defer header.deinit();

        // First byte: FIN + RSV + opcode
        var byte1: u8 = @intFromEnum(self.opcode);
        if (self.fin) byte1 |= 0x80;
        if (self.rsv1) byte1 |= 0x40;
        if (self.rsv2) byte1 |= 0x20;
        if (self.rsv3) byte1 |= 0x10;
        try header.append(byte1);

        // Second byte: MASK + payload length
        var byte2: u8 = 0;
        if (self.masked) byte2 |= 0x80;

        if (self.payload_length < 126) {
            byte2 |= @intCast(self.payload_length);
            try header.append(byte2);
        } else if (self.payload_length <= 65535) {
            byte2 |= 126;
            try header.append(byte2);
            const len_bytes = mem.toBytes(mem.nativeToBig(u16, @intCast(self.payload_length)));
            try header.appendSlice(&len_bytes);
        } else {
            byte2 |= 127;
            try header.append(byte2);
            const len_bytes = mem.toBytes(mem.nativeToBig(u64, self.payload_length));
            try header.appendSlice(&len_bytes);
        }

        // Mask key
        if (self.mask_key) |mask| {
            try header.appendSlice(&mask);
        }

        return header.toOwnedSlice();
    }
};

/// WebSocket frame
pub const Frame = struct {
    header: FrameHeader,
    payload: []const u8,
    owns_payload: bool = false, // Track if we own the payload memory
    allocator: ?Allocator = null, // Store allocator for deallocation

    const Self = @This();

    /// Create text frame
    pub fn text(allocator: Allocator, data: []const u8, masked: bool) !Self {
        const mask_key = if (masked) generateMaskKey() else null;

        // Always duplicate payload to ensure memory safety
        const owned_payload = try allocator.dupe(u8, data);

        return Self{
            .header = FrameHeader{
                .fin = true,
                .rsv1 = false,
                .rsv2 = false,
                .rsv3 = false,
                .opcode = .text,
                .masked = masked,
                .payload_length = data.len,
                .mask_key = mask_key,
                .header_size = 0, // Will be calculated when serializing
            },
            .payload = owned_payload,
            .owns_payload = true,
            .allocator = allocator,
        };
    }

    /// Create compressed text frame (sets RSV1 bit)
    pub fn compressedText(_: Allocator, data: []const u8, masked: bool, compression: *CompressionContext) !Self {
        const compressed_data = try compression.compress(data);
        const mask_key = if (masked) generateMaskKey() else null;

        return Self{
            .header = FrameHeader{
                .fin = true,
                .rsv1 = true, // Compression flag
                .rsv2 = false,
                .rsv3 = false,
                .opcode = .text,
                .masked = masked,
                .payload_length = compressed_data.len,
                .mask_key = mask_key,
                .header_size = 0,
            },
            .payload = compressed_data,
        };
    }

    /// Create binary frame
    pub fn binary(allocator: Allocator, data: []const u8, masked: bool) !Self {
        const mask_key = if (masked) generateMaskKey() else null;

        // Always duplicate payload to ensure memory safety
        const owned_payload = try allocator.dupe(u8, data);

        return Self{
            .header = FrameHeader{
                .fin = true,
                .rsv1 = false,
                .rsv2 = false,
                .rsv3 = false,
                .opcode = .binary,
                .masked = masked,
                .payload_length = data.len,
                .mask_key = mask_key,
                .header_size = 0,
            },
            .payload = owned_payload,
            .owns_payload = true,
            .allocator = allocator,
        };
    }

    /// Create compressed binary frame (sets RSV1 bit)
    pub fn compressedBinary(_: Allocator, data: []const u8, masked: bool, compression: *CompressionContext) !Self {
        const compressed_data = try compression.compress(data);
        const mask_key = if (masked) generateMaskKey() else null;

        return Self{
            .header = FrameHeader{
                .fin = true,
                .rsv1 = true, // Compression flag
                .rsv2 = false,
                .rsv3 = false,
                .opcode = .binary,
                .masked = masked,
                .payload_length = compressed_data.len,
                .mask_key = mask_key,
                .header_size = 0,
            },
            .payload = compressed_data,
        };
    }

    /// Decompress frame payload if compressed (RSV1 bit set)
    pub fn decompressPayload(self: *const Self, compression: *CompressionContext) ![]u8 {
        if (!self.header.rsv1 or !compression.enabled) {
            // Not compressed or compression not enabled, return payload as-is
            return try compression.allocator.dupe(u8, self.payload);
        }

        // Decompress the payload
        const decompressed = try compression.decompress(self.payload);
        return @constCast(decompressed);
    }

    /// Check if frame is compressed
    pub fn isCompressed(self: *const Self) bool {
        return self.header.rsv1;
    }

    /// Create close frame
    pub fn close(allocator: Allocator, code: CloseCode, reason: ?[]const u8, masked: bool) !Self {
        const mask_key = if (masked) generateMaskKey() else null;
        const reason_bytes = reason orelse "";

        // Close frame payload: 2-byte status code + optional reason
        var payload = try allocator.alloc(u8, 2 + reason_bytes.len);
        mem.writeInt(u16, payload[0..2], @intFromEnum(code), .big);
        @memcpy(payload[2..], reason_bytes);

        return Self{
            .header = FrameHeader{
                .fin = true,
                .rsv1 = false,
                .rsv2 = false,
                .rsv3 = false,
                .opcode = .close,
                .masked = masked,
                .payload_length = payload.len,
                .mask_key = mask_key,
                .header_size = 0,
            },
            .payload = payload,
            .owns_payload = true,
            .allocator = allocator,
        };
    }

    /// Create ping frame
    pub fn ping(allocator: Allocator, data: ?[]const u8, masked: bool) !Self {
        const payload = data orelse &[_]u8{};
        const mask_key = if (masked) generateMaskKey() else null;

        // Always duplicate payload to ensure memory safety
        const owned_payload = try allocator.dupe(u8, payload);

        return Self{
            .header = FrameHeader{
                .fin = true,
                .rsv1 = false,
                .rsv2 = false,
                .rsv3 = false,
                .opcode = .ping,
                .masked = masked,
                .payload_length = payload.len,
                .mask_key = mask_key,
                .header_size = 0,
            },
            .payload = owned_payload,
            .owns_payload = true,
            .allocator = allocator,
        };
    }

    /// Create pong frame
    pub fn pong(allocator: Allocator, data: ?[]const u8, masked: bool) !Self {
        const payload = data orelse &[_]u8{};
        const mask_key = if (masked) generateMaskKey() else null;

        // Always duplicate payload to ensure memory safety
        const owned_payload = try allocator.dupe(u8, payload);

        return Self{
            .header = FrameHeader{
                .fin = true,
                .rsv1 = false,
                .rsv2 = false,
                .rsv3 = false,
                .opcode = .pong,
                .masked = masked,
                .payload_length = payload.len,
                .mask_key = mask_key,
                .header_size = 0,
            },
            .payload = owned_payload,
            .owns_payload = true,
            .allocator = allocator,
        };
    }

    /// Serialize frame to bytes
    pub fn serialize(self: *const Self, allocator: Allocator) ![]u8 {
        const header_bytes = try self.header.generate(allocator);
        defer allocator.free(header_bytes);

        var result = try allocator.alloc(u8, header_bytes.len + self.payload.len);
        @memcpy(result[0..header_bytes.len], header_bytes);
        @memcpy(result[header_bytes.len..], self.payload);

        // Apply masking if needed
        if (self.header.mask_key) |mask| {
            maskPayload(result[header_bytes.len..], mask);
        }

        return result;
    }

    /// Create a frame from parsed data without duplicating payload (for parsing)
    pub fn fromParsedData(header: FrameHeader, payload: []const u8) Self {
        return Self{
            .header = header,
            .payload = payload,
            .owns_payload = false,
            .allocator = null,
        };
    }

    /// Create a frame that takes ownership of existing allocated payload
    pub fn fromOwnedData(allocator: Allocator, header: FrameHeader, payload: []u8) Self {
        return Self{
            .header = header,
            .payload = payload,
            .owns_payload = true,
            .allocator = allocator,
        };
    }

    /// Deinitialize frame and free owned payload
    pub fn deinit(self: *Self) void {
        if (self.owns_payload) {
            if (self.allocator) |allocator| {
                allocator.free(@constCast(self.payload));
            }
        }
        self.* = undefined;
    }
};

/// WebSocket parser for parsing frames from incoming data
pub const Parser = struct {
    state: enum {
        waiting_for_header,
        waiting_for_payload,
        frame_complete,
    } = .waiting_for_header,

    header: ?FrameHeader = null,
    payload_buffer: std.ArrayList(u8),
    bytes_needed: usize = 2, // Minimum header size

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .payload_buffer = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.payload_buffer.deinit();
    }

    pub fn reset(self: *Self) void {
        self.state = .waiting_for_header;
        self.header = null;
        self.payload_buffer.clearRetainingCapacity();
        self.bytes_needed = 2;
    }

    /// Parse incoming data, returns completed frame if available
    pub fn parse(self: *Self, data: []const u8) !?Frame {
        var pos: usize = 0;

        while (pos < data.len) {
            switch (self.state) {
                .waiting_for_header => {
                    // Try to parse header
                    if (FrameHeader.parse(data[pos..])) |header| {
                        self.header = header;
                        pos += header.header_size;

                        if (header.payload_length == 0) {
                            // No payload, frame is complete
                            self.state = .frame_complete;
                            return Frame.fromParsedData(header, &[_]u8{});
                        } else {
                            // Need to read payload
                            self.state = .waiting_for_payload;
                            self.bytes_needed = header.payload_length;
                            try self.payload_buffer.ensureTotalCapacity(header.payload_length);
                        }
                    } else {
                        // Not enough data for header
                        break;
                    }
                },
                .waiting_for_payload => {
                    const header = self.header.?;
                    const remaining = data.len - pos;
                    const bytes_to_read = @min(remaining, self.bytes_needed);

                    try self.payload_buffer.appendSlice(data[pos .. pos + bytes_to_read]);
                    pos += bytes_to_read;
                    self.bytes_needed -= bytes_to_read;

                    if (self.bytes_needed == 0) {
                        // Payload complete
                        var payload_owned = try self.payload_buffer.toOwnedSlice();

                        // Unmask if necessary
                        if (header.mask_key) |mask| {
                            // Must use explicit mutation to avoid compiler warning
                            _ = &payload_owned; // Mark as mutable
                            maskPayload(payload_owned, mask);
                        }

                        self.state = .frame_complete;
                        // Create frame that takes ownership of the payload
                        return Frame.fromOwnedData(self.payload_buffer.allocator, header, payload_owned);
                    }
                },
                .frame_complete => {
                    // Should not reach here in normal flow
                    break;
                },
            }
        }

        return null; // No complete frame yet
    }
};

/// WebSocket connection state
pub const ConnectionState = enum {
    handshaking,
    connected,
    closing,
    closed,
};

/// WebSocket connection errors
pub const WebSocketError = error{
    InvalidHandshake,
    UnsupportedVersion,
    MissingKey,
    InvalidKey,
    ProtocolError,
    MessageTooLarge,
    ConnectionClosed,
    InvalidFrame,
    OutOfMemory,
    NetworkError,
};

/// WebSocket message types
pub const MessageType = enum {
    text,
    binary,
    ping,
    pong,
    close,
};

/// WebSocket message
pub const Message = struct {
    type: MessageType,
    data: []const u8,
    allocator: ?Allocator = null,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        if (self.allocator) |alloc| {
            alloc.free(self.data);
        }
    }
};

/// WebSocket connection handler
pub const Connection = struct {
    allocator: Allocator,
    parser: Parser,
    state: ConnectionState,
    is_server: bool,
    message_buffer: std.ArrayList(u8),
    fragmented_type: ?Opcode = null,

    // Configuration
    max_message_size: usize = 16 * 1024 * 1024, // 16MB default
    ping_interval_ms: u32 = 30000, // 30 seconds
    close_timeout_ms: u32 = 5000, // 5 seconds

    // Statistics
    messages_sent: u64 = 0,
    messages_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,

    const Self = @This();

    pub fn init(allocator: Allocator, is_server: bool) Self {
        return Self{
            .allocator = allocator,
            .parser = Parser.init(allocator),
            .state = .handshaking,
            .is_server = is_server,
            .message_buffer = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.parser.deinit();
        self.message_buffer.deinit();
    }

    /// Handle incoming data and return any complete messages
    pub fn handleData(self: *Self, data: []const u8) ![]Message {
        if (self.state != .connected) {
            return error.ConnectionClosed;
        }

        var messages = std.ArrayList(Message).init(self.allocator);
        errdefer {
            for (messages.items) |*msg| {
                msg.deinit();
            }
            messages.deinit();
        }

        var remaining = data;
        while (remaining.len > 0) {
            if (try self.parser.parse(remaining)) |frame| {
                var mutable_frame = frame;
                defer mutable_frame.deinit();

                // Update statistics
                self.bytes_received += remaining.len;

                // Process frame based on opcode
                switch (mutable_frame.header.opcode) {
                    .text, .binary => {
                        if (try self.handleDataFrame(mutable_frame)) |message| {
                            try messages.append(message);
                            self.messages_received += 1;
                        }
                    },
                    .continuation => {
                        if (try self.handleContinuationFrame(mutable_frame)) |message| {
                            try messages.append(message);
                            self.messages_received += 1;
                        }
                    },
                    .ping => {
                        try messages.append(Message{
                            .type = .ping,
                            .data = try self.allocator.dupe(u8, mutable_frame.payload),
                            .allocator = self.allocator,
                        });
                    },
                    .pong => {
                        try messages.append(Message{
                            .type = .pong,
                            .data = try self.allocator.dupe(u8, mutable_frame.payload),
                            .allocator = self.allocator,
                        });
                    },
                    .close => {
                        self.state = .closing;
                        try messages.append(Message{
                            .type = .close,
                            .data = try self.allocator.dupe(u8, mutable_frame.payload),
                            .allocator = self.allocator,
                        });
                    },
                    else => {
                        return error.ProtocolError;
                    },
                }

                // Reset parser for next frame
                self.parser.reset();

                // Advance remaining data
                const frame_size = mutable_frame.header.header_size + mutable_frame.payload.len;
                remaining = remaining[frame_size..];
            } else {
                // No complete frame yet
                break;
            }
        }

        return messages.toOwnedSlice();
    }

    /// Send a text message
    pub fn sendText(self: *Self, text: []const u8) ![]u8 {
        if (self.state != .connected) {
            return error.ConnectionClosed;
        }

        var frame = try Frame.text(self.allocator, text, !self.is_server);
        defer frame.deinit();
        const serialized = try frame.serialize(self.allocator);

        self.messages_sent += 1;
        self.bytes_sent += serialized.len;

        return serialized;
    }

    /// Send a binary message
    pub fn sendBinary(self: *Self, data: []const u8) ![]u8 {
        if (self.state != .connected) {
            return error.ConnectionClosed;
        }

        var frame = try Frame.binary(self.allocator, data, !self.is_server);
        defer frame.deinit();
        const serialized = try frame.serialize(self.allocator);

        self.messages_sent += 1;
        self.bytes_sent += serialized.len;

        return serialized;
    }

    /// Send a ping frame
    pub fn sendPing(self: *Self, data: ?[]const u8) ![]u8 {
        if (self.state != .connected) {
            return error.ConnectionClosed;
        }

        var frame = try Frame.ping(self.allocator, data, !self.is_server);
        defer frame.deinit();
        return try frame.serialize(self.allocator);
    }

    /// Send a pong frame (response to ping)
    pub fn sendPong(self: *Self, data: ?[]const u8) ![]u8 {
        if (self.state != .connected) {
            return error.ConnectionClosed;
        }

        var frame = try Frame.pong(self.allocator, data, !self.is_server);
        defer frame.deinit();
        return try frame.serialize(self.allocator);
    }

    /// Send a close frame
    pub fn sendClose(self: *Self, code: CloseCode, reason: ?[]const u8) ![]u8 {
        if (self.state == .closed) {
            return error.ConnectionClosed;
        }

        self.state = .closing;

        var frame = try Frame.close(self.allocator, code, reason, !self.is_server);
        defer frame.deinit();

        return try frame.serialize(self.allocator);
    }

    /// Get connection statistics
    pub fn getStats(self: Self) ConnectionStats {
        return ConnectionStats{
            .messages_sent = self.messages_sent,
            .messages_received = self.messages_received,
            .bytes_sent = self.bytes_sent,
            .bytes_received = self.bytes_received,
            .state = self.state,
        };
    }

    // Private helper methods

    fn handleDataFrame(self: *Self, frame: Frame) !?Message {
        if (!frame.header.fin) {
            // Start of fragmented message
            if (self.fragmented_type != null) {
                return error.ProtocolError; // Already have fragmented message
            }

            self.fragmented_type = frame.header.opcode;
            try self.message_buffer.appendSlice(frame.payload);

            if (self.message_buffer.items.len > self.max_message_size) {
                return error.MessageTooLarge;
            }

            return null; // Not complete yet
        } else {
            // Complete message
            const message_type: MessageType = switch (frame.header.opcode) {
                .text => .text,
                .binary => .binary,
                else => return error.ProtocolError,
            };

            const data = try self.allocator.dupe(u8, frame.payload);
            return Message{
                .type = message_type,
                .data = data,
                .allocator = self.allocator,
            };
        }
    }

    fn handleContinuationFrame(self: *Self, frame: Frame) !?Message {
        if (self.fragmented_type == null) {
            return error.ProtocolError; // No fragmented message in progress
        }

        try self.message_buffer.appendSlice(frame.payload);

        if (self.message_buffer.items.len > self.max_message_size) {
            return error.MessageTooLarge;
        }

        if (frame.header.fin) {
            // Message complete
            const message_type: MessageType = switch (self.fragmented_type.?) {
                .text => .text,
                .binary => .binary,
                else => return error.ProtocolError,
            };

            const data = try self.message_buffer.toOwnedSlice();
            self.fragmented_type = null;

            return Message{
                .type = message_type,
                .data = data,
                .allocator = self.allocator,
            };
        }

        return null; // Still fragmenting
    }
};

/// Connection statistics
pub const ConnectionStats = struct {
    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    state: ConnectionState,
};

/// WebSocket upgrade handler for HTTP servers
pub const UpgradeHandler = struct {
    /// Perform WebSocket handshake upgrade
    pub fn performUpgrade(allocator: Allocator, request_headers: anytype) !UpgradeResponse {
        // Validate handshake headers
        if (!Handshake.validateHandshake(request_headers)) {
            return error.InvalidHandshake;
        }

        // Get client key
        const client_key = request_headers.get("sec-websocket-key") orelse return error.MissingKey;

        // Generate accept key
        const accept_key = try Handshake.generateAcceptKey(allocator, client_key);

        // Check for subprotocols
        const subprotocols = request_headers.get("sec-websocket-protocol");

        // Check for extensions
        const extensions = request_headers.get("sec-websocket-extensions");

        return UpgradeResponse{
            .accept_key = accept_key,
            .subprotocol = if (subprotocols) |sp| try selectSubprotocol(allocator, sp) else null,
            .extensions = if (extensions) |ext| try selectExtensions(allocator, ext) else null,
        };
    }

    /// Generate HTTP response for successful WebSocket upgrade
    pub fn generateResponse(allocator: Allocator, upgrade: UpgradeResponse) ![]u8 {
        var response = std.ArrayList(u8).init(allocator);
        defer response.deinit();

        try response.appendSlice("HTTP/1.1 101 Switching Protocols\r\n");
        try response.appendSlice("Upgrade: websocket\r\n");
        try response.appendSlice("Connection: Upgrade\r\n");

        try response.appendSlice("Sec-WebSocket-Accept: ");
        try response.appendSlice(upgrade.accept_key);
        try response.appendSlice("\r\n");

        if (upgrade.subprotocol) |subproto| {
            try response.appendSlice("Sec-WebSocket-Protocol: ");
            try response.appendSlice(subproto);
            try response.appendSlice("\r\n");
        }

        if (upgrade.extensions) |ext| {
            try response.appendSlice("Sec-WebSocket-Extensions: ");
            try response.appendSlice(ext);
            try response.appendSlice("\r\n");
        }

        try response.appendSlice("\r\n");

        return response.toOwnedSlice();
    }

    /// Supported WebSocket subprotocols (can be configured)
    const SUPPORTED_SUBPROTOCOLS = [_][]const u8{
        "chat",
        "echo",
        "json",
        "binary",
    };

    /// Supported WebSocket extensions
    const SUPPORTED_EXTENSIONS = [_][]const u8{
        "permessage-deflate",
    };

    fn selectSubprotocol(allocator: Allocator, requested: []const u8) ![]const u8 {
        _ = allocator;

        // Parse requested subprotocols
        var iter = std.mem.splitSequence(u8, requested, ",");
        while (iter.next()) |protocol| {
            const trimmed = std.mem.trim(u8, protocol, " \t");

            // Check if we support this subprotocol
            for (SUPPORTED_SUBPROTOCOLS) |supported| {
                if (std.mem.eql(u8, trimmed, supported)) {
                    return supported;
                }
            }
        }

        return ""; // No supported subprotocol found
    }

    fn selectExtensions(allocator: Allocator, requested: []const u8) ![]const u8 {
        var selected = std.ArrayList(u8).init(allocator);
        defer selected.deinit();

        // Parse requested extensions
        var iter = std.mem.splitSequence(u8, requested, ",");
        while (iter.next()) |extension| {
            const trimmed = std.mem.trim(u8, extension, " \t");

            // Parse extension name and parameters
            var ext_iter = std.mem.splitSequence(u8, trimmed, ";");
            if (ext_iter.next()) |ext_name| {
                const ext_name_trimmed = std.mem.trim(u8, ext_name, " \t");

                // Check if we support this extension
                for (SUPPORTED_EXTENSIONS) |supported| {
                    if (std.mem.eql(u8, ext_name_trimmed, supported)) {
                        if (selected.items.len > 0) {
                            try selected.appendSlice(", ");
                        }

                        if (std.mem.eql(u8, supported, "permessage-deflate")) {
                            // Parse permessage-deflate parameters and respond appropriately
                            var compression_ctx = CompressionContext.init(allocator);
                            defer compression_ctx.deinit();

                            // Parse client parameters
                            while (ext_iter.next()) |param| {
                                const param_trimmed = std.mem.trim(u8, param, " \t");
                                try compression_ctx.parseExtensionParams(param_trimmed);
                            }

                            // Generate response parameters
                            const response_params = try compression_ctx.generateExtensionParams(allocator);
                            defer allocator.free(response_params);
                            try selected.appendSlice(response_params);
                        } else {
                            try selected.appendSlice(supported);
                        }
                        break;
                    }
                }
            }
        }

        return selected.toOwnedSlice();
    }
};

/// WebSocket upgrade response data
pub const UpgradeResponse = struct {
    accept_key: []const u8,
    subprotocol: ?[]const u8 = null,
    extensions: ?[]const u8 = null,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.accept_key);
        if (self.subprotocol) |sp| allocator.free(sp);
        if (self.extensions) |ext| allocator.free(ext);
    }
};

/// WebSocket handshake utilities
pub const Handshake = struct {
    /// Generate WebSocket accept key from client key
    pub fn generateAcceptKey(allocator: Allocator, client_key: []const u8) ![]u8 {
        // Concatenate client key with magic string
        const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ client_key, WEBSOCKET_MAGIC_KEY });
        defer allocator.free(combined);

        // Hash with SHA-1
        var sha1 = crypto.hash.Sha1.init(.{});
        sha1.update(combined);
        var hash: [20]u8 = undefined;
        sha1.final(&hash);

        // Base64 encode
        const encoder = std.base64.standard.Encoder;
        const encoded = try allocator.alloc(u8, encoder.calcSize(hash.len));
        _ = encoder.encode(encoded, &hash);
        return encoded;
    }

    /// Validate WebSocket handshake headers
    pub fn validateHandshake(headers: anytype) bool {
        // Check required headers
        if (headers.get("upgrade")) |upgrade| {
            if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return false;
        } else return false;

        if (headers.get("connection")) |connection| {
            // Connection header should contain "upgrade" (case-insensitive)
            var i: usize = 0;
            while (i <= connection.len - 7) : (i += 1) {
                if (std.ascii.startsWithIgnoreCase(connection[i..], "upgrade")) {
                    break;
                }
            } else return false;
        } else return false;

        if (headers.get("sec-websocket-version")) |version| {
            if (!mem.eql(u8, version, "13")) return false;
        } else return false;

        if (headers.get("sec-websocket-key")) |key| {
            if (key.len != 24) return false; // Base64 encoded 16 bytes
        } else return false;

        return true;
    }

    /// Check if HTTP request is a WebSocket upgrade request
    pub fn isUpgradeRequest(headers: anytype) bool {
        // Check for upgrade header
        if (headers.get("upgrade")) |upgrade| {
            if (std.ascii.eqlIgnoreCase(upgrade, "websocket")) {
                // Check for connection upgrade
                if (headers.get("connection")) |connection| {
                    var i: usize = 0;
                    while (i <= connection.len - 7) : (i += 1) {
                        if (std.ascii.startsWithIgnoreCase(connection[i..], "upgrade")) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
};

/// Generate random 4-byte mask key
fn generateMaskKey() [4]u8 {
    var mask: [4]u8 = undefined;
    crypto.random.bytes(&mask);
    return mask;
}

/// Apply/remove XOR mask to payload
fn maskPayload(payload: []u8, mask: [4]u8) void {
    for (payload, 0..) |*byte, i| {
        byte.* ^= mask[i % 4];
    }
}

// Tests
test "WebSocket frame header parsing" {
    // Simple text frame: FIN=1, opcode=1, no mask, length=5
    const data = [_]u8{ 0x81, 0x05 };

    const header = FrameHeader.parse(&data).?;
    try testing.expect(header.fin == true);
    try testing.expect(header.opcode == .text);
    try testing.expect(header.masked == false);
    try testing.expect(header.payload_length == 5);
    try testing.expect(header.header_size == 2);
}

test "WebSocket frame header parsing - extended length" {
    // Frame with 126 byte payload
    const data = [_]u8{ 0x81, 0x7e, 0x00, 0x7e };

    const header = FrameHeader.parse(&data).?;
    try testing.expect(header.payload_length == 126);
    try testing.expect(header.header_size == 4);
}

test "WebSocket frame header parsing - masked" {
    // Masked frame with 4-byte mask
    const data = [_]u8{ 0x81, 0x85, 0x12, 0x34, 0x56, 0x78 };

    const header = FrameHeader.parse(&data).?;
    try testing.expect(header.masked == true);
    try testing.expect(header.payload_length == 5);
    try testing.expect(header.mask_key.?[0] == 0x12);
    try testing.expect(header.mask_key.?[1] == 0x34);
    try testing.expect(header.mask_key.?[2] == 0x56);
    try testing.expect(header.mask_key.?[3] == 0x78);
    try testing.expect(header.header_size == 6);
}

test "WebSocket frame creation" {
    var text_frame = try Frame.text(testing.allocator, "hello", false);
    defer text_frame.deinit();
    try testing.expect(text_frame.header.opcode == .text);
    try testing.expect(text_frame.header.fin == true);
    try testing.expect(text_frame.header.masked == false);
    try testing.expect(text_frame.header.payload_length == 5);
    try testing.expectEqualStrings(text_frame.payload, "hello");
}

test "WebSocket handshake key generation" {
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    const accept_key = try Handshake.generateAcceptKey(testing.allocator, client_key);
    defer testing.allocator.free(accept_key);

    // Expected result from RFC 6455 example
    try testing.expectEqualStrings(accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

test "WebSocket frame serialization" {
    var frame = try Frame.text(testing.allocator, "hello", false);
    defer frame.deinit();
    const serialized = try frame.serialize(testing.allocator);
    defer testing.allocator.free(serialized);

    // Should be: 0x81 0x05 "hello"
    try testing.expect(serialized.len == 7);
    try testing.expect(serialized[0] == 0x81); // FIN + text opcode
    try testing.expect(serialized[1] == 0x05); // Unmaksed + length 5
    try testing.expectEqualStrings(serialized[2..], "hello");
}

test "WebSocket masking" {
    var payload = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    const mask = [_]u8{ 0x12, 0x34, 0x56, 0x78 };

    // Apply mask
    maskPayload(&payload, mask);

    // Verify data is changed
    try testing.expect(payload[0] != 'h');

    // Remove mask (XOR is reversible)
    maskPayload(&payload, mask);

    // Should be back to original
    try testing.expectEqualStrings(&payload, "hello");
}

test "WebSocket parser - simple frame" {
    var parser = Parser.init(testing.allocator);
    defer parser.deinit();

    // Text frame: "hello"
    const frame_data = [_]u8{ 0x81, 0x05, 'h', 'e', 'l', 'l', 'o' };

    const frame = try parser.parse(&frame_data);
    try testing.expect(frame != null);

    const parsed_frame = frame.?;
    defer testing.allocator.free(parsed_frame.payload);
    try testing.expect(parsed_frame.header.opcode == .text);
    try testing.expect(parsed_frame.header.fin == true);
    try testing.expectEqualStrings(parsed_frame.payload, "hello");
}

test "WebSocket parser - fragmented input" {
    var parser = Parser.init(testing.allocator);
    defer parser.deinit();

    // Send header first
    const header_data = [_]u8{ 0x81, 0x05 };
    var frame = try parser.parse(&header_data);
    try testing.expect(frame == null); // Not complete yet

    // Send payload
    const payload_data = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    frame = try parser.parse(&payload_data);
    try testing.expect(frame != null);

    const parsed_frame = frame.?;
    defer testing.allocator.free(parsed_frame.payload);
    try testing.expect(parsed_frame.header.opcode == .text);
    try testing.expectEqualStrings(parsed_frame.payload, "hello");
}

test "WebSocket connection - message handling" {
    var connection = Connection.init(testing.allocator, true);
    defer connection.deinit();

    // Manually set state to connected for testing
    connection.state = .connected;

    // Create test text message frame
    var text_frame = try Frame.text(testing.allocator, "Hello WebSocket!", false);
    defer text_frame.deinit();
    const serialized = try text_frame.serialize(testing.allocator);
    defer testing.allocator.free(serialized);

    // Handle the data
    const messages = try connection.handleData(serialized);
    defer {
        for (messages) |*msg| {
            var mut_msg = msg;
            mut_msg.deinit();
        }
        testing.allocator.free(messages);
    }

    try testing.expect(messages.len == 1);
    try testing.expect(messages[0].type == .text);
    try testing.expectEqualStrings(messages[0].data, "Hello WebSocket!");
}

test "WebSocket connection - send text message" {
    var connection = Connection.init(testing.allocator, false); // Client
    defer connection.deinit();

    connection.state = .connected;

    const serialized = try connection.sendText("Hello from client!");
    defer testing.allocator.free(serialized);

    // Parse the serialized frame to verify
    const header = FrameHeader.parse(serialized).?;
    try testing.expect(header.opcode == .text);
    try testing.expect(header.fin == true);
    try testing.expect(header.masked == true); // Client messages should be masked

    const stats = connection.getStats();
    try testing.expect(stats.messages_sent == 1);
}

test "WebSocket connection - ping/pong" {
    var connection = Connection.init(testing.allocator, true); // Server
    defer connection.deinit();

    connection.state = .connected;

    // Send ping
    const ping_data = try connection.sendPing("ping data");
    defer testing.allocator.free(ping_data);

    // Send pong
    const pong_data = try connection.sendPong("pong data");
    defer testing.allocator.free(pong_data);

    // Verify ping frame
    const ping_header = FrameHeader.parse(ping_data).?;
    try testing.expect(ping_header.opcode == .ping);
    try testing.expect(ping_header.masked == false); // Server messages not masked
}

test "WebSocket connection - close handling" {
    var connection = Connection.init(testing.allocator, true);
    defer connection.deinit();

    connection.state = .connected;

    const close_data = try connection.sendClose(.normal, "Goodbye");
    defer testing.allocator.free(close_data);

    try testing.expect(connection.state == .closing);

    const header = FrameHeader.parse(close_data).?;
    try testing.expect(header.opcode == .close);
}

test "WebSocket upgrade handler - valid handshake" {
    // Create a mock headers map
    var headers = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(testing.allocator);
    defer headers.deinit();

    try headers.put("upgrade", "websocket");
    try headers.put("connection", "upgrade");
    try headers.put("sec-websocket-version", "13");
    try headers.put("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

    const upgrade_response = try UpgradeHandler.performUpgrade(testing.allocator, headers);
    defer {
        var mut_response = upgrade_response;
        mut_response.deinit(testing.allocator);
    }

    // Check that accept key was generated
    try testing.expect(upgrade_response.accept_key.len > 0);
    try testing.expectEqualStrings(upgrade_response.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

test "WebSocket upgrade handler - invalid handshake" {
    var headers = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(testing.allocator);
    defer headers.deinit();

    // Missing required headers
    try headers.put("upgrade", "websocket");
    // Missing connection, version, and key headers

    try testing.expectError(error.InvalidHandshake, UpgradeHandler.performUpgrade(testing.allocator, headers));
}

test "WebSocket upgrade handler - response generation" {
    var upgrade_response = UpgradeResponse{
        .accept_key = try testing.allocator.dupe(u8, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        .subprotocol = try testing.allocator.dupe(u8, "chat"),
        .extensions = null,
    };
    defer upgrade_response.deinit(testing.allocator);

    const response = try UpgradeHandler.generateResponse(testing.allocator, upgrade_response);
    defer testing.allocator.free(response);

    // Check that response contains required headers
    try testing.expect(mem.indexOf(u8, response, "HTTP/1.1 101 Switching Protocols") != null);
    try testing.expect(mem.indexOf(u8, response, "Upgrade: websocket") != null);
    try testing.expect(mem.indexOf(u8, response, "Connection: Upgrade") != null);
    try testing.expect(mem.indexOf(u8, response, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != null);
    try testing.expect(mem.indexOf(u8, response, "Sec-WebSocket-Protocol: chat") != null);
}

test "WebSocket handshake - upgrade request detection" {
    var headers = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(testing.allocator);
    defer headers.deinit();

    // Valid upgrade request
    try headers.put("upgrade", "websocket");
    try headers.put("connection", "upgrade");

    try testing.expect(Handshake.isUpgradeRequest(headers) == true);

    // Invalid upgrade request
    _ = headers.remove("upgrade");
    try headers.put("upgrade", "http2");

    try testing.expect(Handshake.isUpgradeRequest(headers) == false);
}

test "WebSocket message fragmentation" {
    var connection = Connection.init(testing.allocator, true);
    defer connection.deinit();

    connection.state = .connected;

    // Create fragmented text message (2 fragments)
    const fragment1_header = FrameHeader{
        .fin = false, // Not final
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .text,
        .masked = false,
        .payload_length = 5,
        .mask_key = null,
        .header_size = 2,
    };

    const fragment2_header = FrameHeader{
        .fin = true, // Final
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = .continuation,
        .masked = false,
        .payload_length = 6,
        .mask_key = null,
        .header_size = 2,
    };

    const fragment1 = Frame{ .header = fragment1_header, .payload = "Hello" };
    const fragment2 = Frame{ .header = fragment2_header, .payload = " World" };

    const serialized1 = try fragment1.serialize(testing.allocator);
    defer testing.allocator.free(serialized1);
    const serialized2 = try fragment2.serialize(testing.allocator);
    defer testing.allocator.free(serialized2);

    // Handle first fragment
    const messages1 = try connection.handleData(serialized1);
    defer testing.allocator.free(messages1);
    try testing.expect(messages1.len == 0); // No complete message yet

    // Handle second fragment
    const messages2 = try connection.handleData(serialized2);
    defer {
        for (messages2) |*msg| {
            var mut_msg = msg;
            mut_msg.deinit();
        }
        testing.allocator.free(messages2);
    }

    try testing.expect(messages2.len == 1);
    try testing.expect(messages2[0].type == .text);
    try testing.expectEqualStrings(messages2[0].data, "Hello World");
}

test "WebSocket compression - permessage-deflate initialization" {
    var compression = CompressionContext.init(testing.allocator);
    defer compression.deinit();

    try testing.expect(!compression.enabled);
    try testing.expect(compression.server_max_window_bits == 15);
    try testing.expect(compression.client_max_window_bits == 15);
    try testing.expect(!compression.server_no_context_takeover);
    try testing.expect(!compression.client_no_context_takeover);
}

test "WebSocket compression - parameter parsing" {
    var compression = CompressionContext.init(testing.allocator);
    defer compression.deinit();

    try compression.parseExtensionParams("server_max_window_bits=12; client_no_context_takeover");

    try testing.expect(compression.server_max_window_bits == 12);
    try testing.expect(compression.client_max_window_bits == 15); // Default
    try testing.expect(!compression.server_no_context_takeover);
    try testing.expect(compression.client_no_context_takeover);
}

test "WebSocket compression - extension parameter generation" {
    var compression = CompressionContext.init(testing.allocator);
    defer compression.deinit();

    compression.server_max_window_bits = 12;
    compression.client_no_context_takeover = true;

    const params = try compression.generateExtensionParams(testing.allocator);
    defer testing.allocator.free(params);

    try testing.expect(std.mem.indexOf(u8, params, "permessage-deflate") != null);
    try testing.expect(std.mem.indexOf(u8, params, "server_max_window_bits=12") != null);
    try testing.expect(std.mem.indexOf(u8, params, "client_no_context_takeover") != null);
}

test "WebSocket compression - compress and decompress cycle" {
    var compression = CompressionContext.init(testing.allocator);
    defer compression.deinit();

    try compression.enable(15, 15, false, false);

    const original_data = "Hello, World! This is a test message that should compress well because it has repeating patterns and common words.";

    // Compress data
    const compressed = try compression.compress(original_data);
    defer testing.allocator.free(compressed);
    try testing.expect(compressed.len < original_data.len); // Should be smaller

    // Decompress data
    const decompressed = try compression.decompress(compressed);
    defer testing.allocator.free(decompressed);

    try testing.expectEqualStrings(original_data, decompressed);
}

test "WebSocket compression - compressed text frame creation" {
    var compression = CompressionContext.init(testing.allocator);
    defer compression.deinit();

    try compression.enable(15, 15, false, false);

    const original_data = "This is a test message for compression.";
    const frame = try Frame.compressedText(testing.allocator, original_data, false, &compression);
    defer testing.allocator.free(frame.payload);

    try testing.expect(frame.header.opcode == .text);
    try testing.expect(frame.header.fin == true);
    try testing.expect(frame.header.rsv1 == true); // Compression flag set
    try testing.expect(frame.header.masked == false);
    try testing.expect(frame.isCompressed());

    // Verify we can decompress the payload
    const decompressed = try frame.decompressPayload(&compression);
    defer testing.allocator.free(decompressed);
    try testing.expectEqualStrings(original_data, decompressed);
}

test "WebSocket compression - compressed binary frame creation" {
    var compression = CompressionContext.init(testing.allocator);
    defer compression.deinit();

    try compression.enable(15, 15, false, false);

    const original_data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 } ** 20; // Repeating pattern
    const frame = try Frame.compressedBinary(testing.allocator, &original_data, false, &compression);
    defer testing.allocator.free(frame.payload);

    try testing.expect(frame.header.opcode == .binary);
    try testing.expect(frame.header.rsv1 == true); // Compression flag set
    try testing.expect(frame.isCompressed());

    // Verify compression worked (payload should be smaller)
    try testing.expect(frame.payload.len < original_data.len);
}

test "WebSocket compression - frame decompression when not compressed" {
    var compression = CompressionContext.init(testing.allocator);
    defer compression.deinit();

    try compression.enable(15, 15, false, false);

    const original_data = "Uncompressed message";
    var frame = try Frame.text(testing.allocator, original_data, false);
    defer frame.deinit();

    try testing.expect(!frame.isCompressed()); // RSV1 should be false

    // Decompressing uncompressed frame should return original data
    const result = try frame.decompressPayload(&compression);
    defer testing.allocator.free(result);
    try testing.expectEqualStrings(original_data, result);
}

test "WebSocket compression - performance benchmark" {
    var compression = CompressionContext.init(testing.allocator);
    defer compression.deinit();

    try compression.enable(15, 15, false, false);

    // Large test data that should compress well
    const large_data = "The quick brown fox jumps over the lazy dog. " ** 100;

    const iterations = 1000;
    const start = std.time.nanoTimestamp();

    var total_original: usize = 0;
    var total_compressed: usize = 0;

    for (0..iterations) |_| {
        const compressed = try compression.compress(large_data);
        defer testing.allocator.free(compressed);
        total_original += large_data.len;
        total_compressed += compressed.len;

        // Verify decompression
        const decompressed = try compression.decompress(compressed);
        defer testing.allocator.free(decompressed);
        try testing.expectEqualStrings(large_data, decompressed);
    }

    const end = std.time.nanoTimestamp();
    const duration_ns = end - start;
    const compression_ratio = @as(f64, @floatFromInt(total_compressed)) / @as(f64, @floatFromInt(total_original));

    std.debug.print("\nWebSocket Compression Performance:\n", .{});
    std.debug.print("  Iterations: {}\n", .{iterations});
    std.debug.print("  Total time: {d:.2} ms\n", .{@as(f64, @floatFromInt(duration_ns)) / 1_000_000.0});
    std.debug.print("  Per operation: {d:.2} μs\n", .{@as(f64, @floatFromInt(duration_ns)) / @as(f64, @floatFromInt(iterations)) / 1000.0});
    std.debug.print("  Compression ratio: {d:.1}% ({} -> {} bytes avg)\n", .{ compression_ratio * 100.0, total_original / iterations, total_compressed / iterations });

    try testing.expect(compression_ratio < 0.5); // Should achieve >50% compression
}
