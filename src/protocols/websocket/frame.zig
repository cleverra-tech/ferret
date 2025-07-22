//! WebSocket frame handling
//!
//! This module provides frame parsing, generation, and manipulation
//! functionality for WebSocket connections.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;

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
    no_status = 1005,
    abnormal_closure = 1006,
    invalid_frame_payload_data = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_server_error = 1011,
    tls_handshake = 1015,
    _,

    pub fn isValid(code: u16) bool {
        return switch (code) {
            1000...1003, 1007...1011 => true,
            3000...4999 => true, // Application-defined codes
            else => false,
        };
    }
};

/// WebSocket frame header
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

    /// Parse frame header from bytes
    pub fn parse(data: []const u8) !FrameHeader {
        if (data.len < 2) return error.IncompleteFrame;

        const first_byte = data[0];
        const second_byte = data[1];

        var header = FrameHeader{
            .fin = (first_byte & 0x80) != 0,
            .rsv1 = (first_byte & 0x40) != 0,
            .rsv2 = (first_byte & 0x20) != 0,
            .rsv3 = (first_byte & 0x10) != 0,
            .opcode = @enumFromInt(first_byte & 0x0F),
            .masked = (second_byte & 0x80) != 0,
            .payload_length = second_byte & 0x7F,
            .mask_key = null,
            .header_size = 2,
        };

        var offset: usize = 2;

        // Handle extended payload length
        if (header.payload_length == 126) {
            if (data.len < offset + 2) return error.IncompleteFrame;
            header.payload_length = mem.readInt(u16, data[offset .. offset + 2], .big);
            offset += 2;
            header.header_size += 2;
        } else if (header.payload_length == 127) {
            if (data.len < offset + 8) return error.IncompleteFrame;
            header.payload_length = mem.readInt(u64, data[offset .. offset + 8], .big);
            offset += 8;
            header.header_size += 8;
        }

        // Handle mask key
        if (header.masked) {
            if (data.len < offset + 4) return error.IncompleteFrame;
            header.mask_key = data[offset .. offset + 4][0..4].*;
            header.header_size += 4;
        }

        return header;
    }

    /// Serialize header to bytes
    pub fn serialize(self: FrameHeader, writer: anytype) !void {
        // First byte: FIN(1) + RSV(3) + Opcode(4)
        var first_byte: u8 = @intFromEnum(self.opcode);
        if (self.fin) first_byte |= 0x80;
        if (self.rsv1) first_byte |= 0x40;
        if (self.rsv2) first_byte |= 0x20;
        if (self.rsv3) first_byte |= 0x10;

        try writer.writeByte(first_byte);

        // Second byte: MASK(1) + Payload length(7)
        var second_byte: u8 = 0;
        if (self.masked) second_byte |= 0x80;

        if (self.payload_length <= 125) {
            second_byte |= @as(u8, @intCast(self.payload_length));
            try writer.writeByte(second_byte);
        } else if (self.payload_length <= 65535) {
            second_byte |= 126;
            try writer.writeByte(second_byte);
            try writer.writeInt(u16, @as(u16, @intCast(self.payload_length)), .big);
        } else {
            second_byte |= 127;
            try writer.writeByte(second_byte);
            try writer.writeInt(u64, self.payload_length, .big);
        }

        // Write mask key if present
        if (self.mask_key) |mask| {
            try writer.writeAll(&mask);
        }
    }
};

/// Generate a random mask key for client frames
pub fn generateMaskKey() [4]u8 {
    var key: [4]u8 = undefined;
    crypto.random.bytes(&key);
    return key;
}

/// Apply/remove XOR masking to payload data
pub fn applyMask(data: []u8, mask: [4]u8) void {
    for (data, 0..) |*byte, i| {
        byte.* ^= mask[i % 4];
    }
}

/// WebSocket frame
pub const Frame = struct {
    header: FrameHeader,
    payload: []const u8,
    owns_payload: bool, // Track if we own the payload memory
    allocator: ?Allocator, // Store allocator for deallocation

    /// Create a text frame
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
                .header_size = 0,
            },
            .payload = owned_payload,
            .owns_payload = true,
            .allocator = allocator,
        };
    }

    /// Create a binary frame
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

    /// Create a ping frame
    pub fn ping(allocator: Allocator, data: []const u8, masked: bool) !Self {
        const mask_key = if (masked) generateMaskKey() else null;

        // Always duplicate payload to ensure memory safety
        const owned_payload = try allocator.dupe(u8, data);

        return Self{
            .header = FrameHeader{
                .fin = true,
                .rsv1 = false,
                .rsv2 = false,
                .rsv3 = false,
                .opcode = .ping,
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

    /// Create a pong frame
    pub fn pong(allocator: Allocator, data: []const u8, masked: bool) !Self {
        const mask_key = if (masked) generateMaskKey() else null;

        // Always duplicate payload to ensure memory safety
        const owned_payload = try allocator.dupe(u8, data);

        return Self{
            .header = FrameHeader{
                .fin = true,
                .rsv1 = false,
                .rsv2 = false,
                .rsv3 = false,
                .opcode = .pong,
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

    /// Create a close frame
    pub fn close(allocator: Allocator, code: CloseCode, reason: []const u8, masked: bool) !Self {
        const mask_key = if (masked) generateMaskKey() else null;

        // Close frame payload: 2-byte status code + optional reason
        var payload = try allocator.alloc(u8, 2 + reason.len);
        mem.writeInt(u16, payload[0..2], @intFromEnum(code), .big);
        @memcpy(payload[2..], reason);

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

    /// Check if frame uses compression (RSV1 bit set)
    pub fn isCompressed(self: Self) bool {
        return self.header.rsv1;
    }

    /// Get close code from close frame payload
    pub fn getCloseCode(self: Self) ?CloseCode {
        if (self.header.opcode != .close or self.payload.len < 2) return null;
        const code = mem.readInt(u16, self.payload[0..2], .big);
        return @enumFromInt(code);
    }

    /// Get close reason from close frame payload
    pub fn getCloseReason(self: Self) []const u8 {
        if (self.header.opcode != .close or self.payload.len <= 2) return "";
        return self.payload[2..];
    }

    /// Serialize frame to bytes
    pub fn serialize(self: Self, allocator: Allocator, writer: anytype) !void {
        try self.header.serialize(writer);

        if (self.header.masked) {
            // Apply masking to payload
            if (self.header.mask_key) |mask| {
                var masked_payload = try allocator.alloc(u8, self.payload.len);
                defer allocator.free(masked_payload);

                @memcpy(masked_payload, self.payload);
                applyMask(masked_payload, mask);
                try writer.writeAll(masked_payload);
            }
        } else {
            try writer.writeAll(self.payload);
        }
    }

    const Self = @This();
};
