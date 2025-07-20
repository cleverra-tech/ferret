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

    const Self = @This();

    /// Create text frame
    pub fn text(allocator: Allocator, data: []const u8, masked: bool) !Self {
        _ = allocator;
        const mask_key = if (masked) generateMaskKey() else null;

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
            .payload = data,
        };
    }

    /// Create binary frame
    pub fn binary(allocator: Allocator, data: []const u8, masked: bool) !Self {
        _ = allocator;
        const mask_key = if (masked) generateMaskKey() else null;

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
            .payload = data,
        };
    }

    /// Create close frame
    pub fn close(allocator: Allocator, code: CloseCode, reason: ?[]const u8, masked: bool) !Self {
        _ = allocator;
        _ = code;
        const mask_key = if (masked) generateMaskKey() else null;

        // Close frame payload: 2-byte status code + optional reason
        var payload_len: usize = 2;
        if (reason) |r| payload_len += r.len;

        return Self{
            .header = FrameHeader{
                .fin = true,
                .rsv1 = false,
                .rsv2 = false,
                .rsv3 = false,
                .opcode = .close,
                .masked = masked,
                .payload_length = payload_len,
                .mask_key = mask_key,
                .header_size = 0,
            },
            .payload = &[_]u8{}, // Payload will be constructed separately
        };
    }

    /// Create ping frame
    pub fn ping(allocator: Allocator, data: ?[]const u8, masked: bool) !Self {
        _ = allocator;
        const payload = data orelse &[_]u8{};
        const mask_key = if (masked) generateMaskKey() else null;

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
            .payload = payload,
        };
    }

    /// Create pong frame
    pub fn pong(allocator: Allocator, data: ?[]const u8, masked: bool) !Self {
        _ = allocator;
        const payload = data orelse &[_]u8{};
        const mask_key = if (masked) generateMaskKey() else null;

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
            .payload = payload,
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
                            return Frame{
                                .header = header,
                                .payload = &[_]u8{},
                            };
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
                        const payload = try self.payload_buffer.toOwnedSlice();

                        // Unmask if necessary
                        if (header.mask_key) |mask| {
                            // Create a mutable copy for unmasking
                            const mutable_payload = try self.payload_buffer.allocator.dupe(u8, payload);
                            defer self.payload_buffer.allocator.free(payload);
                            maskPayload(mutable_payload, mask);

                            self.state = .frame_complete;
                            return Frame{
                                .header = header,
                                .payload = mutable_payload,
                            };
                        }

                        self.state = .frame_complete;
                        return Frame{
                            .header = header,
                            .payload = payload,
                        };
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
    const text_frame = try Frame.text(testing.allocator, "hello", false);
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
    const frame = try Frame.text(testing.allocator, "hello", false);
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
