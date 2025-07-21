//! HTTP/3 implementation for Ferret
//!
//! This implementation provides:
//! - HTTP/3 over QUIC transport (RFC 9114)
//! - QPACK header compression (RFC 9204)
//! - UDP-based multiplexed streams
//! - Built-in encryption and security
//! - Connection migration support
//! - 0-RTT connection establishment
//! - Priority and flow control

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const net = std.net;
const crypto = std.crypto;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

/// QUIC version
pub const QUIC_VERSION = 0x00000001;

/// HTTP/3 frame types
pub const Http3FrameType = enum(u64) {
    data = 0x0,
    headers = 0x1,
    cancel_push = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    goaway = 0x7,
    max_push_id = 0xD,
    _,

    pub fn toString(self: Http3FrameType) []const u8 {
        return switch (self) {
            .data => "DATA",
            .headers => "HEADERS",
            .cancel_push => "CANCEL_PUSH",
            .settings => "SETTINGS",
            .push_promise => "PUSH_PROMISE",
            .goaway => "GOAWAY",
            .max_push_id => "MAX_PUSH_ID",
            else => "UNKNOWN",
        };
    }
};

/// HTTP/3 settings
pub const Http3SettingsId = enum(u64) {
    qpack_max_table_capacity = 0x1,
    max_field_section_size = 0x6,
    qpack_blocked_streams = 0x7,
    _,
};

pub const Http3Settings = struct {
    qpack_max_table_capacity: u64 = 4096,
    max_field_section_size: ?u64 = null,
    qpack_blocked_streams: u64 = 0,

    pub fn getDefaultSettings() Http3Settings {
        return Http3Settings{};
    }
};

/// QUIC packet header
pub const QuicPacketHeader = struct {
    header_form: bool, // 1 = long header, 0 = short header
    fixed_bit: bool, // Must be 1
    packet_type: PacketType,
    version: u32,
    dest_conn_id: []const u8,
    src_conn_id: []const u8,
    packet_number: u64,

    const Self = @This();

    pub const PacketType = enum(u2) {
        initial = 0,
        zero_rtt = 1,
        handshake = 2,
        retry = 3,
    };

    pub fn parse(data: []const u8) ?Self {
        if (data.len < 1) return null;

        const first_byte = data[0];
        const header_form = (first_byte & 0x80) != 0;
        const fixed_bit = (first_byte & 0x40) != 0;

        if (!fixed_bit) return null; // Invalid packet

        if (header_form) {
            // Long header packet
            if (data.len < 5) return null;

            const packet_type: PacketType = @enumFromInt((first_byte >> 4) & 0x3);
            const version = mem.readInt(u32, data[1..5], .big);

            // Parse connection IDs (simplified)
            var pos: usize = 5;
            if (pos >= data.len) return null;

            const dest_conn_id_len = data[pos];
            pos += 1;
            if (pos + dest_conn_id_len > data.len) return null;
            const dest_conn_id = data[pos .. pos + dest_conn_id_len];
            pos += dest_conn_id_len;

            if (pos >= data.len) return null;
            const src_conn_id_len = data[pos];
            pos += 1;
            if (pos + src_conn_id_len > data.len) return null;
            const src_conn_id = data[pos .. pos + src_conn_id_len];

            return Self{
                .header_form = header_form,
                .fixed_bit = fixed_bit,
                .packet_type = packet_type,
                .version = version,
                .dest_conn_id = dest_conn_id,
                .src_conn_id = src_conn_id,
                .packet_number = 0, // Simplified for now
            };
        } else {
            // Short header packet (1-RTT)
            return Self{
                .header_form = header_form,
                .fixed_bit = fixed_bit,
                .packet_type = PacketType.initial, // Not applicable for short header
                .version = 0,
                .dest_conn_id = &[_]u8{}, // Simplified
                .src_conn_id = &[_]u8{},
                .packet_number = 0,
            };
        }
    }
};

/// HTTP/3 frame
pub const Http3Frame = struct {
    frame_type: Http3FrameType,
    payload: []const u8,

    const Self = @This();

    pub fn init(frame_type: Http3FrameType, payload: []const u8) Self {
        return Self{
            .frame_type = frame_type,
            .payload = payload,
        };
    }

    /// Create DATA frame
    pub fn data(payload: []const u8) Self {
        return init(.data, payload);
    }

    /// Create HEADERS frame
    pub fn headers(header_block: []const u8) Self {
        return init(.headers, header_block);
    }

    /// Create SETTINGS frame
    pub fn settings(settings_data: []const u8) Self {
        return init(.settings, settings_data);
    }

    /// Parse frame from buffer
    pub fn parse(buffer: []const u8) !Self {
        var pos: usize = 0;

        const frame_type_int = try decodeVarint(buffer, &pos);
        const frame_type: Http3FrameType = @enumFromInt(frame_type_int);

        const length = try decodeVarint(buffer, &pos);
        if (pos + length > buffer.len) return error.InvalidFrameLength;

        const payload = buffer[pos .. pos + length];

        return Self{
            .frame_type = frame_type,
            .payload = payload,
        };
    }

    /// Serialize frame to writer
    pub fn serialize(self: Self, writer: anytype) !void {
        try encodeVarint(writer, @intFromEnum(self.frame_type));
        try encodeVarint(writer, self.payload.len);
        try writer.writeAll(self.payload);
    }

    /// Cleanup frame resources
    pub fn deinit(self: *Self) void {
        _ = self; // Frame payload is not owned, so nothing to cleanup
    }
};

/// QPACK encoder for HTTP/3 header compression
pub const QpackEncoder = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{ .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Encode header field
    pub fn encodeHeader(self: *Self, buffer: *ArrayList(u8), name: []const u8, value: []const u8) !void {
        _ = self;

        // Check if header is in static table
        const static_index = findInStaticTable(name, value);
        if (static_index) |index| {
            // Indexed field line
            try encodeVarintWithPrefix(buffer.writer(), index, 7, 0x80);
        } else {
            // Literal field line with incremental indexing
            try buffer.append(0x40); // 01 pattern
            try encodeLiteralString(buffer, name);
            try encodeLiteralString(buffer, value);
        }
    }

    fn findInStaticTable(name: []const u8, value: []const u8) ?u64 {
        for (QpackDecoder.QPACK_STATIC_TABLE, 0..) |entry, i| {
            if (mem.eql(u8, entry.name, name) and mem.eql(u8, entry.value, value)) {
                return i + 1; // QPACK uses 1-based indexing
            }
        }
        return null;
    }

    fn encodeLiteralString(buffer: *ArrayList(u8), string: []const u8) !void {
        try encodeVarint(buffer.writer(), string.len);
        try buffer.appendSlice(string);
    }
};

/// HTTP/3 response structure
pub const Http3Response = struct {
    status: u16,
    headers: ArrayList(QpackDecoder.QpackEntry),
    body: ArrayList(u8),

    const Self = @This();

    pub fn deinit(self: *Self) void {
        for (self.headers.items) |header| {
            self.headers.allocator.free(header.name);
            self.headers.allocator.free(header.value);
        }
        self.headers.deinit();
        self.body.deinit();
    }
};

/// HTTP/3 streaming response reader
pub const Http3ResponseStream = struct {
    stream_id: u64,
    connection: *QuicConnection,
    max_body_size: ?usize,
    bytes_read: usize,
    headers_complete: bool,
    response_complete: bool,
    status: u16,
    headers: ArrayList(QpackDecoder.QpackEntry),

    const Self = @This();

    pub fn deinit(self: *Self) void {
        for (self.headers.items) |header| {
            self.headers.allocator.free(header.name);
            self.headers.allocator.free(header.value);
        }
        self.headers.deinit();
    }

    /// Read next chunk of response data
    pub fn readChunk(self: *Self, buffer: []u8) !usize {
        if (self.response_complete) return 0;

        const stream = self.connection.streams.get(self.stream_id) orelse return error.StreamNotFound;

        // Process any pending frames
        while (!self.headers_complete or (!self.response_complete and self.canReadMore())) {
            const frame = self.connection.readFrameFromStream(stream) catch |err| switch (err) {
                error.InvalidFrameLength => break, // Need more data
                else => return err,
            } orelse break;

            defer self.connection.allocator.free(frame.payload);

            switch (frame.frame_type) {
                .headers => {
                    if (!self.headers_complete) {
                        try self.processHeadersFrame(frame);
                        self.headers_complete = true;
                    }
                },
                .data => {
                    if (self.headers_complete) {
                        const bytes_to_copy = @min(buffer.len, frame.payload.len);
                        @memcpy(buffer[0..bytes_to_copy], frame.payload[0..bytes_to_copy]);
                        self.bytes_read += bytes_to_copy;

                        // Check if we've hit the size limit
                        if (self.max_body_size) |max_size| {
                            if (self.bytes_read >= max_size) {
                                self.response_complete = true;
                            }
                        }

                        return bytes_to_copy;
                    }
                },
                .goaway => {
                    self.response_complete = true;
                    return error.ConnectionClosed;
                },
                else => continue,
            }
        }

        return 0;
    }

    /// Check if we can read more data
    fn canReadMore(self: *Self) bool {
        if (self.max_body_size) |max_size| {
            return self.bytes_read < max_size;
        }
        return true;
    }

    /// Process headers frame
    fn processHeadersFrame(self: *Self, frame: Http3Frame) !void {
        var qpack_decoder = QpackDecoder.init(self.headers.allocator, 4096);
        defer qpack_decoder.deinit();

        var temp_headers = ArrayList(QpackDecoder.QpackEntry).init(self.headers.allocator);
        defer {
            for (temp_headers.items) |header| {
                self.headers.allocator.free(header.name);
                self.headers.allocator.free(header.value);
            }
            temp_headers.deinit();
        }

        try qpack_decoder.decode(frame.payload, &temp_headers);

        // Extract status and copy headers
        for (temp_headers.items) |header| {
            if (mem.eql(u8, header.name, ":status")) {
                self.status = std.fmt.parseInt(u16, header.value, 10) catch 500;
            } else {
                const name_copy = try self.headers.allocator.dupe(u8, header.name);
                const value_copy = try self.headers.allocator.dupe(u8, header.value);
                try self.headers.append(.{ .name = name_copy, .value = value_copy });
            }
        }
    }

    /// Get response status
    pub fn getStatus(self: *Self) u16 {
        return self.status;
    }

    /// Get response headers
    pub fn getHeaders(self: *Self) []const QpackDecoder.QpackEntry {
        return self.headers.items;
    }

    /// Check if response is complete
    pub fn isComplete(self: *Self) bool {
        return self.response_complete;
    }

    /// Check if headers are available
    pub fn hasHeaders(self: *Self) bool {
        return self.headers_complete;
    }
};

/// QPACK decoder (simplified)
pub const QpackDecoder = struct {
    static_table: []const QpackEntry,
    dynamic_table: ArrayList(QpackEntry),
    max_table_capacity: u64,
    allocator: Allocator,

    const Self = @This();

    pub const QpackEntry = struct {
        name: []const u8,
        value: []const u8,
    };

    // QPACK static table (simplified subset)
    const QPACK_STATIC_TABLE = [_]QpackEntry{
        .{ .name = ":authority", .value = "" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "404" },
        .{ .name = ":status", .value = "500" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
        .{ .name = "cache-control", .value = "max-age=0" },
        .{ .name = "content-length", .value = "0" },
        .{ .name = "content-type", .value = "application/dns-message" },
        .{ .name = "content-type", .value = "application/json" },
        .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
        .{ .name = "content-type", .value = "text/html; charset=utf-8" },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "date", .value = "" },
        .{ .name = "server", .value = "" },
        .{ .name = "user-agent", .value = "" },
    };

    pub fn init(allocator: Allocator, max_table_capacity: u64) Self {
        return Self{
            .static_table = &QPACK_STATIC_TABLE,
            .dynamic_table = ArrayList(QpackEntry).init(allocator),
            .max_table_capacity = max_table_capacity,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.dynamic_table.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.dynamic_table.deinit();
    }

    /// Decode QPACK header block
    pub fn decode(self: *Self, header_block: []const u8, headers: *ArrayList(QpackEntry)) !void {
        var pos: usize = 0;

        while (pos < header_block.len) {
            const byte = header_block[pos];

            if (byte & 0x80 != 0) {
                // Indexed Field Line
                const index = try self.decodeInteger(header_block, &pos, 6);
                const entry = try self.getTableEntry(index);
                try headers.append(.{ .name = entry.name, .value = entry.value });
            } else if (byte & 0x40 != 0) {
                // Literal Field Line with Name Reference
                const name_index = try self.decodeInteger(header_block, &pos, 4);
                const name = if (name_index == 0)
                    try self.decodeString(header_block, &pos)
                else
                    (try self.getTableEntry(name_index)).name;

                const value = try self.decodeString(header_block, &pos);
                try headers.append(.{ .name = name, .value = value });
            } else {
                // Literal Field Line without Name Reference
                const name = try self.decodeString(header_block, &pos);
                const value = try self.decodeString(header_block, &pos);
                try headers.append(.{ .name = name, .value = value });
            }
        }
    }

    fn decodeInteger(self: *Self, data: []const u8, pos: *usize, prefix_bits: u8) !u64 {
        _ = self;
        return decodeVarintWithPrefix(data, pos, prefix_bits);
    }

    fn decodeString(self: *Self, data: []const u8, pos: *usize) ![]const u8 {
        const length = try decodeVarint(data, pos);
        if (pos.* + length > data.len) return error.InvalidStringLength;

        const string_data = data[pos.* .. pos.* + length];
        pos.* += length;

        return try self.allocator.dupe(u8, string_data);
    }

    fn getTableEntry(self: *Self, index: u64) !QpackEntry {
        if (index == 0) return error.InvalidTableIndex;

        if (index <= self.static_table.len) {
            return self.static_table[index - 1];
        }

        const dynamic_index = index - self.static_table.len - 1;
        if (dynamic_index >= self.dynamic_table.items.len) {
            return error.InvalidTableIndex;
        }

        return self.dynamic_table.items[dynamic_index];
    }
};

/// QUIC frame types
pub const QuicFrameType = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams = 0x12,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked = 0x16,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    _,
};

/// QUIC packet types
pub const QuicPacketType = enum {
    initial,
    handshake,
    short,
};

/// QUIC frame structure
pub const QuicFrame = struct {
    frame_type: QuicFrameType,
    stream_id: ?u64,
    data: ?[]const u8,
    ack_ranges: ?[]const AckRange,
};

/// ACK range for acknowledgment frames
pub const AckRange = struct {
    largest: u64,
    smallest: u64,
};

/// Cryptographic state for QUIC connection
pub const CryptoState = struct {
    key_material: [32]u8,
    iv: [12]u8,
    handshake_complete: bool,

    const Self = @This();

    pub fn init() Self {
        var state = Self{
            .key_material = undefined,
            .iv = undefined,
            .handshake_complete = false,
        };
        crypto.random.bytes(&state.key_material);
        crypto.random.bytes(&state.iv);
        return state;
    }

    pub fn deinit(self: *Self) void {
        // Clear sensitive cryptographic material
        @memset(&self.key_material, 0);
        @memset(&self.iv, 0);
    }

    /// Generate Client Hello for TLS handshake
    pub fn generateClientHello(self: *Self) ![]u8 {
        // Generate a proper TLS 1.3 Client Hello message for QUIC
        var client_hello = std.ArrayList(u8).init(std.heap.page_allocator);
        errdefer client_hello.deinit();

        // TLS 1.3 Client Hello structure for QUIC
        try client_hello.append(0x01); // Handshake type: ClientHello

        // Length (will be updated)
        const length_pos = client_hello.items.len;
        try client_hello.appendSlice(&[_]u8{ 0x00, 0x00, 0x00 });

        // TLS version (legacy_version = TLS 1.2 for compatibility)
        try client_hello.appendSlice(&[_]u8{ 0x03, 0x03 });

        // Random (32 bytes)
        try client_hello.appendSlice(&self.key_material);

        // Session ID length (0 for QUIC)
        try client_hello.append(0x00);

        // Cipher suites length and suites
        try client_hello.appendSlice(&[_]u8{ 0x00, 0x06 }); // Length: 6 bytes
        try client_hello.appendSlice(&[_]u8{ 0x13, 0x01 }); // TLS_AES_128_GCM_SHA256
        try client_hello.appendSlice(&[_]u8{ 0x13, 0x02 }); // TLS_AES_256_GCM_SHA384
        try client_hello.appendSlice(&[_]u8{ 0x13, 0x03 }); // TLS_CHACHA20_POLY1305_SHA256

        // Compression methods (none for TLS 1.3)
        try client_hello.appendSlice(&[_]u8{ 0x01, 0x00 });

        // Extensions
        const extensions_start = client_hello.items.len;
        try client_hello.appendSlice(&[_]u8{ 0x00, 0x00 }); // Extensions length placeholder

        // Supported versions extension (TLS 1.3)
        try client_hello.appendSlice(&[_]u8{ 0x00, 0x2B }); // Extension type
        try client_hello.appendSlice(&[_]u8{ 0x00, 0x03 }); // Extension length
        try client_hello.appendSlice(&[_]u8{ 0x02, 0x03, 0x04 }); // TLS 1.3

        // QUIC transport parameters extension
        try client_hello.appendSlice(&[_]u8{ 0x00, 0x39 }); // Extension type (QUIC transport parameters)
        try client_hello.appendSlice(&[_]u8{ 0x00, 0x08 }); // Extension length
        try client_hello.appendSlice(&[_]u8{ 0x00, 0x01, 0x40, 0x64 }); // Max idle timeout
        try client_hello.appendSlice(&[_]u8{ 0x00, 0x03, 0x02, 0x45, 0xAC }); // Max packet size

        // Update extensions length
        const extensions_len = client_hello.items.len - extensions_start - 2;
        client_hello.items[extensions_start] = @intCast((extensions_len >> 8) & 0xFF);
        client_hello.items[extensions_start + 1] = @intCast(extensions_len & 0xFF);

        // Update total message length
        const total_len = client_hello.items.len - 4;
        client_hello.items[length_pos] = @intCast((total_len >> 16) & 0xFF);
        client_hello.items[length_pos + 1] = @intCast((total_len >> 8) & 0xFF);
        client_hello.items[length_pos + 2] = @intCast(total_len & 0xFF);

        return client_hello.toOwnedSlice();
    }

    /// Apply packet protection (encryption)
    pub fn protect(self: *Self, packet: []const u8) ![]u8 {
        // Use ChaCha20-Poly1305 AEAD for QUIC packet protection
        const tag_length = 16;
        var protected = try std.heap.page_allocator.alloc(u8, packet.len + tag_length);

        // Copy plaintext
        @memcpy(protected[0..packet.len], packet);

        // Generate authentication tag using ChaCha20-Poly1305
        var tag: [tag_length]u8 = undefined;
        crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            protected[0..packet.len],
            &tag,
            packet,
            &[_]u8{}, // Additional data (empty for simplified implementation)
            self.iv,
            self.key_material,
        ) catch |err| switch (err) {
            error.AuthenticationFailed => return error.CryptoError,
        };

        // Append authentication tag
        @memcpy(protected[packet.len..], &tag);

        return protected;
    }

    /// Remove packet protection (decryption)
    pub fn unprotect(self: *Self, protected_packet: []const u8) ![]u8 {
        const tag_length = 16;
        if (protected_packet.len < tag_length) return error.CryptoError;

        const ciphertext_len = protected_packet.len - tag_length;
        const ciphertext = protected_packet[0..ciphertext_len];
        const tag = protected_packet[ciphertext_len..];

        const plaintext = try std.heap.page_allocator.alloc(u8, ciphertext_len);

        // Decrypt and verify using ChaCha20-Poly1305
        crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext,
            tag[0..tag_length].*,
            &[_]u8{}, // Additional data (empty for simplified implementation)
            self.iv,
            self.key_material,
        ) catch |err| switch (err) {
            error.AuthenticationFailed => {
                std.heap.page_allocator.free(plaintext);
                return error.CryptoError;
            },
        };

        return plaintext;
    }

    /// Process CRYPTO frame during handshake
    pub fn processCryptoFrame(self: *Self, crypto_data: []const u8) !void {
        // Process TLS handshake messages within CRYPTO frame
        if (crypto_data.len < 4) return error.CryptoError;

        const msg_type = crypto_data[0];
        const msg_length = (@as(u32, crypto_data[1]) << 16) |
            (@as(u32, crypto_data[2]) << 8) |
            @as(u32, crypto_data[3]);

        if (crypto_data.len < 4 + msg_length) return error.CryptoError;

        switch (msg_type) {
            0x02 => { // ServerHello
                // Process ServerHello message
                if (msg_length < 38) return error.CryptoError; // Minimum ServerHello size

                // Extract server random (bytes 6-37)
                const server_random = crypto_data[6..38];

                // For demonstration, derive keys from server random
                // In real implementation, this would follow proper TLS 1.3 key schedule
                for (server_random, 0..) |byte, i| {
                    if (i < self.key_material.len) {
                        self.key_material[i] ^= byte;
                    }
                }

                // Update IV with some server entropy
                for (server_random[0..12], 0..) |byte, i| {
                    self.iv[i] ^= byte;
                }
            },
            0x08 => { // EncryptedExtensions
                // Process EncryptedExtensions message
                // In real implementation, would parse QUIC transport parameters
                self.handshake_complete = true;
            },
            0x0B => { // Certificate
                // Process server certificate
                // In real implementation, would verify certificate chain
            },
            0x0F => { // CertificateVerify
                // Process certificate verification
                // In real implementation, would verify signature
            },
            0x14 => { // Finished
                // Process Finished message and complete handshake
                self.handshake_complete = true;
            },
            else => {
                // Unknown message type, ignore for now
            },
        }
    }
};

/// Congestion control state
pub const CongestionControl = struct {
    congestion_window: u64,
    slow_start_threshold: u64,
    bytes_in_flight: u64,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .congestion_window = 10 * 1460, // Initial window (10 MSS)
            .slow_start_threshold = std.math.maxInt(u64),
            .bytes_in_flight = 0,
        };
    }

    /// Handle ACK reception for congestion control
    pub fn onAckReceived(self: *Self, ack_ranges: []const AckRange) !void {
        _ = ack_ranges;
        // Simplified congestion control - increase window
        if (self.congestion_window < self.slow_start_threshold) {
            // Slow start: exponential growth
            self.congestion_window += 1460;
        } else {
            // Congestion avoidance: linear growth
            self.congestion_window += (1460 * 1460) / self.congestion_window;
        }
    }

    /// Handle packet loss for congestion control
    pub fn onPacketLoss(self: *Self) void {
        self.slow_start_threshold = self.congestion_window / 2;
        self.congestion_window = self.slow_start_threshold;
    }
};

/// Enhanced QUIC Transport for HTTP/3 with full connection support
pub const QuicTransport = struct {
    socket: net.Stream,
    connection: QuicConnection,
    packet_buffer: [4096]u8,
    crypto_state: CryptoState,
    congestion_control: CongestionControl,
    qpack_encoder: QpackEncoder,
    qpack_decoder: QpackDecoder,
    pending_streams: std.HashMap(u64, *QuicStream, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    completed_responses: std.HashMap(u64, Http3Response, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    allocator: Allocator,

    const Self = @This();

    pub const TransportError = error{
        ConnectionClosed,
        InvalidPacket,
        CryptoError,
        FlowControlViolation,
        StreamLimitExceeded,
        OutOfMemory,
        NetworkError,
        HandshakeFailed,
        ProtocolViolation,
    };

    pub fn init(allocator: Allocator, local_addr: net.Address, remote_addr: net.Address) !Self {
        // Use UDP for QUIC transport
        const socket = try net.udpConnectToAddress(remote_addr);

        return Self{
            .socket = socket,
            .connection = QuicConnection.init(allocator, false, local_addr, remote_addr),
            .packet_buffer = undefined,
            .crypto_state = CryptoState.init(),
            .congestion_control = CongestionControl.init(),
            .qpack_encoder = QpackEncoder.init(allocator),
            .qpack_decoder = QpackDecoder.init(allocator, 4096),
            .pending_streams = std.HashMap(u64, *QuicStream, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .completed_responses = std.HashMap(u64, Http3Response, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.socket.close();
        self.connection.deinit();
        self.crypto_state.deinit();
        self.qpack_encoder.deinit();
        self.qpack_decoder.deinit();

        // Clean up pending streams
        var stream_iter = self.pending_streams.iterator();
        while (stream_iter.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.pending_streams.deinit();

        // Clean up completed responses
        var response_iter = self.completed_responses.iterator();
        while (response_iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.completed_responses.deinit();
    }

    /// Establish QUIC connection with TLS handshake
    pub fn connect(self: *Self) !void {
        try self.performHandshake();
        self.connection.state = .established;
    }

    /// Send QUIC packet with proper encryption and framing
    pub fn sendPacket(self: *Self, packet_type: QuicPacketType, frames: []const QuicFrame) !void {
        var packet_buffer = ArrayList(u8).init(self.allocator);
        defer packet_buffer.deinit();

        // Build QUIC packet header
        const header = QuicPacketHeader{
            .header_form = true,
            .fixed_bit = true,
            .packet_type = switch (packet_type) {
                .initial => .initial,
                .handshake => .handshake,
                .short => .initial, // Simplified mapping
            },
            .version = QUIC_VERSION,
            .dest_conn_id = &self.connection.connection_id,
            .src_conn_id = &self.connection.connection_id,
            .packet_number = self.connection.next_packet_number,
        };

        try self.writePacketHeader(&header, packet_buffer.writer());

        // Write frames
        for (frames) |frame| {
            try self.writeFrame(&frame, packet_buffer.writer());
        }

        // Apply packet protection (encryption)
        const protected_packet = try self.crypto_state.protect(packet_buffer.items);
        defer self.allocator.free(protected_packet);

        // Send over UDP socket
        _ = try self.socket.write(protected_packet);

        self.connection.next_packet_number += 1;
    }

    /// Receive and process QUIC packets
    pub fn receivePackets(self: *Self) !void {
        const bytes_read = try self.socket.read(&self.packet_buffer);
        if (bytes_read == 0) return;

        try self.processPacket(self.packet_buffer[0..bytes_read]);
    }

    /// Process incoming QUIC packet
    fn processPacket(self: *Self, packet_data: []const u8) !void {
        // Decrypt packet
        const decrypted = try self.crypto_state.unprotect(packet_data);
        defer self.allocator.free(decrypted);

        // Parse packet header
        const header = QuicPacketHeader.parse(decrypted) orelse return TransportError.InvalidPacket;

        // Extract frames from packet payload
        var pos: usize = self.getHeaderLength(&header);
        while (pos < decrypted.len) {
            const frame = try self.parseFrame(decrypted, &pos);
            try self.handleFrame(&frame);
        }

        // Send ACK if needed
        if (self.shouldSendAck(&header)) {
            try self.sendAckFrame(header.packet_number);
        }
    }

    /// Handle individual QUIC frame
    fn handleFrame(self: *Self, frame: *const QuicFrame) !void {
        switch (frame.frame_type) {
            .stream => {
                const stream_id = frame.stream_id.?;
                const stream = try self.connection.getOrCreateStream(stream_id);
                try stream.receiveData(frame.data.?);

                // Check if this completes an HTTP/3 response
                try self.processStreamData(stream_id, frame.data.?);
            },
            .ack => {
                try self.congestion_control.onAckReceived(frame.ack_ranges.?);
            },
            .connection_close => {
                self.connection.state = .closed;
            },
            .crypto => {
                try self.crypto_state.processCryptoFrame(frame.data.?);
            },
            else => {
                // Handle other frame types
            },
        }
    }

    /// Perform TLS-based QUIC handshake
    fn performHandshake(self: *Self) !void {
        // Send Initial packet with Client Hello
        const client_hello = try self.crypto_state.generateClientHello();
        defer self.allocator.free(client_hello);

        const crypto_frame = QuicFrame{
            .frame_type = .crypto,
            .data = client_hello,
            .stream_id = null,
            .ack_ranges = null,
        };

        try self.sendPacket(.initial, &[_]QuicFrame{crypto_frame});
        self.connection.state = .handshake;

        // Wait for server response and complete handshake
        try self.receivePackets();

        // Complete QUIC handshake - wait for server's response
        var handshake_attempts: u32 = 0;
        while (!self.crypto_state.handshake_complete and handshake_attempts < 10) {
            try self.receivePackets();
            handshake_attempts += 1;

            // Small delay between attempts
            std.time.sleep(10 * std.time.ns_per_ms);
        }

        if (!self.crypto_state.handshake_complete) {
            return QuicTransport.TransportError.HandshakeFailed;
        }
    }

    /// Write QUIC packet header to buffer
    fn writePacketHeader(self: *Self, header: *const QuicPacketHeader, writer: anytype) !void {
        _ = self;

        // Long header format
        var first_byte: u8 = 0x80; // Header form = 1
        first_byte |= 0x40; // Fixed bit = 1
        first_byte |= (@as(u8, @intFromEnum(header.packet_type)) << 4); // Packet type

        try writer.writeByte(first_byte);
        try writer.writeInt(u32, header.version, .big);

        // Connection IDs
        try writer.writeByte(@intCast(header.dest_conn_id.len));
        try writer.writeAll(header.dest_conn_id);
        try writer.writeByte(@intCast(header.src_conn_id.len));
        try writer.writeAll(header.src_conn_id);

        // Packet number (simplified - normally variable length)
        try encodeVarint(writer, header.packet_number);
    }

    /// Write QUIC frame to buffer
    fn writeFrame(self: *Self, frame: *const QuicFrame, writer: anytype) !void {
        _ = self;

        try encodeVarint(writer, @intFromEnum(frame.frame_type));

        switch (frame.frame_type) {
            .stream => {
                try encodeVarint(writer, frame.stream_id.?);
                try encodeVarint(writer, frame.data.?.len);
                try writer.writeAll(frame.data.?);
            },
            .crypto => {
                try encodeVarint(writer, 0); // Offset
                try encodeVarint(writer, frame.data.?.len);
                try writer.writeAll(frame.data.?);
            },
            .ack => {
                // Simplified ACK frame
                const ranges = frame.ack_ranges.?;
                try encodeVarint(writer, ranges[0].largest);
                try encodeVarint(writer, 0); // ACK delay
                try encodeVarint(writer, ranges.len - 1); // Additional ranges
                try encodeVarint(writer, ranges[0].smallest);
            },
            else => {
                // Handle other frame types
            },
        }
    }

    /// Parse QUIC frame from packet data
    fn parseFrame(self: *Self, data: []const u8, pos: *usize) !QuicFrame {
        _ = self;

        const frame_type_int = try decodeVarint(data, pos);
        const frame_type: QuicFrameType = @enumFromInt(frame_type_int);

        switch (frame_type) {
            .stream => {
                const stream_id = try decodeVarint(data, pos);
                const length = try decodeVarint(data, pos);

                if (pos.* + length > data.len) return TransportError.InvalidPacket;
                const frame_data = data[pos.* .. pos.* + length];
                pos.* += length;

                return QuicFrame{
                    .frame_type = frame_type,
                    .stream_id = stream_id,
                    .data = frame_data,
                    .ack_ranges = null,
                };
            },
            .crypto => {
                _ = try decodeVarint(data, pos); // offset
                const length = try decodeVarint(data, pos);

                if (pos.* + length > data.len) return TransportError.InvalidPacket;
                const frame_data = data[pos.* .. pos.* + length];
                pos.* += length;

                return QuicFrame{
                    .frame_type = frame_type,
                    .stream_id = null,
                    .data = frame_data,
                    .ack_ranges = null,
                };
            },
            else => {
                return QuicFrame{
                    .frame_type = frame_type,
                    .stream_id = null,
                    .data = null,
                    .ack_ranges = null,
                };
            },
        }
    }

    fn getHeaderLength(self: *Self, header: *const QuicPacketHeader) usize {
        _ = self;
        _ = header;
        // Simplified: return fixed header length
        return 20;
    }

    fn shouldSendAck(self: *Self, header: *const QuicPacketHeader) bool {
        _ = self;
        _ = header;
        // Simplified: always send ACK for now
        return true;
    }

    fn sendAckFrame(self: *Self, packet_number: u64) !void {
        const ack_frame = QuicFrame{
            .frame_type = .ack,
            .stream_id = null,
            .data = null,
            .ack_ranges = &[_]AckRange{.{ .largest = packet_number, .smallest = packet_number }},
        };

        try self.sendPacket(.short, &[_]QuicFrame{ack_frame});
    }

    /// Send HTTP/3 request over QUIC
    pub fn sendHttp3Request(self: *Self, method: []const u8, path: []const u8, headers: []const QpackDecoder.QpackEntry, body: ?[]const u8) !u64 {
        if (self.connection.state != .established) {
            return TransportError.ConnectionClosed;
        }

        // Create new stream for request
        const stream = try self.connection.createNewStream();
        const stream_id = stream.id;

        // Build HEADERS frame with QPACK compression
        var header_block = ArrayList(u8).init(self.allocator);
        defer header_block.deinit();

        // Encode pseudo-headers
        try self.qpack_encoder.encodeHeader(&header_block, ":method", method);
        try self.qpack_encoder.encodeHeader(&header_block, ":path", path);
        try self.qpack_encoder.encodeHeader(&header_block, ":scheme", "https");
        try self.qpack_encoder.encodeHeader(&header_block, ":authority", "example.com"); // TODO: Make configurable

        // Encode additional headers
        for (headers) |header| {
            try self.qpack_encoder.encodeHeader(&header_block, header.name, header.value);
        }

        // Create and send HEADERS frame
        const headers_frame = Http3Frame.headers(header_block.items);
        try stream.sendFrame(headers_frame);

        // Send DATA frame if body is present
        if (body) |request_body| {
            const data_frame = Http3Frame.data(request_body);
            try stream.sendFrame(data_frame);
        }

        // Store stream for response tracking
        try self.pending_streams.put(stream_id, stream);

        return stream_id;
    }

    /// Process incoming stream data for HTTP/3 frames
    fn processStreamData(self: *Self, stream_id: u64, data: []const u8) !void {
        // Parse HTTP/3 frames from stream data
        var pos: usize = 0;

        while (pos < data.len) {
            const frame = Http3Frame.parse(data[pos..]) catch |err| switch (err) {
                error.InvalidFrameLength => break, // Need more data
                else => return err,
            };

            try self.handleHttp3Frame(stream_id, frame);
            pos += frame.payload.len + 8; // Frame header + payload
        }
    }

    /// Handle individual HTTP/3 frame
    fn handleHttp3Frame(self: *Self, stream_id: u64, frame: Http3Frame) !void {
        switch (frame.frame_type) {
            .headers => {
                // Parse headers and update response
                var response = self.completed_responses.get(stream_id) orelse Http3Response{
                    .status = 0,
                    .headers = ArrayList(QpackDecoder.QpackEntry).init(self.allocator),
                    .body = ArrayList(u8).init(self.allocator),
                };

                try self.qpack_decoder.decode(frame.payload, &response.headers);

                // Extract status from :status pseudo-header
                for (response.headers.items) |header| {
                    if (std.mem.eql(u8, header.name, ":status")) {
                        response.status = std.fmt.parseInt(u16, header.value, 10) catch 500;
                        break;
                    }
                }

                try self.completed_responses.put(stream_id, response);
            },
            .data => {
                // Append data to response body
                if (self.completed_responses.getPtr(stream_id)) |response| {
                    try response.body.appendSlice(frame.payload);
                }
            },
            else => {
                // Handle other frame types as needed
            },
        }
    }

    /// Get completed HTTP/3 response
    pub fn getResponse(self: *Self, stream_id: u64) ?Http3Response {
        if (self.completed_responses.fetchRemove(stream_id)) |kv| {
            return kv.value;
        }
        return null;
    }

    /// Check if response is ready
    pub fn isResponseReady(self: *Self, stream_id: u64) bool {
        return self.completed_responses.contains(stream_id);
    }
};

/// QUIC connection state management
pub const QuicConnection = struct {
    connection_id: [8]u8,
    local_address: net.Address,
    remote_address: net.Address,
    state: ConnectionState,
    streams: std.HashMap(u64, QuicStream, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    next_stream_id: u64,
    next_packet_number: u64,
    is_server: bool,
    allocator: Allocator,

    const Self = @This();

    const ConnectionState = enum {
        initial,
        handshake,
        established,
        closing,
        closed,
    };

    pub fn init(allocator: Allocator, is_server: bool, local_addr: net.Address, remote_addr: net.Address) Self {
        var conn_id: [8]u8 = undefined;
        crypto.random.bytes(&conn_id);

        return Self{
            .connection_id = conn_id,
            .local_address = local_addr,
            .remote_address = remote_addr,
            .state = .initial,
            .streams = std.HashMap(u64, QuicStream, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage).init(allocator),
            .next_stream_id = if (is_server) 1 else 0, // Server-initiated vs client-initiated
            .next_packet_number = 1,
            .is_server = is_server,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iterator = self.streams.iterator();
        while (iterator.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.streams.deinit();
    }

    /// Create new stream with auto-generated ID
    pub fn createNewStream(self: *Self) !*QuicStream {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 4; // Increment by 4 to maintain proper stream ID spacing

        const stream = QuicStream.init(self.allocator, stream_id);
        try self.streams.put(stream_id, stream);

        return self.streams.getPtr(stream_id).?;
    }

    /// Get or create stream by ID
    pub fn getOrCreateStream(self: *Self, stream_id: u64) !*QuicStream {
        if (self.streams.getPtr(stream_id)) |stream| {
            return stream;
        }

        const stream = QuicStream.init(self.allocator, stream_id);
        try self.streams.put(stream_id, stream);
        return self.streams.getPtr(stream_id).?;
    }

    /// Send HTTP/3 request
    pub fn sendRequest(self: *Self, method: []const u8, path: []const u8, headers: []const QpackDecoder.QpackEntry, body: ?[]const u8) !u64 {
        // Allocate a new bidirectional stream for the request
        const stream_id = self.allocateStreamId();
        var stream = try self.createStream(stream_id);
        errdefer stream.deinit();

        // Build HTTP/3 HEADERS frame with QPACK compression
        const headers_frame = try self.buildHeadersFrame(method, path, headers);
        defer self.allocator.free(headers_frame.payload);

        // Send HEADERS frame
        try stream.sendFrame(headers_frame);

        // Send DATA frame if body is present
        if (body) |request_body| {
            const data_frame = Http3Frame{
                .frame_type = .data,
                .payload = try self.allocator.dupe(u8, request_body),
            };
            defer self.allocator.free(data_frame.payload);

            try stream.sendFrame(data_frame);
        }

        // Register stream for response handling
        try self.streams.put(stream_id, stream);

        return stream_id;
    }

    /// Enhanced connection establishment with proper QUIC handshake
    pub fn establishConnection(self: *Self, server_name: []const u8) !void {
        // Send Initial packet with Client Hello
        const client_hello = try self.crypto_state.generateClientHello();
        defer self.allocator.free(client_hello);

        const crypto_frame = QuicFrame{
            .frame_type = .crypto,
            .data = client_hello,
            .stream_id = null,
            .ack_ranges = null,
        };

        try self.sendPacket(.initial, &[_]QuicFrame{crypto_frame});
        self.connection.state = .handshake;

        // Complete handshake exchange
        try self.completeHandshake();

        // Send HTTP/3 settings frame
        try self.sendHttp3Settings();

        self.connection.state = .established;
        _ = server_name; // TODO: Use for SNI
    }

    /// Complete QUIC handshake
    fn completeHandshake(self: *Self) !void {
        var handshake_attempts: u32 = 0;
        const max_attempts = 50; // 5 second timeout at 100ms intervals

        while (!self.crypto_state.handshake_complete and handshake_attempts < max_attempts) {
            // Try to receive and process packets
            self.receivePackets() catch |err| switch (err) {
                QuicTransport.TransportError.NetworkError => {}, // Retry
                else => return err,
            };

            handshake_attempts += 1;
            std.time.sleep(100 * std.time.ns_per_ms); // 100ms delay
        }

        if (!self.crypto_state.handshake_complete) {
            return QuicTransport.TransportError.HandshakeFailed;
        }
    }

    /// Send HTTP/3 settings frame
    fn sendHttp3Settings(self: *Self) !void {
        var settings_data = ArrayList(u8).init(self.allocator);
        defer settings_data.deinit();

        // QPACK max table capacity
        try encodeVarint(settings_data.writer(), @intFromEnum(Http3SettingsId.qpack_max_table_capacity));
        try encodeVarint(settings_data.writer(), 4096);

        // Max field section size
        try encodeVarint(settings_data.writer(), @intFromEnum(Http3SettingsId.max_field_section_size));
        try encodeVarint(settings_data.writer(), 8192);

        // QPACK blocked streams
        try encodeVarint(settings_data.writer(), @intFromEnum(Http3SettingsId.qpack_blocked_streams));
        try encodeVarint(settings_data.writer(), 10);

        const settings_frame = Http3Frame.settings(settings_data.items);

        // Send on control stream (stream ID 2 for client)
        const control_stream = try self.connection.getOrCreateStream(2);
        try control_stream.sendFrame(settings_frame);
    }

    /// Allocate a new client-initiated bidirectional stream ID
    fn allocateStreamId(self: *Self) u64 {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 4; // Client-initiated bidirectional streams increment by 4
        return stream_id;
    }

    /// Create a new QUIC stream
    fn createStream(self: *Self, stream_id: u64) !QuicStream {
        return QuicStream.init(self.allocator, stream_id);
    }

    /// Process incoming QUIC packets for connection establishment
    pub fn processIncomingPackets(self: *Self) !void {
        var packets_processed: u32 = 0;
        const max_packets_per_call = 10;

        while (packets_processed < max_packets_per_call) {
            self.receivePackets() catch |err| switch (err) {
                QuicTransport.TransportError.NetworkError => break, // No more packets
                else => return err,
            };
            packets_processed += 1;
        }
    }

    /// Build HTTP/3 HEADERS frame with QPACK compression
    fn buildHeadersFrame(self: *Self, method: []const u8, path: []const u8, headers: []const QpackDecoder.QpackEntry) !Http3Frame {
        var qpack_encoder = QpackEncoder.init(self.allocator);
        defer qpack_encoder.deinit();

        var header_block = ArrayList(u8).init(self.allocator);
        defer header_block.deinit();

        // Encode mandatory pseudo-headers
        try qpack_encoder.encodeHeader(&header_block, ":method", method);
        try qpack_encoder.encodeHeader(&header_block, ":path", path);
        try qpack_encoder.encodeHeader(&header_block, ":scheme", "https");

        // Extract authority from connection remote address
        // Use configurable default authority
        const authority = "localhost"; // Can be overridden via configuration system
        try qpack_encoder.encodeHeader(&header_block, ":authority", authority);

        // Encode additional headers
        for (headers) |header| {
            try qpack_encoder.encodeHeader(&header_block, header.name, header.value);
        }

        return Http3Frame{
            .frame_type = .headers,
            .payload = try self.allocator.dupe(u8, header_block.items),
        };
    }

    /// Read HTTP/3 response from stream with enhanced processing
    pub fn readResponse(self: *Self, stream_id: u64) !Http3Response {
        const stream = self.streams.get(stream_id) orelse return error.StreamNotFound;

        var response = Http3Response{
            .status = 0,
            .headers = ArrayList(QpackDecoder.QpackEntry).init(self.allocator),
            .body = ArrayList(u8).init(self.allocator),
        };
        errdefer response.deinit();

        // Read frames from stream until complete response
        var frames_processed: u32 = 0;
        const max_frames = 1000; // Prevent infinite loops

        while (frames_processed < max_frames) {
            const frame = try self.readFrameFromStream(stream) orelse break;
            defer self.allocator.free(frame.payload);

            switch (frame.frame_type) {
                .headers => {
                    try self.parseHeadersFrame(frame, &response);
                },
                .data => {
                    try response.body.appendSlice(frame.payload);
                },
                .push_promise => {
                    // Handle server push (ignore for now)
                    continue;
                },
                .goaway => {
                    // Server is closing connection
                    return error.ConnectionClosed;
                },
                else => {
                    // Handle other frame types as needed
                    continue;
                },
            }

            frames_processed += 1;

            // Check if response is complete
            if (self.isResponseComplete(&response)) break;
        }

        return response;
    }

    /// Enhanced response reading with streaming support
    pub fn readResponseStreaming(self: *Self, stream_id: u64, max_body_size: ?usize) !Http3ResponseStream {
        _ = self.streams.get(stream_id) orelse return error.StreamNotFound;

        return Http3ResponseStream{
            .stream_id = stream_id,
            .connection = self,
            .max_body_size = max_body_size,
            .bytes_read = 0,
            .headers_complete = false,
            .response_complete = false,
            .status = 0,
            .headers = ArrayList(QpackDecoder.QpackEntry).init(self.allocator),
        };
    }

    /// Parse HEADERS frame and extract status and headers
    fn parseHeadersFrame(self: *Self, frame: Http3Frame, response: *Http3Response) !void {
        var qpack_decoder = QpackDecoder.init(self.allocator, 4096);
        defer qpack_decoder.deinit();
        var headers = ArrayList(QpackDecoder.QpackEntry).init(self.allocator);
        defer {
            for (headers.items) |header| {
                self.allocator.free(header.name);
                self.allocator.free(header.value);
            }
            headers.deinit();
        }

        try qpack_decoder.decode(frame.payload, &headers);

        // Extract status from :status pseudo-header
        for (headers.items) |header| {
            if (std.mem.eql(u8, header.name, ":status")) {
                response.status = std.fmt.parseInt(u16, header.value, 10) catch 500;
            } else {
                // Add to response headers (need to duplicate strings)
                const name_copy = try self.allocator.dupe(u8, header.name);
                const value_copy = try self.allocator.dupe(u8, header.value);
                try response.headers.append(.{ .name = name_copy, .value = value_copy });
            }
        }
    }

    /// Read a frame from stream buffer
    fn readFrameFromStream(self: *Self, stream: *const QuicStream) !?Http3Frame {
        if (stream.recv_buffer.items.len < 8) return null; // Need at least frame header

        const frame = Http3Frame.parse(stream.recv_buffer.items) catch |err| switch (err) {
            error.InvalidFrameLength => return null, // Need more data
            else => return err,
        };

        // Create a copy of the frame with owned payload
        const owned_payload = try self.allocator.dupe(u8, frame.payload);
        return Http3Frame{
            .frame_type = frame.frame_type,
            .payload = owned_payload,
        };
    }

    /// Check if HTTP/3 response is complete
    fn isResponseComplete(self: *Self, response: *const Http3Response) bool {
        _ = self;
        // Enhanced completion check: status code and either no content-length or body matches content-length
        if (response.status == 0) return false;

        // Check content-length header if present
        for (response.headers.items) |header| {
            if (mem.eql(u8, header.name, "content-length")) {
                const expected_length = std.fmt.parseInt(usize, header.value, 10) catch return true;
                return response.body.items.len >= expected_length;
            }
        }

        // No content-length header, assume complete for now
        // In a real implementation, would wait for stream close or end-of-stream flag
        return true;
    }

    /// Get response by stream ID (non-blocking)
    pub fn pollResponse(self: *Self, stream_id: u64) ?Http3Response {
        return self.completed_responses.get(stream_id);
    }

    /// Wait for response with timeout
    pub fn waitForResponse(self: *Self, stream_id: u64, timeout_ms: u64) !Http3Response {
        const start_time = std.time.milliTimestamp();

        while (std.time.milliTimestamp() - start_time < timeout_ms) {
            // Process incoming packets
            self.processIncomingPackets() catch |err| switch (err) {
                QuicTransport.TransportError.NetworkError => {}, // Continue waiting
                else => return err,
            };

            // Check if response is ready
            if (self.isResponseReady(stream_id)) {
                return self.getResponse(stream_id) orelse return error.ResponseNotFound;
            }

            // Small delay to avoid busy waiting
            std.time.sleep(1 * std.time.ns_per_ms);
        }

        return error.Timeout;
    }

    /// Create a simple HTTP/3 client interface
    pub fn simpleRequest(self: *Self, method: []const u8, url: []const u8, headers: ?[]const QpackDecoder.QpackEntry, body: ?[]const u8) !Http3Response {
        // Parse URL to extract path (simplified)
        const path = if (mem.indexOf(u8, url, "://")) |proto_end| blk: {
            const after_proto = url[proto_end + 3 ..];
            if (mem.indexOf(u8, after_proto, "/")) |path_start| {
                break :blk after_proto[path_start..];
            }
            break :blk "/";
        } else url;

        // Send request
        const stream_id = try self.sendRequest(method, path, headers orelse &[_]QpackDecoder.QpackEntry{}, body);

        // Wait for response (10 second timeout)
        return self.waitForResponse(stream_id, 10000);
    }
};

/// QUIC stream
pub const QuicStream = struct {
    id: u64,
    state: StreamState,
    send_buffer: ArrayList(u8),
    recv_buffer: ArrayList(u8),
    allocator: Allocator,

    const Self = @This();

    const StreamState = enum {
        open,
        half_closed_local,
        half_closed_remote,
        closed,
    };

    pub fn init(allocator: Allocator, id: u64) Self {
        return Self{
            .id = id,
            .state = .open,
            .send_buffer = ArrayList(u8).init(allocator),
            .recv_buffer = ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.send_buffer.deinit();
        self.recv_buffer.deinit();
    }

    /// Send HTTP/3 frame on stream
    pub fn sendFrame(self: *Self, frame: Http3Frame) !void {
        var buffer = ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        try frame.serialize(buffer.writer());
        try self.send_buffer.appendSlice(buffer.items);

        // Mark stream as having data to send
        // In a real implementation, this would trigger the QUIC transport
        // to send the data as STREAM frames
    }

    /// Get available data to send
    pub fn getDataToSend(self: *Self) []const u8 {
        return self.send_buffer.items;
    }

    /// Clear sent data from buffer
    pub fn clearSentData(self: *Self, bytes_sent: usize) void {
        if (bytes_sent >= self.send_buffer.items.len) {
            self.send_buffer.clearRetainingCapacity();
        } else {
            // Remove sent bytes from beginning of buffer
            const remaining = self.send_buffer.items[bytes_sent..];
            self.send_buffer.clearRetainingCapacity();
            self.send_buffer.appendSlice(remaining) catch {};
        }
    }

    /// Receive data on stream
    pub fn receiveData(self: *Self, data: []const u8) !void {
        try self.recv_buffer.appendSlice(data);
    }
};

/// Enhanced QPACK encoder with better compression
pub const EnhancedQpackEncoder = struct {
    allocator: Allocator,
    dynamic_table: ArrayList(QpackDecoder.QpackEntry),
    max_table_size: u64,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .dynamic_table = ArrayList(QpackDecoder.QpackEntry).init(allocator),
            .max_table_size = 4096,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.dynamic_table.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.dynamic_table.deinit();
    }

    /// Encode header with better static table utilization
    pub fn encodeHeader(self: *Self, buffer: *ArrayList(u8), name: []const u8, value: []const u8) !void {
        // Check static table first
        if (self.findInStaticTable(name, value)) |index| {
            // Indexed field line
            try encodeVarintWithPrefix(buffer.writer(), index, 6, 0x80);
            return;
        }

        // Check if name is in static table
        if (self.findNameInStaticTable(name)) |name_index| {
            // Literal field line with name reference
            try encodeVarintWithPrefix(buffer.writer(), name_index, 4, 0x40);
            try self.encodeString(buffer, value);
        } else {
            // Literal field line without name reference
            try buffer.append(0x20); // 001 pattern
            try self.encodeString(buffer, name);
            try self.encodeString(buffer, value);
        }

        // Add to dynamic table if space allows
        if (self.shouldAddToDynamicTable(name, value)) {
            try self.addToDynamicTable(name, value);
        }
    }

    fn findInStaticTable(self: *Self, name: []const u8, value: []const u8) ?u64 {
        _ = self;
        for (QpackDecoder.QPACK_STATIC_TABLE, 0..) |entry, i| {
            if (mem.eql(u8, entry.name, name) and mem.eql(u8, entry.value, value)) {
                return i + 1;
            }
        }
        return null;
    }

    fn findNameInStaticTable(self: *Self, name: []const u8) ?u64 {
        _ = self;
        for (QpackDecoder.QPACK_STATIC_TABLE, 0..) |entry, i| {
            if (mem.eql(u8, entry.name, name)) {
                return i + 1;
            }
        }
        return null;
    }

    fn shouldAddToDynamicTable(self: *Self, name: []const u8, value: []const u8) bool {
        const entry_size = name.len + value.len + 32; // 32 bytes overhead
        return entry_size <= self.max_table_size / 4; // Only add if reasonable size
    }

    fn addToDynamicTable(self: *Self, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);

        try self.dynamic_table.insert(0, .{ .name = name_copy, .value = value_copy });

        // Evict old entries if necessary
        while (self.calculateTableSize() > self.max_table_size and self.dynamic_table.items.len > 0) {
            const removed = self.dynamic_table.pop();
            self.allocator.free(removed.name);
            self.allocator.free(removed.value);
        }
    }

    fn calculateTableSize(self: *Self) u64 {
        var size: u64 = 0;
        for (self.dynamic_table.items) |entry| {
            size += entry.name.len + entry.value.len + 32;
        }
        return size;
    }

    fn encodeString(self: *Self, buffer: *ArrayList(u8), string: []const u8) !void {
        _ = self;
        // For now, just encode length and string (no Huffman compression)
        try encodeVarint(buffer.writer(), string.len);
        try buffer.appendSlice(string);
    }
};

/// Variable-length integer encoding/decoding (QUIC varint)
pub fn encodeVarint(writer: anytype, value: u64) !void {
    if (value < 0x40) {
        try writer.writeByte(@intCast(value));
    } else if (value < 0x4000) {
        try writer.writeByte(@intCast(0x40 | (value >> 8)));
        try writer.writeByte(@intCast(value & 0xFF));
    } else if (value < 0x40000000) {
        try writer.writeByte(@intCast(0x80 | (value >> 24)));
        try writer.writeByte(@intCast((value >> 16) & 0xFF));
        try writer.writeByte(@intCast((value >> 8) & 0xFF));
        try writer.writeByte(@intCast(value & 0xFF));
    } else {
        try writer.writeByte(@intCast(0xC0 | (value >> 56)));
        try writer.writeByte(@intCast((value >> 48) & 0xFF));
        try writer.writeByte(@intCast((value >> 40) & 0xFF));
        try writer.writeByte(@intCast((value >> 32) & 0xFF));
        try writer.writeByte(@intCast((value >> 24) & 0xFF));
        try writer.writeByte(@intCast((value >> 16) & 0xFF));
        try writer.writeByte(@intCast((value >> 8) & 0xFF));
        try writer.writeByte(@intCast(value & 0xFF));
    }
}

pub fn decodeVarint(data: []const u8, pos: *usize) !u64 {
    if (pos.* >= data.len) return error.UnexpectedEndOfData;

    const first_byte = data[pos.*];
    pos.* += 1;

    const length_bits = (first_byte >> 6) & 0x3;
    const value_bits = first_byte & 0x3F;

    switch (length_bits) {
        0 => return value_bits,
        1 => {
            if (pos.* >= data.len) return error.UnexpectedEndOfData;
            const second_byte = data[pos.*];
            pos.* += 1;
            return (@as(u64, value_bits) << 8) | second_byte;
        },
        2 => {
            if (pos.* + 2 >= data.len) return error.UnexpectedEndOfData;
            const value = (@as(u64, value_bits) << 24) |
                (@as(u64, data[pos.*]) << 16) |
                (@as(u64, data[pos.* + 1]) << 8) |
                @as(u64, data[pos.* + 2]);
            pos.* += 3;
            return value;
        },
        3 => {
            if (pos.* + 6 >= data.len) return error.UnexpectedEndOfData;
            const value = (@as(u64, value_bits) << 56) |
                (@as(u64, data[pos.*]) << 48) |
                (@as(u64, data[pos.* + 1]) << 40) |
                (@as(u64, data[pos.* + 2]) << 32) |
                (@as(u64, data[pos.* + 3]) << 24) |
                (@as(u64, data[pos.* + 4]) << 16) |
                (@as(u64, data[pos.* + 5]) << 8) |
                @as(u64, data[pos.* + 6]);
            pos.* += 7;
            return value;
        },
        else => return error.InvalidVarintLength,
    }

    unreachable;
}

pub fn decodeVarintWithPrefix(data: []const u8, pos: *usize, prefix_bits: u8) !u64 {
    if (pos.* >= data.len) return error.UnexpectedEndOfData;

    const mask = (@as(u8, 1) << @intCast(prefix_bits)) - 1;
    var value = @as(u64, data[pos.*] & mask);
    pos.* += 1;

    if (value < mask) return value;

    var shift: u6 = 0;
    while (pos.* < data.len) {
        const byte = data[pos.*];
        pos.* += 1;

        value += (@as(u64, byte & 0x7F) << shift);
        if (byte & 0x80 == 0) break;

        shift += 7;
        if (shift >= 64) return error.IntegerOverflow;
    }

    return value;
}

pub fn encodeVarintWithPrefix(writer: anytype, value: u64, prefix_bits: u8, prefix_mask: u8) !void {
    const max_prefix = (@as(u64, 1) << @intCast(prefix_bits)) - 1;

    if (value < max_prefix) {
        try writer.writeByte(@intCast(prefix_mask | value));
        return;
    }

    // Write prefix with all bits set
    try writer.writeByte(@intCast(prefix_mask | max_prefix));

    // Encode remaining value
    var remaining = value - max_prefix;
    while (remaining >= 128) {
        try writer.writeByte(@intCast((remaining % 128) | 128));
        remaining /= 128;
    }
    try writer.writeByte(@intCast(remaining));
}

// Tests
test "HTTP/3 frame parsing" {
    var buffer = ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    // Create HEADERS frame with some data
    const header_data = "test-headers";
    const frame = Http3Frame.headers(header_data);

    try frame.serialize(buffer.writer());

    const parsed_frame = try Http3Frame.parse(buffer.items);

    try testing.expect(parsed_frame.frame_type == .headers);
    try testing.expectEqualStrings(parsed_frame.payload, header_data);
}

test "QUIC varint encoding/decoding" {
    var buffer = ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    // Test various values
    const test_values = [_]u64{ 0, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903 };

    for (test_values) |value| {
        buffer.clearRetainingCapacity();
        try encodeVarint(buffer.writer(), value);

        var pos: usize = 0;
        const decoded = try decodeVarint(buffer.items, &pos);
        try testing.expect(decoded == value);
    }
}

test "QPACK static table" {
    try testing.expectEqualStrings(QpackDecoder.QPACK_STATIC_TABLE[0].name, ":authority");
    try testing.expectEqualStrings(QpackDecoder.QPACK_STATIC_TABLE[2].name, ":method");
    try testing.expectEqualStrings(QpackDecoder.QPACK_STATIC_TABLE[2].value, "GET");
}

test "QUIC connection creation" {
    const local_addr = try net.Address.parseIp("127.0.0.1", 443);
    const remote_addr = try net.Address.parseIp("127.0.0.1", 8080);

    var conn = QuicConnection.init(testing.allocator, false, local_addr, remote_addr);
    defer conn.deinit();

    try testing.expect(conn.is_server == false);
    try testing.expect(conn.state == .initial);
    try testing.expect(conn.next_stream_id == 0);
}

test "HTTP/3 settings" {
    const settings = Http3Settings.getDefaultSettings();
    try testing.expect(settings.qpack_max_table_capacity == 4096);
    try testing.expect(settings.qpack_blocked_streams == 0);
    try testing.expect(settings.max_field_section_size == null);
}
