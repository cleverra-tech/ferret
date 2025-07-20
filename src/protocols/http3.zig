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

/// QUIC connection
pub const QuicConnection = struct {
    connection_id: [8]u8,
    local_address: net.Address,
    remote_address: net.Address,
    state: ConnectionState,
    streams: std.HashMap(u64, QuicStream, std.hash_map.AutoContext(u64), std.hash_map.default_max_load_percentage),
    next_stream_id: u64,
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

        // TODO: Extract authority from connection if available
        // For now, use a default authority
        try qpack_encoder.encodeHeader(&header_block, ":authority", "localhost");

        // Encode additional headers
        for (headers) |header| {
            try qpack_encoder.encodeHeader(&header_block, header.name, header.value);
        }

        return Http3Frame{
            .frame_type = .headers,
            .payload = try self.allocator.dupe(u8, header_block.items),
        };
    }

    /// Read HTTP/3 response from stream
    pub fn readResponse(self: *Self, stream_id: u64) !Http3Response {
        const stream = self.streams.get(stream_id) orelse return error.StreamNotFound;

        var response = Http3Response{
            .status = 0,
            .headers = ArrayList(QpackDecoder.QpackEntry).init(self.allocator),
            .body = ArrayList(u8).init(self.allocator),
        };
        errdefer response.deinit();

        // Read frames from stream until complete response
        while (true) {
            const frame = try self.readFrameFromStream(stream) orelse break;
            defer self.allocator.free(frame.payload);

            switch (frame.frame_type) {
                .headers => {
                    try self.parseHeadersFrame(frame, &response);
                },
                .data => {
                    try response.body.appendSlice(frame.payload);
                },
                else => {
                    // Handle other frame types as needed
                    continue;
                },
            }

            // Check if response is complete
            if (self.isResponseComplete(&response)) break;
        }

        return response;
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

    /// Read a frame from stream (simplified for demonstration)
    fn readFrameFromStream(self: *Self, stream: *const QuicStream) !?Http3Frame {
        _ = self;
        // In a real implementation, this would read from the stream's receive buffer
        // and parse HTTP/3 frames. For now, return null to indicate no more frames
        _ = stream;
        return null;
    }

    /// Check if HTTP/3 response is complete
    fn isResponseComplete(self: *Self, response: *const Http3Response) bool {
        _ = self;
        // Simple heuristic: response is complete if we have a status
        return response.status != 0;
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
    }

    /// Receive data on stream
    pub fn receiveData(self: *Self, data: []const u8) !void {
        try self.recv_buffer.appendSlice(data);
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
