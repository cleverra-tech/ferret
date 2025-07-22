//! HTTP/1.1 implementation for Ferret
//!
//! This implementation provides:
//! - High-performance HTTP/1.1 parser with zero-copy optimizations
//! - Support for streaming request/response parsing
//! - Chunked encoding support
//! - Header case-insensitive handling
//! - Pipeline support with configurable limits
//! - Memory-efficient buffer management
//! - WebSocket upgrade support

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;

/// HTTP methods
pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
    TRACE,
    CONNECT,

    /// Parse method from string
    pub fn fromString(str: []const u8) ?Method {
        return switch (str.len) {
            3 => switch (str[0]) {
                'G', 'g' => if (mem.eql(u8, str, "GET") or mem.eql(u8, str, "get")) .GET else null,
                'P', 'p' => if (mem.eql(u8, str, "PUT") or mem.eql(u8, str, "put")) .PUT else null,
                else => null,
            },
            4 => switch (str[0]) {
                'P', 'p' => if (mem.eql(u8, str, "POST") or mem.eql(u8, str, "post")) .POST else null,
                'H', 'h' => if (mem.eql(u8, str, "HEAD") or mem.eql(u8, str, "head")) .HEAD else null,
                else => null,
            },
            5 => switch (str[0]) {
                'P', 'p' => if (mem.eql(u8, str, "PATCH") or mem.eql(u8, str, "patch")) .PATCH else null,
                'T', 't' => if (mem.eql(u8, str, "TRACE") or mem.eql(u8, str, "trace")) .TRACE else null,
                else => null,
            },
            6 => if (mem.eql(u8, str, "DELETE") or mem.eql(u8, str, "delete")) .DELETE else null,
            7 => switch (str[0]) {
                'O', 'o' => if (mem.eql(u8, str, "OPTIONS") or mem.eql(u8, str, "options")) .OPTIONS else null,
                'C', 'c' => if (mem.eql(u8, str, "CONNECT") or mem.eql(u8, str, "connect")) .CONNECT else null,
                else => null,
            },
            else => null,
        };
    }

    /// Convert to string representation
    pub fn toString(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
            .PATCH => "PATCH",
            .TRACE => "TRACE",
            .CONNECT => "CONNECT",
        };
    }
};

/// HTTP version
pub const Version = enum {
    http_1_0,
    http_1_1,
    http_2_0,

    pub fn fromString(str: []const u8) ?Version {
        if (mem.eql(u8, str, "HTTP/1.0")) return .http_1_0;
        if (mem.eql(u8, str, "HTTP/1.1")) return .http_1_1;
        if (mem.eql(u8, str, "HTTP/2.0")) return .http_2_0;
        return null;
    }

    pub fn toString(self: Version) []const u8 {
        return switch (self) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
            .http_2_0 => "HTTP/2.0",
        };
    }
};

/// HTTP status codes
pub const Status = enum(u16) {
    // 1xx Informational
    continue_100 = 100,
    switching_protocols = 101,
    processing = 102,

    // 2xx Success
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    partial_content = 206,

    // 3xx Redirection
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    temporary_redirect = 307,
    permanent_redirect = 308,

    // 4xx Client Error
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    payload_too_large = 413,
    uri_too_long = 414,
    unsupported_media_type = 415,
    range_not_satisfiable = 416,
    upgrade_required = 426,
    too_many_requests = 429,

    // 5xx Server Error
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,

    pub fn phrase(self: Status) []const u8 {
        return switch (self) {
            .continue_100 => "Continue",
            .switching_protocols => "Switching Protocols",
            .processing => "Processing",
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .no_content => "No Content",
            .partial_content => "Partial Content",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .see_other => "See Other",
            .not_modified => "Not Modified",
            .temporary_redirect => "Temporary Redirect",
            .permanent_redirect => "Permanent Redirect",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .not_acceptable => "Not Acceptable",
            .request_timeout => "Request Timeout",
            .conflict => "Conflict",
            .gone => "Gone",
            .length_required => "Length Required",
            .payload_too_large => "Payload Too Large",
            .uri_too_long => "URI Too Long",
            .unsupported_media_type => "Unsupported Media Type",
            .range_not_satisfiable => "Range Not Satisfiable",
            .upgrade_required => "Upgrade Required",
            .too_many_requests => "Too Many Requests",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .gateway_timeout => "Gateway Timeout",
            .http_version_not_supported => "HTTP Version Not Supported",
        };
    }
};

/// HTTP headers container with case-insensitive lookup
pub const Headers = struct {
    map: std.StringHashMap([]const u8),
    allocator: Allocator,
    owns_values: bool, // Track whether values should be deallocated

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .map = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
            .owns_values = false,
        };
    }

    /// Initialize headers with control over value ownership
    pub fn initWithOwnership(allocator: Allocator, owns_values: bool) Self {
        return Self{
            .map = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
            .owns_values = owns_values,
        };
    }

    pub fn deinit(self: *Self) void {
        // Free all allocated keys and values
        var iterator = self.map.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            if (self.owns_values) {
                self.allocator.free(@constCast(entry.value_ptr.*));
            }
        }
        self.map.deinit();
    }

    /// Set header value (case-insensitive key)
    pub fn set(self: *Self, key: []const u8, value: []const u8) !void {
        // Store lowercase key for case-insensitive lookup
        const lower_key = try self.allocator.alloc(u8, key.len);
        for (key, 0..) |c, i| {
            lower_key[i] = std.ascii.toLower(c);
        }

        // Check if key already exists and free old key and value
        if (self.map.fetchRemove(lower_key)) |old_entry| {
            self.allocator.free(old_entry.key);
            if (self.owns_values) {
                self.allocator.free(@constCast(old_entry.value));
            }
        }

        try self.map.put(lower_key, value);
    }

    /// Set header value with ownership control
    pub fn setOwned(self: *Self, key: []const u8, value: []const u8) !void {
        // Store lowercase key for case-insensitive lookup
        const lower_key = try self.allocator.alloc(u8, key.len);
        for (key, 0..) |c, i| {
            lower_key[i] = std.ascii.toLower(c);
        }

        // Always duplicate the value to ensure we own it
        const owned_value = try self.allocator.dupe(u8, value);

        // Check if key already exists and free old key and value
        if (self.map.fetchRemove(lower_key)) |old_entry| {
            self.allocator.free(old_entry.key);
            if (self.owns_values) {
                self.allocator.free(@constCast(old_entry.value));
            }
        }

        try self.map.put(lower_key, owned_value);
        self.owns_values = true;
    }

    /// Get header value (case-insensitive key)
    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        var lower_key: [256]u8 = undefined;
        if (key.len > lower_key.len) return null;

        for (key, 0..) |c, i| {
            lower_key[i] = std.ascii.toLower(c);
        }
        return self.map.get(lower_key[0..key.len]);
    }

    /// Check if header exists
    pub fn has(self: *const Self, key: []const u8) bool {
        return self.get(key) != null;
    }

    /// Get content length from headers
    pub fn getContentLength(self: *const Self) !?u64 {
        if (self.get("content-length")) |value| {
            return try std.fmt.parseInt(u64, value, 10);
        }
        return null;
    }

    /// Check if connection should be kept alive
    pub fn isKeepAlive(self: *const Self, version: Version) bool {
        if (self.get("connection")) |conn| {
            const lower_conn = std.ascii.lowerString(conn, conn);
            if (mem.indexOf(u8, lower_conn, "close") != null) return false;
            if (mem.indexOf(u8, lower_conn, "keep-alive") != null) return true;
        }
        // HTTP/1.1 defaults to keep-alive, HTTP/1.0 defaults to close
        return version == .http_1_1;
    }

    /// Check if transfer encoding is chunked
    pub fn isChunked(self: *const Self) bool {
        if (self.get("transfer-encoding")) |encoding| {
            // Check for chunked case-insensitively
            if (encoding.len >= 7) {
                var i: usize = 0;
                while (i <= encoding.len - 7) : (i += 1) {
                    if (std.ascii.startsWithIgnoreCase(encoding[i..], "chunked")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
};

/// HTTP request representation
pub const Request = struct {
    method: Method,
    path: []const u8,
    query: ?[]const u8,
    version: Version,
    headers: Headers,
    trailers: Headers,
    body: ?[]const u8,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .method = .GET,
            .path = "",
            .query = null,
            .version = .http_1_1,
            .headers = Headers.init(allocator),
            .trailers = Headers.init(allocator),
            .body = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        self.trailers.deinit();
    }
};

/// HTTP response representation
pub const Response = struct {
    version: Version,
    status: Status,
    headers: Headers,
    trailers: Headers,
    body: ?[]const u8,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .version = .http_1_1,
            .status = .ok,
            .headers = Headers.init(allocator),
            .trailers = Headers.init(allocator),
            .body = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        self.trailers.deinit();
    }

    /// Format response as HTTP message
    pub fn format(self: *const Self, allocator: Allocator) ![]u8 {
        var response = ArrayList(u8).init(allocator);
        defer response.deinit();

        // Status line
        try response.writer().print("{s} {} {s}\r\n", .{
            self.version.toString(),
            @intFromEnum(self.status),
            self.status.phrase(),
        });

        // Headers
        var iterator = self.headers.map.iterator();
        while (iterator.next()) |entry| {
            try response.writer().print("{s}: {s}\r\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        // Body
        if (self.body) |body| {
            try response.writer().print("Content-Length: {}\r\n\r\n{s}", .{ body.len, body });
        } else {
            try response.appendSlice("\r\n");
        }

        return response.toOwnedSlice();
    }
};

/// Parser state flags
const ParserFlags = packed struct {
    status_line_complete: bool = false,
    headers_complete: bool = false,
    message_complete: bool = false,
    content_length_set: bool = false,
    chunked_encoding: bool = false,
    is_response: bool = false,
    upgrade_connection: bool = false,
    reserved: u1 = 0,
};

/// Check if character is valid in HTTP header name (RFC 7230)
fn isValidHeaderNameChar(char: u8) bool {
    return switch (char) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}

/// HTTP parser callbacks
pub const ParserCallbacks = struct {
    on_method: ?*const fn (method: Method) void = null,
    on_path: ?*const fn (path: []const u8) void = null,
    on_query: ?*const fn (query: []const u8) void = null,
    on_version: ?*const fn (version: Version) void = null,
    on_status: ?*const fn (status: Status) void = null,
    on_header: ?*const fn (name: []const u8, value: []const u8) void = null,
    on_headers_complete: ?*const fn () void = null,
    on_body: ?*const fn (data: []const u8) void = null,
    on_trailer: ?*const fn (name: []const u8, value: []const u8) void = null,
    on_message_complete: ?*const fn () void = null,
    on_error: ?*const fn (err: ParserError) void = null,
};

/// Parser error types
pub const ParserError = error{
    InvalidMethod,
    InvalidPath,
    InvalidVersion,
    InvalidStatus,
    InvalidHeader,
    HeaderTooLarge,
    MessageTooLarge,
    ChunkedEncodingError,
    ProtocolError,
    OutOfMemory,
};

/// HTTP parser state
pub const Parser = struct {
    // Parser state
    state: enum {
        start,
        method,
        path,
        query,
        version,
        status_code,
        status_phrase,
        header_name,
        header_value,
        headers_done,
        body,
        chunk_size,
        chunk_data,
        chunk_trailer,
        trailer_name,
        trailer_value,
        message_complete,
        error_state,
    } = .start,

    flags: ParserFlags = .{},
    content_length: i64 = -1, // -1 = unknown, negative = chunked state
    bytes_read: usize = 0,
    current_chunk_size: usize = 0,

    // Current parsing context
    current_method: ?Method = null,
    current_status: ?Status = null,
    current_header_name: ?[]const u8 = null,

    // Configuration
    max_header_size: usize = 8192,
    max_headers_count: usize = 100,
    max_body_size: usize = 1024 * 1024, // 1MB default

    // Callbacks
    callbacks: ParserCallbacks = .{},

    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    /// Reset parser state for reuse
    pub fn reset(self: *Self) void {
        self.state = .start;
        self.flags = .{};
        self.content_length = -1;
        self.bytes_read = 0;
        self.current_chunk_size = 0;
        self.current_method = null;
        self.current_status = null;
        self.current_header_name = null;
    }

    /// Parse HTTP data
    pub fn parse(self: *Self, data: []const u8) ParserError!usize {
        var pos: usize = 0;
        var last_pos: usize = 0;

        while (pos <= data.len) {
            // Prevent infinite loops on states that don't consume data
            if (pos == last_pos and pos == data.len and self.state != .headers_done and self.state != .message_complete) {
                break;
            }
            last_pos = pos;

            switch (self.state) {
                .start => {
                    pos = try self.parseStart(data, pos);
                },
                .method => {
                    pos = try self.parseMethod(data, pos);
                },
                .path => {
                    pos = try self.parsePath(data, pos);
                },
                .query => {
                    pos = try self.parseQuery(data, pos);
                },
                .version => {
                    pos = try self.parseVersion(data, pos);
                },
                .status_code => {
                    pos = try self.parseStatusCode(data, pos);
                },
                .status_phrase => {
                    pos = try self.parseStatusPhrase(data, pos);
                },
                .header_name => {
                    pos = try self.parseHeaderName(data, pos);
                },
                .header_value => {
                    pos = try self.parseHeaderValue(data, pos);
                },
                .headers_done => {
                    pos = try self.parseHeadersDone(data, pos);
                },
                .body => {
                    pos = try self.parseBody(data, pos);
                },
                .chunk_size => {
                    pos = try self.parseChunkSize(data, pos);
                },
                .chunk_data => {
                    pos = try self.parseChunkData(data, pos);
                },
                .chunk_trailer => {
                    pos = try self.parseChunkTrailer(data, pos);
                },
                .trailer_name => {
                    pos = try self.parseTrailerName(data, pos);
                },
                .trailer_value => {
                    pos = try self.parseTrailerValue(data, pos);
                },
                .message_complete => {
                    if (self.callbacks.on_message_complete) |callback| {
                        callback();
                    }
                    return pos;
                },
                .error_state => {
                    return ParserError.ProtocolError;
                },
            }
        }

        return pos;
    }

    /// Find next occurrence of character in data
    fn findChar(self: *const Self, data: []const u8, pos: usize, char: u8) ?usize {
        _ = self;
        return mem.indexOfScalarPos(u8, data, pos, char);
    }

    /// Find CRLF or LF in data
    fn findEOL(self: *const Self, data: []const u8, pos: usize) ?struct { pos: usize, len: usize } {
        _ = self;
        if (pos >= data.len) return null;

        // Look for \r\n first
        if (mem.indexOfPos(u8, data, pos, "\r\n")) |crlf_pos| {
            return .{ .pos = crlf_pos, .len = 2 };
        }

        // Fall back to \n only
        if (mem.indexOfScalarPos(u8, data, pos, '\n')) |lf_pos| {
            return .{ .pos = lf_pos, .len = 1 };
        }

        return null;
    }

    /// Parse start of message
    fn parseStart(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        // Skip leading whitespace
        var current_pos = pos;
        while (current_pos < data.len and std.ascii.isWhitespace(data[current_pos])) {
            current_pos += 1;
        }

        if (current_pos >= data.len) return current_pos;

        // Detect if this is a response (starts with HTTP/)
        if (data.len - current_pos >= 5 and mem.startsWith(u8, data[current_pos..], "HTTP/")) {
            self.flags.is_response = true;
            self.state = .version;
        } else {
            self.state = .method;
        }

        return current_pos;
    }

    /// Parse HTTP method
    fn parseMethod(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findChar(data, pos, ' ')) |space_pos| {
            const method_str = data[pos..space_pos];
            if (Method.fromString(method_str)) |method| {
                self.current_method = method;
                if (self.callbacks.on_method) |callback| {
                    callback(method);
                }
                self.state = .path;
                return space_pos + 1;
            } else {
                return ParserError.InvalidMethod;
            }
        }
        return pos; // Need more data
    }

    /// Parse request path
    fn parsePath(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        // Look for space (end of path) or ? (start of query)
        var current_pos = pos;
        while (current_pos < data.len) {
            switch (data[current_pos]) {
                ' ' => {
                    const path = data[pos..current_pos];
                    if (self.callbacks.on_path) |callback| {
                        callback(path);
                    }
                    self.state = .version;
                    return current_pos + 1;
                },
                '?' => {
                    const path = data[pos..current_pos];
                    if (self.callbacks.on_path) |callback| {
                        callback(path);
                    }
                    self.state = .query;
                    return current_pos + 1;
                },
                else => current_pos += 1,
            }
        }
        return current_pos; // Need more data
    }

    /// Parse query string
    fn parseQuery(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findChar(data, pos, ' ')) |space_pos| {
            const query = data[pos..space_pos];
            if (self.callbacks.on_query) |callback| {
                callback(query);
            }
            self.state = .version;
            return space_pos + 1;
        }
        return pos; // Need more data
    }

    /// Parse HTTP version
    fn parseVersion(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findEOL(data, pos)) |eol| {
            const version_str = data[pos..eol.pos];
            if (Version.fromString(version_str)) |version| {
                if (self.callbacks.on_version) |callback| {
                    callback(version);
                }

                if (self.flags.is_response) {
                    self.state = .status_code;
                } else {
                    self.state = .header_name;
                }
                self.flags.status_line_complete = true;
                return eol.pos + eol.len;
            } else {
                return ParserError.InvalidVersion;
            }
        }
        return pos; // Need more data
    }

    /// Parse status code (for responses)
    fn parseStatusCode(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findChar(data, pos, ' ')) |space_pos| {
            const status_str = data[pos..space_pos];
            if (std.fmt.parseInt(u16, status_str, 10)) |status_code| {
                self.current_status = @enumFromInt(status_code);
                if (self.callbacks.on_status) |callback| {
                    callback(self.current_status.?);
                }
                self.state = .status_phrase;
                return space_pos + 1;
            } else |_| {
                return ParserError.InvalidStatus;
            }
        }
        return pos; // Need more data
    }

    /// Parse status phrase (for responses)
    fn parseStatusPhrase(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findEOL(data, pos)) |eol| {
            // Status phrase is ignored in this implementation
            self.state = .header_name;
            return eol.pos + eol.len;
        }
        return pos; // Need more data
    }

    /// Parse header name
    fn parseHeaderName(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findEOL(data, pos)) |eol| {
            // Empty line indicates end of headers
            if (eol.pos == pos) {
                self.flags.headers_complete = true;
                if (self.callbacks.on_headers_complete) |callback| {
                    callback();
                }
                self.state = .headers_done;
                return eol.pos + eol.len;
            }
        }

        if (self.findChar(data, pos, ':')) |colon_pos| {
            self.current_header_name = data[pos..colon_pos];
            self.state = .header_value;

            // Skip colon and optional whitespace
            var next_pos = colon_pos + 1;
            while (next_pos < data.len and data[next_pos] == ' ') {
                next_pos += 1;
            }
            return next_pos;
        }
        return pos; // Need more data
    }

    /// Parse header value
    fn parseHeaderValue(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findEOL(data, pos)) |eol| {
            if (self.current_header_name) |name| {
                const value = std.mem.trim(u8, data[pos..eol.pos], " \t");
                if (self.callbacks.on_header) |callback| {
                    callback(name, value);
                }

                // Process important headers
                if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                    if (std.fmt.parseInt(u64, value, 10)) |len| {
                        self.content_length = @intCast(len);
                        self.flags.content_length_set = true;
                    } else |_| {
                        return ParserError.InvalidHeader;
                    }
                } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                    // Check for chunked case-insensitively
                    if (value.len >= 7) {
                        var i: usize = 0;
                        while (i <= value.len - 7) : (i += 1) {
                            if (std.ascii.startsWithIgnoreCase(value[i..], "chunked")) {
                                self.flags.chunked_encoding = true;
                                self.content_length = -1;
                                break;
                            }
                        }
                    }
                } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
                    if (std.ascii.eqlIgnoreCase(value, "upgrade")) {
                        self.flags.upgrade_connection = true;
                    }
                }
            }

            self.current_header_name = null;
            self.state = .header_name;
            return eol.pos + eol.len;
        }
        return pos; // Need more data
    }

    /// Handle end of headers
    fn parseHeadersDone(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        _ = data;

        // Determine next state based on headers
        if (self.flags.chunked_encoding) {
            self.state = .chunk_size;
        } else if (self.content_length > 0) {
            self.state = .body;
        } else {
            // No body, message is complete
            self.flags.message_complete = true;
            self.state = .message_complete;
        }

        return pos;
    }

    /// Parse message body
    fn parseBody(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        const remaining_length = @as(usize, @intCast(self.content_length)) - self.bytes_read;
        const available = data.len - pos;
        const to_read = @min(remaining_length, available);

        if (to_read > 0) {
            if (self.callbacks.on_body) |callback| {
                callback(data[pos .. pos + to_read]);
            }
            self.bytes_read += to_read;
        }

        if (self.bytes_read >= self.content_length) {
            self.flags.message_complete = true;
            self.state = .message_complete;
        }

        return pos + to_read;
    }

    /// Parse chunk size (for chunked encoding)
    fn parseChunkSize(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findEOL(data, pos)) |eol| {
            const size_str = data[pos..eol.pos];

            // Parse hex chunk size
            if (std.fmt.parseInt(usize, size_str, 16)) |chunk_size| {
                self.current_chunk_size = chunk_size;

                if (chunk_size == 0) {
                    // Last chunk
                    self.state = .chunk_trailer;
                } else {
                    self.state = .chunk_data;
                }
                return eol.pos + eol.len;
            } else |_| {
                return ParserError.ChunkedEncodingError;
            }
        }
        return pos; // Need more data
    }

    /// Parse chunk data
    fn parseChunkData(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        const available = data.len - pos;
        const to_read = @min(self.current_chunk_size, available);

        if (to_read > 0) {
            if (self.callbacks.on_body) |callback| {
                callback(data[pos .. pos + to_read]);
            }
            self.current_chunk_size -= to_read;
        }

        var next_pos = pos + to_read;

        if (self.current_chunk_size == 0) {
            // Chunk complete, expect CRLF
            if (self.findEOL(data, next_pos)) |eol| {
                self.state = .chunk_size;
                next_pos = eol.pos + eol.len;
            }
        }

        return next_pos;
    }

    /// Parse chunk trailer (after last chunk)
    fn parseChunkTrailer(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findEOL(data, pos)) |eol| {
            if (eol.pos == pos) {
                // Empty line, trailers complete
                self.state = .message_complete;
                return eol.pos + eol.len;
            } else {
                // Start parsing trailer header
                self.state = .trailer_name;
                return pos;
            }
        }
        return pos; // Need more data
    }

    /// Parse trailer header name
    fn parseTrailerName(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findEOL(data, pos)) |eol| {
            // Empty line indicates end of trailers
            if (eol.pos == pos) {
                self.state = .message_complete;
                return eol.pos + eol.len;
            }
        }

        // Look for colon separator
        if (self.findChar(data, pos, ':')) |colon_pos| {
            if (colon_pos > pos) {
                const name = mem.trim(u8, data[pos..colon_pos], " \t");

                // Validate header name
                if (name.len == 0) return ParserError.InvalidHeader;
                for (name) |char| {
                    if (!isValidHeaderNameChar(char)) {
                        return ParserError.InvalidHeader;
                    }
                }

                self.current_header_name = name;
                self.state = .trailer_value;
                return colon_pos + 1;
            }
        }

        // Check if we have a complete line but no colon (invalid)
        if (self.findEOL(data, pos)) |_| {
            return ParserError.InvalidHeader;
        }

        return pos; // Need more data
    }

    /// Parse trailer header value
    fn parseTrailerValue(self: *Self, data: []const u8, pos: usize) ParserError!usize {
        if (self.findEOL(data, pos)) |eol| {
            const value = mem.trim(u8, data[pos..eol.pos], " \t");

            if (self.current_header_name) |name| {
                // Call trailer callback
                if (self.callbacks.on_trailer) |callback| {
                    callback(name, value);
                }
                self.current_header_name = null;
            }

            // Continue looking for more trailers
            self.state = .chunk_trailer;
            return eol.pos + eol.len;
        }
        return pos; // Need more data
    }
};

// Tests
test "HTTP Method parsing" {
    try testing.expect(Method.fromString("GET") == .GET);
    try testing.expect(Method.fromString("POST") == .POST);
    try testing.expect(Method.fromString("get") == .GET);
    try testing.expect(Method.fromString("invalid") == null);
    try testing.expectEqualStrings(Method.GET.toString(), "GET");
}

test "HTTP Version parsing" {
    try testing.expect(Version.fromString("HTTP/1.1") == .http_1_1);
    try testing.expect(Version.fromString("HTTP/1.0") == .http_1_0);
    try testing.expect(Version.fromString("invalid") == null);
    try testing.expectEqualStrings(Version.http_1_1.toString(), "HTTP/1.1");
}

test "HTTP Status codes" {
    try testing.expect(@intFromEnum(Status.ok) == 200);
    try testing.expect(@intFromEnum(Status.not_found) == 404);
    try testing.expectEqualStrings(Status.ok.phrase(), "OK");
    try testing.expectEqualStrings(Status.not_found.phrase(), "Not Found");
}

test "Headers case-insensitive operations" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.set("Content-Type", "application/json");
    try testing.expectEqualStrings(headers.get("content-type").?, "application/json");
    try testing.expectEqualStrings(headers.get("CONTENT-TYPE").?, "application/json");
    try testing.expect(headers.has("content-length") == false);
}

test "HTTP Request parsing - simple GET" {
    const request_data = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";

    var parser = Parser.init();

    // Use static data for test callbacks
    const TestData = struct {
        var method: ?Method = null;
        var path: ?[]const u8 = null;
        var version: ?Version = null;
        var headers_complete = false;
        var message_complete = false;

        fn onMethod(m: Method) void {
            method = m;
        }

        fn onPath(p: []const u8) void {
            path = p;
        }

        fn onVersion(v: Version) void {
            version = v;
        }

        fn onHeadersComplete() void {
            headers_complete = true;
        }

        fn onMessageComplete() void {
            message_complete = true;
        }
    };

    // Reset test data
    TestData.method = null;
    TestData.path = null;
    TestData.version = null;
    TestData.headers_complete = false;
    TestData.message_complete = false;

    parser.callbacks = .{
        .on_method = TestData.onMethod,
        .on_path = TestData.onPath,
        .on_version = TestData.onVersion,
        .on_headers_complete = TestData.onHeadersComplete,
        .on_message_complete = TestData.onMessageComplete,
    };

    const parsed = try parser.parse(request_data);
    try testing.expect(parsed == request_data.len);
    try testing.expect(TestData.method == .GET);
    try testing.expectEqualStrings(TestData.path.?, "/path");
    try testing.expect(TestData.version == .http_1_1);
    try testing.expect(TestData.headers_complete);
    try testing.expect(TestData.message_complete);
}

test "HTTP Request parsing - POST with body" {
    const request_data = "POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";

    var parser = Parser.init();

    const TestData = struct {
        var body_data: ?[]const u8 = null;
        var message_complete = false;

        fn onBody(data: []const u8) void {
            body_data = data;
        }

        fn onMessageComplete() void {
            message_complete = true;
        }
    };

    // Reset test data
    TestData.body_data = null;
    TestData.message_complete = false;

    parser.callbacks = .{
        .on_body = TestData.onBody,
        .on_message_complete = TestData.onMessageComplete,
    };

    _ = try parser.parse(request_data);
    try testing.expectEqualStrings(TestData.body_data.?, "hello");
    try testing.expect(TestData.message_complete);
}

test "HTTP Response formatting" {
    var response = Response.init(testing.allocator);
    defer response.deinit();

    response.status = .ok;
    try response.headers.set("Content-Type", "text/plain");
    response.body = "Hello, World!";

    const formatted = try response.format(testing.allocator);
    defer testing.allocator.free(formatted);

    try testing.expect(mem.indexOf(u8, formatted, "HTTP/1.1 200 OK") != null);
    try testing.expect(mem.indexOf(u8, formatted, "content-type: text/plain") != null);
    try testing.expect(mem.indexOf(u8, formatted, "Hello, World!") != null);
}

test "Chunked encoding detection" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.set("Transfer-Encoding", "chunked");
    try testing.expect(headers.isChunked());

    try headers.set("Transfer-Encoding", "gzip, chunked");
    try testing.expect(headers.isChunked());
}

test "Parser reset functionality" {
    var parser = Parser.init();
    parser.state = .body;
    parser.content_length = 100;
    parser.bytes_read = 50;

    parser.reset();

    try testing.expect(parser.state == .start);
    try testing.expect(parser.content_length == -1);
    try testing.expect(parser.bytes_read == 0);
}

test "Headers memory management with value ownership" {
    // Test without value ownership (default behavior)
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.set("content-type", "application/json");
    try headers.set("content-length", "100");

    // Replace value - should not deallocate since we don't own values
    try headers.set("content-type", "text/plain");
    try testing.expectEqualStrings("text/plain", headers.get("content-type").?);

    // Test with value ownership
    var owned_headers = Headers.initWithOwnership(testing.allocator, true);
    defer owned_headers.deinit();

    // Using setOwned to ensure we own the values
    try owned_headers.setOwned("authorization", "Bearer token123");
    try owned_headers.setOwned("user-agent", "Ferret/1.0");

    try testing.expectEqualStrings("Bearer token123", owned_headers.get("authorization").?);
    try testing.expectEqualStrings("Ferret/1.0", owned_headers.get("user-agent").?);

    // Replace owned value - should deallocate old value
    try owned_headers.setOwned("authorization", "Bearer newtoken456");
    try testing.expectEqualStrings("Bearer newtoken456", owned_headers.get("authorization").?);
}

test "Headers safe value ownership" {
    // Test safer ownership pattern - separate instances for different ownership models

    // Headers with only borrowed values
    var borrowed_headers = Headers.init(testing.allocator);
    defer borrowed_headers.deinit();
    try borrowed_headers.set("host", "example.com");
    try borrowed_headers.set("user-agent", "test-agent");
    try testing.expect(!borrowed_headers.owns_values);

    // Headers with only owned values
    var owned_headers = Headers.initWithOwnership(testing.allocator, true);
    defer owned_headers.deinit();
    try owned_headers.setOwned("authorization", "Bearer token");
    try owned_headers.setOwned("content-type", "application/json");
    try testing.expect(owned_headers.owns_values);

    // Verify values are accessible
    try testing.expectEqualStrings("example.com", borrowed_headers.get("host").?);
    try testing.expectEqualStrings("Bearer token", owned_headers.get("authorization").?);
}

test "HTTP chunked encoding with trailers parsing" {
    const TrailerEntry = struct { name: []const u8, value: []const u8 };

    const TestData = struct {
        var trailers: std.ArrayList(TrailerEntry) = undefined;
        var message_complete = false;

        fn onTrailer(name: []const u8, value: []const u8) void {
            trailers.append(.{ .name = name, .value = value }) catch {};
        }

        fn onMessageComplete() void {
            message_complete = true;
        }
    };

    TestData.trailers = std.ArrayList(TrailerEntry).init(testing.allocator);
    defer TestData.trailers.deinit();
    TestData.message_complete = false;

    var parser = Parser.init();
    parser.callbacks = .{
        .on_trailer = TestData.onTrailer,
        .on_message_complete = TestData.onMessageComplete,
    };

    // HTTP request with chunked encoding and trailers
    const http_data =
        "POST /upload HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "Trailer: X-Checksum, X-Upload-Time\r\n" ++
        "\r\n" ++
        "7\r\n" ++
        "Mozilla\r\n" ++
        "9\r\n" ++
        "Developer\r\n" ++
        "7\r\n" ++
        "Network\r\n" ++
        "0\r\n" ++
        "X-Checksum: abc123\r\n" ++
        "X-Upload-Time: 1234567890\r\n" ++
        "\r\n";

    _ = try parser.parse(http_data);

    // Verify trailers were parsed correctly
    try testing.expect(TestData.trailers.items.len == 2);
    try testing.expectEqualStrings("X-Checksum", TestData.trailers.items[0].name);
    try testing.expectEqualStrings("abc123", TestData.trailers.items[0].value);
    try testing.expectEqualStrings("X-Upload-Time", TestData.trailers.items[1].name);
    try testing.expectEqualStrings("1234567890", TestData.trailers.items[1].value);
    try testing.expect(TestData.message_complete);
}
