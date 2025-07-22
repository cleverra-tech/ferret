//! Unified HTTP API for Ferret
//!
//! This module provides a unified interface for HTTP/1.1, HTTP/2, and HTTP/3
//! with automatic protocol negotiation and HTTP/3 as the default.
//!
//! Features:
//! - Automatic protocol version detection and negotiation
//! - HTTP/3 (QUIC) as the default protocol with fallback
//! - Unified API across all HTTP versions
//! - Performance optimizations for each protocol version
//! - Connection pooling and reuse
//! - Automatic upgrade/downgrade handling

const std = @import("std");
const mem = std.mem;
const net = std.net;
const testing = std.testing;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;

const http1 = @import("http.zig");
const http2 = @import("http2.zig");
const http3 = @import("http3.zig");
const Buffer = @import("../io/buffer.zig").Buffer;
const SocketManager = @import("../io/socket.zig").SocketManager;
const SocketUUID = @import("../io/socket.zig").SocketUUID;
const Socket = @import("../io/socket.zig").Socket;
const SocketAddress = @import("../io/socket.zig").SocketAddress;
const SocketError = @import("../io/socket.zig").SocketError;
const Protocol = @import("../io/socket.zig").Protocol;
const Reactor = @import("../io/reactor.zig").Reactor;

/// HTTP client errors
pub const HttpClientError = error{
    /// Invalid URI format
    InvalidUri,
    /// Network connection failed
    ConnectionFailed,
    /// Request timeout
    Timeout,
    /// HTTP/2 requires TLS
    Http2RequiresTls,
    /// HTTP/3 requires HTTPS
    Http3RequiresHttps,
    /// Protocol negotiation failed
    ProtocolNegotiationFailed,
    /// Invalid response received
    InvalidResponse,
    /// Memory allocation failed
    OutOfMemory,
    /// I/O operation failed
    IOError,
    /// Feature not yet implemented
    NotImplemented,
};

/// HTTP server errors
pub const HttpServerError = error{
    /// Server is already listening
    AlreadyListening,
    /// Server is not listening
    NotListening,
    /// No request handler configured
    NoRequestHandler,
    /// Failed to bind to address
    BindFailed,
    /// Failed to start listening
    ListenFailed,
    /// Invalid address format
    InvalidAddress,
    /// Memory allocation failed
    OutOfMemory,
    /// I/O operation failed
    IOError,
    /// Invalid HTTP request format
    InvalidRequest,
};

/// HTTP protocol versions
pub const HttpVersion = enum(u8) {
    http_1_0 = 10,
    http_1_1 = 11,
    http_2_0 = 20,
    http_3_0 = 30,

    pub fn toString(self: HttpVersion) []const u8 {
        return switch (self) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
            .http_2_0 => "HTTP/2.0",
            .http_3_0 => "HTTP/3.0",
        };
    }

    pub fn fromString(str: []const u8) ?HttpVersion {
        if (mem.eql(u8, str, "HTTP/1.0")) return .http_1_0;
        if (mem.eql(u8, str, "HTTP/1.1")) return .http_1_1;
        if (mem.eql(u8, str, "HTTP/2.0")) return .http_2_0;
        if (mem.eql(u8, str, "HTTP/3.0")) return .http_3_0;
        return null;
    }

    pub fn supportsMultiplexing(self: HttpVersion) bool {
        return switch (self) {
            .http_1_0, .http_1_1 => false,
            .http_2_0, .http_3_0 => true,
        };
    }

    pub fn requiresEncryption(self: HttpVersion) bool {
        return switch (self) {
            .http_1_0, .http_1_1 => false,
            .http_2_0 => false, // Can work over plaintext in theory
            .http_3_0 => true, // QUIC always encrypted
        };
    }

    pub fn usesUdp(self: HttpVersion) bool {
        return switch (self) {
            .http_1_0, .http_1_1, .http_2_0 => false,
            .http_3_0 => true,
        };
    }
};

/// HTTP method (unified across all versions)
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

    pub fn fromString(str: []const u8) ?Method {
        const methods = [_]Method{ .GET, .POST, .PUT, .DELETE, .HEAD, .OPTIONS, .PATCH, .TRACE, .CONNECT };
        for (methods) |method| {
            if (mem.eql(u8, str, method.toString())) return method;
        }
        return null;
    }

    pub fn isIdempotent(self: Method) bool {
        return switch (self) {
            .GET, .HEAD, .PUT, .DELETE, .OPTIONS, .TRACE => true,
            .POST, .PATCH, .CONNECT => false,
        };
    }

    pub fn isSafe(self: Method) bool {
        return switch (self) {
            .GET, .HEAD, .OPTIONS, .TRACE => true,
            .POST, .PUT, .DELETE, .PATCH, .CONNECT => false,
        };
    }
};

/// HTTP status code (unified across all versions)
pub const StatusCode = enum(u16) {
    // 1xx Informational
    continue_100 = 100,
    switching_protocols = 101,
    processing = 102,
    early_hints = 103,

    // 2xx Success
    ok = 200,
    created = 201,
    accepted = 202,
    non_authoritative = 203,
    no_content = 204,
    reset_content = 205,
    partial_content = 206,

    // 3xx Redirection
    multiple_choices = 300,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    use_proxy = 305,
    temporary_redirect = 307,
    permanent_redirect = 308,

    // 4xx Client Error
    bad_request = 400,
    unauthorized = 401,
    payment_required = 402,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    proxy_authentication_required = 407,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    precondition_failed = 412,
    payload_too_large = 413,
    uri_too_long = 414,
    unsupported_media_type = 415,
    range_not_satisfiable = 416,
    expectation_failed = 417,
    im_a_teapot = 418,
    misdirected_request = 421,
    unprocessable_entity = 422,
    locked = 423,
    failed_dependency = 424,
    too_early = 425,
    upgrade_required = 426,
    precondition_required = 428,
    too_many_requests = 429,
    request_header_fields_too_large = 431,
    unavailable_for_legal_reasons = 451,

    // 5xx Server Error
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,
    variant_also_negotiates = 506,
    insufficient_storage = 507,
    loop_detected = 508,
    not_extended = 510,
    network_authentication_required = 511,

    pub fn class(self: StatusCode) StatusClass {
        const code = @intFromEnum(self);
        return switch (code / 100) {
            1 => .informational,
            2 => .success,
            3 => .redirection,
            4 => .client_error,
            5 => .server_error,
            else => .unknown,
        };
    }

    pub fn phrase(self: StatusCode) []const u8 {
        return switch (self) {
            .continue_100 => "Continue",
            .switching_protocols => "Switching Protocols",
            .processing => "Processing",
            .early_hints => "Early Hints",
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .non_authoritative => "Non-Authoritative Information",
            .no_content => "No Content",
            .reset_content => "Reset Content",
            .partial_content => "Partial Content",
            .multiple_choices => "Multiple Choices",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .see_other => "See Other",
            .not_modified => "Not Modified",
            .use_proxy => "Use Proxy",
            .temporary_redirect => "Temporary Redirect",
            .permanent_redirect => "Permanent Redirect",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .payment_required => "Payment Required",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .not_acceptable => "Not Acceptable",
            .proxy_authentication_required => "Proxy Authentication Required",
            .request_timeout => "Request Timeout",
            .conflict => "Conflict",
            .gone => "Gone",
            .length_required => "Length Required",
            .precondition_failed => "Precondition Failed",
            .payload_too_large => "Payload Too Large",
            .uri_too_long => "URI Too Long",
            .unsupported_media_type => "Unsupported Media Type",
            .range_not_satisfiable => "Range Not Satisfiable",
            .expectation_failed => "Expectation Failed",
            .im_a_teapot => "I'm a teapot",
            .misdirected_request => "Misdirected Request",
            .unprocessable_entity => "Unprocessable Entity",
            .locked => "Locked",
            .failed_dependency => "Failed Dependency",
            .too_early => "Too Early",
            .upgrade_required => "Upgrade Required",
            .precondition_required => "Precondition Required",
            .too_many_requests => "Too Many Requests",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .unavailable_for_legal_reasons => "Unavailable For Legal Reasons",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .gateway_timeout => "Gateway Timeout",
            .http_version_not_supported => "HTTP Version Not Supported",
            .variant_also_negotiates => "Variant Also Negotiates",
            .insufficient_storage => "Insufficient Storage",
            .loop_detected => "Loop Detected",
            .not_extended => "Not Extended",
            .network_authentication_required => "Network Authentication Required",
        };
    }
};

pub const StatusClass = enum {
    informational,
    success,
    redirection,
    client_error,
    server_error,
    unknown,
};

/// HPACK encoder for HTTP/2 header compression
const HpackEncoder = struct {
    dynamic_table: ArrayList(http2.HeaderEntry),
    max_table_size: u32,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, max_table_size: u32) Self {
        return Self{
            .dynamic_table = ArrayList(http2.HeaderEntry).init(allocator),
            .max_table_size = max_table_size,
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

    /// Encode headers using HPACK compression
    pub fn encode(self: *Self, headers: []const http2.HeaderEntry) ![]u8 {
        var output = std.ArrayList(u8).init(self.allocator);
        defer output.deinit();

        for (headers) |header| {
            // For simplicity, use literal header field without indexing
            // In a production implementation, would check static/dynamic tables first

            // Header field without indexing (pattern: 0000xxxx)
            try output.append(0x00);

            // Encode header name
            try self.encodeString(&output, header.name, false);

            // Encode header value
            try self.encodeString(&output, header.value, false);
        }

        return try output.toOwnedSlice();
    }

    fn encodeString(self: *Self, output: *std.ArrayList(u8), str: []const u8, huffman: bool) !void {
        if (huffman) {
            // For now, don't use Huffman encoding - just set length with H=0
            try self.encodeInteger(output, str.len, 7, 0x00);
        } else {
            // Literal string encoding (H=0)
            try self.encodeInteger(output, str.len, 7, 0x00);
        }

        try output.appendSlice(str);
    }

    fn encodeInteger(self: *Self, output: *std.ArrayList(u8), value: usize, prefix_bits: u8, flags: u8) !void {
        _ = self;

        const max_prefix = (@as(usize, 1) << @intCast(prefix_bits)) - 1;

        if (value < max_prefix) {
            try output.append(@intCast(flags | value));
        } else {
            try output.append(@intCast(flags | max_prefix));
            var remaining = value - max_prefix;

            while (remaining >= 128) {
                try output.append(@intCast((remaining % 128) | 0x80));
                remaining /= 128;
            }
            try output.append(@intCast(remaining));
        }
    }
};

/// Unified HTTP headers
pub const Headers = struct {
    map: HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .map = HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var map_iter = self.map.iterator();
        while (map_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
    }

    pub fn set(self: *Self, key: []const u8, value: []const u8) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        const value_copy = try self.allocator.dupe(u8, value);

        // Convert key to lowercase for case-insensitive comparison
        for (key_copy) |*c| {
            c.* = std.ascii.toLower(c.*);
        }

        // Free old values if they exist
        if (self.map.fetchRemove(key_copy)) |old_entry| {
            self.allocator.free(old_entry.key);
            self.allocator.free(old_entry.value);
        }

        try self.map.put(key_copy, value_copy);
    }

    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        var lower_key: [256]u8 = undefined;
        if (key.len > lower_key.len) return null;

        for (key, 0..) |c, i| {
            lower_key[i] = std.ascii.toLower(c);
        }

        return self.map.get(lower_key[0..key.len]);
    }

    pub fn has(self: *const Self, key: []const u8) bool {
        return self.get(key) != null;
    }

    pub fn remove(self: *Self, key: []const u8) bool {
        var lower_key: [256]u8 = undefined;
        if (key.len > lower_key.len) return false;

        for (key, 0..) |c, i| {
            lower_key[i] = std.ascii.toLower(c);
        }

        if (self.map.fetchRemove(lower_key[0..key.len])) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value);
            return true;
        }
        return false;
    }

    pub fn count(self: *const Self) u32 {
        return @intCast(self.map.count());
    }

    pub fn iter(self: *const Self) @TypeOf(self.map.iterator()) {
        return self.map.iterator();
    }
};

/// Unified HTTP request
pub const Request = struct {
    method: Method,
    uri: []const u8,
    version: HttpVersion,
    headers: Headers,
    body: ?[]const u8,

    const Self = @This();

    pub fn init(allocator: Allocator, method: Method, uri: []const u8) Self {
        return Self{
            .method = method,
            .uri = uri,
            .version = .http_3_0, // Default to HTTP/3
            .headers = Headers.init(allocator),
            .body = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
    }

    pub fn setHeader(self: *Self, key: []const u8, value: []const u8) !void {
        try self.headers.set(key, value);
    }

    pub fn setBody(self: *Self, body: []const u8) void {
        self.body = body;
    }

    pub fn getContentLength(self: *const Self) ?u64 {
        if (self.headers.get("content-length")) |value| {
            return std.fmt.parseInt(u64, value, 10) catch null;
        }
        return null;
    }

    pub fn getContentType(self: *const Self) ?[]const u8 {
        return self.headers.get("content-type");
    }

    pub fn isKeepAlive(self: *const Self) bool {
        if (self.headers.get("connection")) |conn| {
            return !std.ascii.eqlIgnoreCase(conn, "close");
        }
        // HTTP/1.1+ defaults to keep-alive
        return switch (self.version) {
            .http_1_0 => false,
            .http_1_1, .http_2_0, .http_3_0 => true,
        };
    }
};

/// Unified HTTP response
pub const Response = struct {
    status: StatusCode,
    version: HttpVersion,
    headers: Headers,
    body: ?[]const u8,
    allocator: Allocator,
    body_owned: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, status: StatusCode) Self {
        return Self{
            .status = status,
            .version = .http_3_0, // Default to HTTP/3
            .headers = Headers.init(allocator),
            .body = null,
            .allocator = allocator,
            .body_owned = false,
        };
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        if (self.body_owned and self.body != null) {
            self.allocator.free(self.body.?);
        }
    }

    pub fn setHeader(self: *Self, key: []const u8, value: []const u8) !void {
        try self.headers.set(key, value);
    }

    pub fn setBody(self: *Self, body: []const u8) void {
        self.body = body;
    }

    pub fn isSuccessful(self: *const Self) bool {
        return self.status.class() == .success;
    }

    pub fn isRedirect(self: *const Self) bool {
        return self.status.class() == .redirection;
    }

    pub fn isClientError(self: *const Self) bool {
        return self.status.class() == .client_error;
    }

    pub fn isServerError(self: *const Self) bool {
        return self.status.class() == .server_error;
    }
};

/// Connection pool for reusing connections
pub const ConnectionPool = struct {
    http2_connections: ArrayList(*http2.Connection),
    http3_connections: ArrayList(*http3.QuicConnection),
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .http2_connections = ArrayList(*http2.Connection).init(allocator),
            .http3_connections = ArrayList(*http3.QuicConnection).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up all connections
        for (self.http2_connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        for (self.http3_connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }

        self.http2_connections.deinit();
        self.http3_connections.deinit();
    }
};

/// HTTP client with unified API
pub const Client = struct {
    allocator: Allocator,
    pool: ConnectionPool,
    default_version: HttpVersion,
    timeout_ms: u32,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .pool = ConnectionPool.init(allocator),
            .default_version = .http_3_0, // Default to HTTP/3
            .timeout_ms = 30000, // 30 second timeout
        };
    }

    pub fn deinit(self: *Self) void {
        self.pool.deinit();
    }

    pub fn setDefaultVersion(self: *Self, version: HttpVersion) void {
        self.default_version = version;
    }

    pub fn setTimeout(self: *Self, timeout_ms: u32) void {
        self.timeout_ms = timeout_ms;
    }

    /// Send HTTP request with automatic protocol negotiation
    pub fn send(self: *Self, request: *Request) !Response {
        // Try HTTP/3 first (default), then fallback to HTTP/2, then HTTP/1.1
        const attempted_versions = [_]HttpVersion{ .http_3_0, .http_2_0, .http_1_1 };

        for (attempted_versions) |version| {
            if (self.attemptRequest(request, version)) |response| {
                return response;
            } else |err| {
                // Log error and try next version
                std.log.debug("Failed to send request with {s}: {}", .{ version.toString(), err });
                continue;
            }
        }

        return error.AllProtocolsFailed;
    }

    /// Attempt to send request using specific HTTP version
    fn attemptRequest(self: *Self, request: *Request, version: HttpVersion) !Response {
        request.version = version;

        return switch (version) {
            .http_1_0, .http_1_1 => self.sendHttp1(request),
            .http_2_0 => self.sendHttp2(request),
            .http_3_0 => self.sendHttp3(request),
        };
    }

    fn sendHttp1(self: *Self, request: *Request) !Response {
        // Parse URI to extract host, port, and path
        const uri_info = try self.parseUri(request.uri);
        defer self.allocator.free(uri_info.host);
        defer self.allocator.free(uri_info.path);

        // Create socket connection
        const address = try net.Address.resolveIp(uri_info.host, uri_info.port);
        var socket_manager = SocketManager.init(self.allocator);
        defer socket_manager.deinit();

        // Establish connection
        const protocol = Protocol{
            .onReady = null,
            .onData = null,
            .onError = null,
            .onClose = null,
        };

        const socket = try socket_manager.connect(SocketAddress.fromStdAddress(address), protocol);
        defer socket_manager.closeSocket(socket.uuid) catch {};

        // Build HTTP/1.1 request
        const request_data = try self.buildHttp1Request(request, uri_info);
        defer self.allocator.free(request_data);

        // Send request
        try socket_manager.writeSocket(socket.uuid, request_data, null);

        // Read response with timeout
        const response_data = try self.readHttpResponse(socket, 30000); // 30 second timeout
        defer self.allocator.free(response_data);

        // Parse response
        return try self.parseHttp1Response(response_data);
    }

    fn sendHttp2(self: *Self, request: *Request) !Response {
        // Parse URI for connection details
        const uri_info = try self.parseUri(request.uri);
        defer self.allocator.free(uri_info.host);
        defer self.allocator.free(uri_info.path);

        // HTTP/2 requires TLS for most implementations
        if (!uri_info.is_https) {
            return error.Http2RequiresTls;
        }

        // Create HTTP/2 connection with ALPN negotiation
        var http2_conn = try self.createHttp2Connection(uri_info);
        defer http2_conn.deinit();

        // Send HTTP/2 request using binary framing
        const stream_id = try http2_conn.sendRequest(request, uri_info);

        // Read HTTP/2 response frames
        return try http2_conn.readResponse(stream_id);
    }

    fn sendHttp3(self: *Self, request: *Request) !Response {
        // Parse URI for QUIC connection
        const uri_info = try self.parseUri(request.uri);
        defer self.allocator.free(uri_info.host);
        defer self.allocator.free(uri_info.path);

        // HTTP/3 requires HTTPS
        if (!uri_info.is_https) {
            return error.Http3RequiresHttps;
        }

        // Create QUIC transport connection
        const local_addr = try net.Address.parseIp4("0.0.0.0", 0);
        const remote_addr = try net.Address.resolveIp(uri_info.host, uri_info.port);
        
        var quic_transport = try http3.QuicTransport.init(self.allocator, local_addr, remote_addr);
        defer quic_transport.deinit();

        // Establish QUIC connection with TLS handshake
        try quic_transport.connect();

        // Convert HTTP headers to QPACK format
        var qpack_headers = try self.convertHeadersToQpack(request, uri_info);
        defer self.deallocateQpackHeaders(&qpack_headers);

        // Send HTTP/3 request
        const stream_id = try quic_transport.connection.sendRequest(
            request.method.toString(),
            uri_info.path,
            qpack_headers.items,
            request.body
        );

        // Read HTTP/3 response
        var http3_response = try quic_transport.connection.readResponse(stream_id);
        defer http3_response.deinit();

        // Convert HTTP/3 response to unified response format
        return try self.convertHttp3Response(http3_response);
    }

    /// Convert HTTP request headers to QPACK format for HTTP/3
    fn convertHeadersToQpack(self: *Self, request: *Request, uri_info: UriInfo) !std.ArrayList(http3.QpackDecoder.QpackEntry) {
        var qpack_headers = std.ArrayList(http3.QpackDecoder.QpackEntry).init(self.allocator);
        errdefer self.deallocateQpackHeaders(&qpack_headers);

        // Add mandatory pseudo-headers for HTTP/3
        try qpack_headers.append(http3.QpackDecoder.QpackEntry{
            .name = try self.allocator.dupe(u8, ":method"),
            .value = try self.allocator.dupe(u8, request.method.toString()),
        });

        try qpack_headers.append(http3.QpackDecoder.QpackEntry{
            .name = try self.allocator.dupe(u8, ":path"),
            .value = try self.allocator.dupe(u8, uri_info.path),
        });

        try qpack_headers.append(http3.QpackDecoder.QpackEntry{
            .name = try self.allocator.dupe(u8, ":scheme"),
            .value = try self.allocator.dupe(u8, uri_info.scheme),
        });

        try qpack_headers.append(http3.QpackDecoder.QpackEntry{
            .name = try self.allocator.dupe(u8, ":authority"),
            .value = try self.allocator.dupe(u8, uri_info.host),
        });

        // Convert regular headers
        var iterator = request.headers.iter();
        while (iterator.next()) |header| {
            // Convert header name to lowercase for HTTP/3 compatibility
            var lowercase_name = try self.allocator.alloc(u8, header.key_ptr.*.len);
            for (header.key_ptr.*, 0..) |c, i| {
                lowercase_name[i] = std.ascii.toLower(c);
            }

            try qpack_headers.append(http3.QpackDecoder.QpackEntry{
                .name = lowercase_name,
                .value = try self.allocator.dupe(u8, header.value_ptr.*),
            });
        }

        // Add content-length if body is present
        if (request.body) |body| {
            const content_length_str = try std.fmt.allocPrint(self.allocator, "{d}", .{body.len});
            try qpack_headers.append(http3.QpackDecoder.QpackEntry{
                .name = try self.allocator.dupe(u8, "content-length"),
                .value = content_length_str,
            });
        }

        return qpack_headers;
    }

    /// Deallocate QPACK headers 
    fn deallocateQpackHeaders(self: *Self, headers: *std.ArrayList(http3.QpackDecoder.QpackEntry)) void {
        for (headers.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        headers.deinit();
    }

    /// Convert HTTP/3 response to unified response format
    fn convertHttp3Response(self: *Self, http3_response: http3.Http3Response) !Response {
        var response = Response.init(self.allocator, .ok);
        
        // Extract status code from pseudo-header or use default
        response.status = if (http3_response.status > 0) 
            @enumFromInt(http3_response.status) 
        else 
            .ok;

        response.version = .http_3_0;

        // Convert headers from QPACK format
        for (http3_response.headers.items) |qpack_header| {
            // Skip pseudo-headers (they start with ':')
            if (qpack_header.name.len > 0 and qpack_header.name[0] == ':') {
                continue;
            }

            try response.headers.set(qpack_header.name, qpack_header.value);
        }

        // Set response body
        if (http3_response.body.items.len > 0) {
            response.body = try self.allocator.dupe(u8, http3_response.body.items);
            response.body_owned = true;
        }

        return response;
    }

    /// Convenience methods for common HTTP operations
    pub fn get(self: *Self, uri: []const u8) !Response {
        var request = Request.init(self.allocator, .GET, uri);
        defer request.deinit();
        return self.send(&request);
    }

    pub fn post(self: *Self, uri: []const u8, body: ?[]const u8) !Response {
        var request = Request.init(self.allocator, .POST, uri);
        defer request.deinit();
        if (body) |b| request.setBody(b);
        return self.send(&request);
    }

    pub fn put(self: *Self, uri: []const u8, body: ?[]const u8) !Response {
        var request = Request.init(self.allocator, .PUT, uri);
        defer request.deinit();
        if (body) |b| request.setBody(b);
        return self.send(&request);
    }

    pub fn delete(self: *Self, uri: []const u8) !Response {
        var request = Request.init(self.allocator, .DELETE, uri);
        defer request.deinit();
        return self.send(&request);
    }

    // Helper structures and methods for HTTP client implementation

    const UriInfo = struct {
        scheme: []const u8,
        host: []const u8,
        port: u16,
        path: []const u8,
        is_https: bool,
    };

    fn parseUri(self: *Self, uri: []const u8) !UriInfo {
        // Simple URI parsing - in production would use a proper URI parser
        var scheme: []const u8 = "http";
        var is_https = false;
        var remaining = uri;

        // Extract scheme
        if (mem.startsWith(u8, uri, "https://")) {
            scheme = "https";
            is_https = true;
            remaining = uri[8..];
        } else if (mem.startsWith(u8, uri, "http://")) {
            scheme = "http";
            remaining = uri[7..];
        }

        // Find path separator
        const path_start = mem.indexOf(u8, remaining, "/") orelse remaining.len;
        const host_port = remaining[0..path_start];
        const path = if (path_start < remaining.len) remaining[path_start..] else "/";

        // Extract host and port
        var host: []const u8 = undefined;
        var port: u16 = if (is_https) 443 else 80;

        if (mem.indexOf(u8, host_port, ":")) |colon_pos| {
            host = try self.allocator.dupe(u8, host_port[0..colon_pos]);
            port = try std.fmt.parseInt(u16, host_port[colon_pos + 1 ..], 10);
        } else {
            host = try self.allocator.dupe(u8, host_port);
        }

        return UriInfo{
            .scheme = scheme,
            .host = host,
            .port = port,
            .path = try self.allocator.dupe(u8, path),
            .is_https = is_https,
        };
    }

    fn buildHttp1Request(self: *Self, request: *Request, uri_info: UriInfo) ![]u8 {
        var buffer = try Buffer.init(self.allocator);
        defer buffer.deinit();

        // Request line: METHOD path HTTP/1.1
        _ = try buffer.write(request.method.toString());
        _ = try buffer.write(" ");
        _ = try buffer.write(uri_info.path);
        _ = try buffer.write(" HTTP/1.1\r\n");

        // Host header (required for HTTP/1.1)
        _ = try buffer.write("Host: ");
        _ = try buffer.write(uri_info.host);
        if ((uri_info.is_https and uri_info.port != 443) or (!uri_info.is_https and uri_info.port != 80)) {
            _ = try buffer.write(":");
            const port_str = try std.fmt.allocPrint(self.allocator, "{d}", .{uri_info.port});
            defer self.allocator.free(port_str);
            _ = try buffer.write(port_str);
        }
        _ = try buffer.write("\r\n");

        // User-Agent if not set
        if (request.headers.get("user-agent") == null) {
            _ = try buffer.write("User-Agent: Ferret-HTTP-Client/1.0\r\n");
        }

        // Connection header
        if (request.headers.get("connection") == null) {
            _ = try buffer.write("Connection: close\r\n");
        }

        // Content-Length for requests with body
        if (request.body) |body| {
            if (request.headers.get("content-length") == null) {
                const length_str = try std.fmt.allocPrint(self.allocator, "Content-Length: {d}\r\n", .{body.len});
                defer self.allocator.free(length_str);
                _ = try buffer.write(length_str);
            }
        }

        // Other headers
        var header_iter = request.headers.map.iterator();
        while (header_iter.next()) |entry| {
            _ = try buffer.write(entry.key_ptr.*);
            _ = try buffer.write(": ");
            _ = try buffer.write(entry.value_ptr.*);
            _ = try buffer.write("\r\n");
        }

        // Empty line separating headers from body
        _ = try buffer.write("\r\n");

        // Body if present
        if (request.body) |body| {
            _ = try buffer.write(body);
        }

        return try self.allocator.dupe(u8, buffer.readable());
    }

    fn readHttpResponse(self: *Self, socket: Socket, timeout_ms: u32) ![]u8 {
        var response_buffer = try Buffer.init(self.allocator);
        defer response_buffer.deinit();

        // Implement proper socket reading with timeout handling
        var response_data = std.ArrayList(u8).init(self.allocator);
        defer response_data.deinit();

        var buffer: [4096]u8 = undefined;
        var total_read: usize = 0;
        var headers_complete = false;
        var content_length: ?usize = null;
        var headers_end_pos: usize = 0;

        // Read response with timeout
        const start_time = std.time.milliTimestamp();
        const timeout_deadline = start_time + @as(i64, @intCast(timeout_ms));

        while (std.time.milliTimestamp() < timeout_deadline) {
            const bytes_read = socket.read(&buffer) catch |err| switch (err) {
                error.WouldBlock => {
                    std.time.sleep(1_000_000); // Sleep 1ms
                    continue;
                },
                else => return err,
            };

            if (bytes_read == 0) break; // Connection closed

            try response_data.appendSlice(buffer[0..bytes_read]);
            total_read += bytes_read;

            // Check if headers are complete
            if (!headers_complete) {
                if (std.mem.indexOf(u8, response_data.items, "\r\n\r\n")) |pos| {
                    headers_complete = true;
                    headers_end_pos = pos + 4;

                    // Parse Content-Length if present
                    const headers_only = response_data.items[0..pos];
                    if (std.mem.indexOf(u8, headers_only, "Content-Length:")) |cl_pos| {
                        const line_start = cl_pos;
                        const line_end = std.mem.indexOf(u8, headers_only[line_start..], "\r\n") orelse headers_only.len - line_start;
                        const cl_line = headers_only[line_start .. line_start + line_end];

                        if (std.mem.indexOf(u8, cl_line, ":")) |colon_pos| {
                            const value_start = colon_pos + 1;
                            while (value_start < cl_line.len and cl_line[value_start] == ' ') {
                                // Skip spaces
                            }
                            const cl_str = std.mem.trim(u8, cl_line[colon_pos + 1 ..], " \t");
                            content_length = std.fmt.parseInt(usize, cl_str, 10) catch null;
                        }
                    }
                }
            }

            // Check if we have complete response
            if (headers_complete) {
                if (content_length) |cl| {
                    const body_bytes = total_read - headers_end_pos;
                    if (body_bytes >= cl) {
                        break; // Complete response received
                    }
                } else {
                    // No Content-Length, assume response is complete for now
                    // In real implementation, would handle chunked encoding
                    break;
                }
            }
        }

        if (total_read == 0) {
            return error.Timeout;
        }

        return try self.allocator.dupe(u8, response_data.items);
    }

    fn parseHttp1Response(self: *Self, response_data: []const u8) !Response {
        var parser = http1.Parser.init();

        const parsed = try parser.parse(response_data);
        var response = Response.init(self.allocator, parsed.status);

        // Copy headers
        for (parsed.headers) |header| {
            try response.setHeader(header.name, header.value);
        }

        // Set body if present
        if (parsed.body.len > 0) {
            const body_copy = try self.allocator.dupe(u8, parsed.body);
            response.setBody(body_copy);
        }

        response.version = .http_1_1;
        return response;
    }

    // HTTP/2 connection implementation with binary framing and HPACK compression
    const Http2Connection = struct {
        allocator: Allocator,
        socket_manager: *SocketManager,
        socket: Socket,
        connection: http2.Connection,
        hpack_encoder: HpackEncoder,
        next_stream_id: u31,
        connection_window: i32,
        streams: std.HashMap(u31, Http2StreamState, std.hash_map.AutoContext(u31), std.hash_map.default_max_load_percentage),
        local_settings: http2.Settings,
        peer_settings: http2.Settings,

        const Http2StreamState = struct {
            window_size: i32,
            headers_complete: bool,
            end_stream_received: bool,
            response_headers: ArrayList(http2.HeaderEntry),
            response_data: ArrayList(u8),
            reset_error_code: ?http2.ErrorCode,
        };

        fn init(allocator: Allocator, socket_manager: *SocketManager, socket: Socket) Http2Connection {
            return Http2Connection{
                .allocator = allocator,
                .socket_manager = socket_manager,
                .socket = socket,
                .connection = http2.Connection.init(allocator, false), // false = client
                .hpack_encoder = HpackEncoder.init(allocator, 4096),
                .next_stream_id = 1, // Client uses odd stream IDs
                .connection_window = 65535,
                .streams = std.HashMap(u31, Http2StreamState, std.hash_map.AutoContext(u31), std.hash_map.default_max_load_percentage).init(allocator),
                .local_settings = http2.Settings.getDefaultSettings(),
                .peer_settings = http2.Settings.getDefaultSettings(),
            };
        }

        fn deinit(self: *Http2Connection) void {
            // Clean up streams
            var stream_iter = self.streams.iterator();
            while (stream_iter.next()) |entry| {
                for (entry.value_ptr.response_headers.items) |header| {
                    self.allocator.free(header.name);
                    self.allocator.free(header.value);
                }
                entry.value_ptr.response_headers.deinit();
                entry.value_ptr.response_data.deinit();
            }
            self.streams.deinit();

            self.hpack_encoder.deinit();
            self.connection.deinit();
        }

        fn sendConnectionPreface(self: *Http2Connection) !void {
            // Send HTTP/2 connection preface
            try self.socket_manager.writeSocket(self.socket.uuid, http2.CONNECTION_PREFACE, null);

            // Send initial SETTINGS frame
            const settings_frame = try self.buildSettingsFrame();
            defer self.allocator.free(settings_frame);
            try self.socket_manager.writeSocket(self.socket.uuid, settings_frame, null);
        }

        fn buildSettingsFrame(self: *Http2Connection) ![]u8 {
            var settings_buffer = std.ArrayList(u8).init(self.allocator);
            defer settings_buffer.deinit();

            // Build settings payload
            var settings_data = std.ArrayList(u8).init(self.allocator);
            defer settings_data.deinit();

            // SETTINGS_HEADER_TABLE_SIZE (default 4096)
            try settings_data.appendSlice(&mem.toBytes(@as(u16, @intFromEnum(http2.SettingsId.header_table_size)), .big));
            try settings_data.appendSlice(&mem.toBytes(@as(u32, 4096), .big));

            // SETTINGS_ENABLE_PUSH (false for client)
            try settings_data.appendSlice(&mem.toBytes(@as(u16, @intFromEnum(http2.SettingsId.enable_push)), .big));
            try settings_data.appendSlice(&mem.toBytes(@as(u32, 0), .big));

            // SETTINGS_MAX_FRAME_SIZE
            try settings_data.appendSlice(&mem.toBytes(@as(u16, @intFromEnum(http2.SettingsId.max_frame_size)), .big));
            try settings_data.appendSlice(&mem.toBytes(@as(u32, 16384), .big));

            // Create SETTINGS frame
            const frame = http2.Frame.settings(settings_data.items, false);

            // Serialize frame
            const frame_writer = settings_buffer.writer();
            try frame.serialize(frame_writer);

            return try settings_buffer.toOwnedSlice();
        }

        fn sendRequest(self: *Http2Connection, request: *Request, uri_info: UriInfo) !u31 {
            const stream_id = self.next_stream_id;
            self.next_stream_id += 2; // Client uses odd stream IDs

            // Initialize stream state
            const stream_state = Http2StreamState{
                .window_size = 65535,
                .headers_complete = false,
                .end_stream_received = false,
                .response_headers = ArrayList(http2.HeaderEntry).init(self.allocator),
                .response_data = ArrayList(u8).init(self.allocator),
                .reset_error_code = null,
            };
            try self.streams.put(stream_id, stream_state);

            // Build HTTP/2 request headers using HPACK compression
            const header_block = try self.buildRequestHeaders(request, uri_info);
            defer self.allocator.free(header_block);

            // Create and send HEADERS frame
            const end_stream = (request.body == null);
            const headers_frame = http2.Frame.headers(stream_id, header_block, end_stream, true);

            var frame_buffer = std.ArrayList(u8).init(self.allocator);
            defer frame_buffer.deinit();
            const frame_writer = frame_buffer.writer();
            try headers_frame.serialize(frame_writer);

            try self.socket_manager.writeSocket(self.socket.uuid, frame_buffer.items, null);

            // Send DATA frame if request has body
            if (request.body) |body| {
                const data_frame = http2.Frame.data(stream_id, body, true);

                frame_buffer.clearRetainingCapacity();
                try data_frame.serialize(frame_writer);
                try self.socket_manager.writeSocket(self.socket.uuid, frame_buffer.items, null);
            }

            return stream_id;
        }

        fn buildRequestHeaders(self: *Http2Connection, request: *Request, uri_info: UriInfo) ![]u8 {
            var headers = ArrayList(http2.HeaderEntry).init(self.allocator);
            defer {
                for (headers.items) |header| {
                    self.allocator.free(header.name);
                    self.allocator.free(header.value);
                }
                headers.deinit();
            }

            // Add HTTP/2 pseudo-headers
            try headers.append(.{ .name = try self.allocator.dupe(u8, ":method"), .value = try self.allocator.dupe(u8, request.method.toString()) });
            try headers.append(.{ .name = try self.allocator.dupe(u8, ":path"), .value = try self.allocator.dupe(u8, uri_info.path) });
            try headers.append(.{ .name = try self.allocator.dupe(u8, ":scheme"), .value = try self.allocator.dupe(u8, if (uri_info.is_https) "https" else "http") });
            try headers.append(.{ .name = try self.allocator.dupe(u8, ":authority"), .value = try self.allocator.dupe(u8, uri_info.host) });

            // Add regular headers
            var header_iter = request.headers.iter();
            while (header_iter.next()) |entry| {
                // Skip headers that are handled by HTTP/2 pseudo-headers or connection-specific
                const name_lower = std.ascii.allocLowerString(self.allocator, entry.key_ptr.*) catch continue;
                defer self.allocator.free(name_lower);

                if (mem.eql(u8, name_lower, "host") or
                    mem.eql(u8, name_lower, "connection") or
                    mem.eql(u8, name_lower, "upgrade") or
                    mem.eql(u8, name_lower, "http2-settings"))
                {
                    continue;
                }

                try headers.append(.{ .name = try self.allocator.dupe(u8, entry.key_ptr.*), .value = try self.allocator.dupe(u8, entry.value_ptr.*) });
            }

            // Encode headers using HPACK
            return try self.hpack_encoder.encode(headers.items);
        }

        fn readResponse(self: *Http2Connection, stream_id: u31) !Response {
            // Read HTTP/2 frames until we have a complete response
            while (!self.isResponseComplete(stream_id)) {
                const frame_data = try self.readNextFrame();
                defer self.allocator.free(frame_data);

                try self.processFrame(frame_data);
            }

            // Build response from collected headers and data
            const stream_state = self.streams.get(stream_id) orelse return error.StreamNotFound;

            // Determine status code from :status pseudo-header
            var status_code: StatusCode = .ok;
            for (stream_state.response_headers.items) |header| {
                if (mem.eql(u8, header.name, ":status")) {
                    const status_int = std.fmt.parseInt(u16, header.value, 10) catch 200;
                    status_code = @enumFromInt(status_int);
                    break;
                }
            }

            var response = Response.init(self.allocator, status_code);
            response.version = .http_2_0;

            // Copy headers (skip pseudo-headers)
            for (stream_state.response_headers.items) |header| {
                if (!mem.startsWith(u8, header.name, ":")) {
                    try response.setHeader(header.name, header.value);
                }
            }

            // Set response body if present
            if (stream_state.response_data.items.len > 0) {
                const body_copy = try self.allocator.dupe(u8, stream_state.response_data.items);
                response.setBody(body_copy);
            }

            return response;
        }

        fn isResponseComplete(self: *Http2Connection, stream_id: u31) bool {
            const stream_state = self.streams.get(stream_id) orelse return false;
            return stream_state.headers_complete and stream_state.end_stream_received;
        }

        fn readNextFrame(self: *Http2Connection) ![]u8 {
            // Read frame header (9 bytes)
            var header_buffer: [9]u8 = undefined;
            _ = try self.socket.read(&header_buffer);

            const frame_header = http2.FrameHeader.parse(&header_buffer) orelse return error.InvalidFrameHeader;

            // Read frame payload
            var frame_data = try self.allocator.alloc(u8, 9 + frame_header.length);
            @memcpy(frame_data[0..9], &header_buffer);

            if (frame_header.length > 0) {
                _ = try self.socket.read(frame_data[9..]);
            }

            return frame_data;
        }

        fn processFrame(self: *Http2Connection, frame_data: []const u8) !void {
            const frame_header = http2.FrameHeader.parse(frame_data) orelse return error.InvalidFrameHeader;
            const payload = frame_data[9..];

            switch (frame_header.frame_type) {
                .headers => try self.processHeadersFrame(frame_header, payload),
                .data => try self.processDataFrame(frame_header, payload),
                .settings => try self.processSettingsFrame(frame_header, payload),
                .window_update => try self.processWindowUpdateFrame(frame_header, payload),
                .rst_stream => try self.processRstStreamFrame(frame_header, payload),
                .ping => try self.processPingFrame(frame_header, payload),
                .goaway => try self.processGoawayFrame(frame_header, payload),
                else => {
                    // Unknown frame type - ignore per RFC 7540
                    std.log.debug("Received unknown frame type: {}", .{@intFromEnum(frame_header.frame_type)});
                },
            }
        }

        fn processHeadersFrame(self: *Http2Connection, frame_header: http2.FrameHeader, payload: []const u8) !void {
            const stream_state = self.streams.getPtr(frame_header.stream_id) orelse return error.StreamNotFound;

            // Decode HPACK headers
            try self.connection.hpack_decoder.decode(payload, &stream_state.response_headers);

            if (frame_header.flags.endHeaders()) {
                stream_state.headers_complete = true;
            }

            if (frame_header.flags.endStream()) {
                stream_state.end_stream_received = true;
            }
        }

        fn processDataFrame(self: *Http2Connection, frame_header: http2.FrameHeader, payload: []const u8) !void {
            const stream_state = self.streams.getPtr(frame_header.stream_id) orelse return error.StreamNotFound;

            // Append data to response body
            try stream_state.response_data.appendSlice(payload);

            if (frame_header.flags.endStream()) {
                stream_state.end_stream_received = true;
            }

            // Send WINDOW_UPDATE for flow control
            if (payload.len > 0) {
                try self.sendWindowUpdate(frame_header.stream_id, @intCast(payload.len));
                try self.sendWindowUpdate(0, @intCast(payload.len)); // Connection-level window update
            }
        }

        fn processSettingsFrame(self: *Http2Connection, frame_header: http2.FrameHeader, payload: []const u8) !void {
            if (frame_header.flags.ack()) {
                // SETTINGS ACK - nothing to do
                return;
            }

            // Process settings and send ACK
            try self.parseAndApplySettings(payload);

            const ack_frame = http2.Frame.settings(&[_]u8{}, true);
            var frame_buffer = std.ArrayList(u8).init(self.allocator);
            defer frame_buffer.deinit();
            const frame_writer = frame_buffer.writer();
            try ack_frame.serialize(frame_writer);
            try self.socket_manager.writeSocket(self.socket.uuid, frame_buffer.items, null);
        }

        fn parseAndApplySettings(self: *Http2Connection, payload: []const u8) !void {
            // RFC 7540: SETTINGS frame payload must be a multiple of 6 bytes
            if (payload.len % 6 != 0) {
                return error.InvalidSettingsFrame;
            }

            // Store previous settings for rollback if needed
            const previous_settings = self.peer_settings;
            var changes_applied: u32 = 0;

            var offset: usize = 0;
            while (offset < payload.len) {
                const setting_id = mem.readInt(u16, payload[offset .. offset + 2][0..2], .big);
                const setting_value = mem.readInt(u32, payload[offset + 2 .. offset + 6][0..4], .big);
                offset += 6;

                // Apply settings with comprehensive validation
                const result = self.applySingleSetting(setting_id, setting_value);
                if (result) |_| {
                    changes_applied += 1;
                    std.log.debug("Applied HTTP/2 setting: ID={}, value={}", .{ setting_id, setting_value });
                } else |err| switch (err) {
                    error.FlowControlError, error.ProtocolError => {
                        self.peer_settings = previous_settings; // Rollback
                        return err;
                    },
                    else => return err,
                }
            }

            std.log.info("Successfully applied {} HTTP/2 settings", .{changes_applied});

            // Apply side effects after all settings are validated
            try self.handleSettingsChanges(previous_settings);
        }

        fn applySingleSetting(self: *Http2Connection, setting_id: u16, setting_value: u32) !void {
            switch (setting_id) {
                @intFromEnum(http2.SettingsId.header_table_size) => {
                    // RFC 7540: No specific limit, but we impose reasonable bounds
                    if (setting_value > 1024 * 1024) { // 1MB limit
                        return error.ProtocolError;
                    }
                    self.peer_settings.header_table_size = setting_value;
                },
                @intFromEnum(http2.SettingsId.enable_push) => {
                    // RFC 7540: Must be 0 (disabled) or 1 (enabled)
                    if (setting_value > 1) {
                        return error.ProtocolError;
                    }
                    self.peer_settings.enable_push = setting_value != 0;
                },
                @intFromEnum(http2.SettingsId.max_concurrent_streams) => {
                    // RFC 7540: No specific limit
                    self.peer_settings.max_concurrent_streams = setting_value;
                },
                @intFromEnum(http2.SettingsId.initial_window_size) => {
                    // RFC 7540: Must not exceed 2^31-1 (flow control)
                    if (setting_value > 0x7FFFFFFF) {
                        return error.FlowControlError;
                    }
                    self.peer_settings.initial_window_size = setting_value;
                },
                @intFromEnum(http2.SettingsId.max_frame_size) => {
                    // RFC 7540: Between 2^14 (16384) and 2^24-1 (16777215)
                    if (setting_value < 16384 or setting_value > 16777215) {
                        return error.ProtocolError;
                    }
                    self.peer_settings.max_frame_size = setting_value;
                },
                @intFromEnum(http2.SettingsId.max_header_list_size) => {
                    // RFC 7540: Advisory limit, no specific bounds but we impose reasonable ones
                    if (setting_value > 10 * 1024 * 1024) { // 10MB limit
                        return error.ProtocolError;
                    }
                    self.peer_settings.max_header_list_size = setting_value;
                },
                else => {
                    // RFC 7540: Ignore unknown settings identifiers
                    std.log.debug("Ignoring unknown HTTP/2 setting ID: {}", .{setting_id});
                },
            }
        }

        fn handleSettingsChanges(self: *Http2Connection, previous_settings: http2.Settings) !void {
            // Handle INITIAL_WINDOW_SIZE changes - adjust existing stream windows
            if (self.peer_settings.initial_window_size != previous_settings.initial_window_size) {
                const window_delta = @as(i64, self.peer_settings.initial_window_size) - @as(i64, previous_settings.initial_window_size);

                var stream_iter = self.streams.iterator();
                while (stream_iter.next()) |entry| {
                    const stream_state = entry.value_ptr;
                    const new_window = @as(i64, stream_state.window_size) + window_delta;

                    // RFC 7540: Window size must not exceed 2^31-1
                    if (new_window > 0x7FFFFFFF or new_window < -0x80000000) {
                        std.log.err("Stream {} window size overflow: {} + {} = {}", .{ entry.key_ptr.*, stream_state.window_size, window_delta, new_window });
                        return error.FlowControlError;
                    }

                    stream_state.window_size = @intCast(new_window);
                    std.log.debug("Updated stream {} window size by {}: {} -> {}", .{ entry.key_ptr.*, window_delta, stream_state.window_size - @as(i32, @intCast(window_delta)), stream_state.window_size });
                }
            }

            // Handle HEADER_TABLE_SIZE changes - resize HPACK encoder/decoder
            if (self.peer_settings.header_table_size != previous_settings.header_table_size) {
                // Update HPACK encoder dynamic table size
                self.hpack_encoder.max_table_size = self.peer_settings.header_table_size;

                // Evict entries if new size is smaller
                while (self.hpack_encoder.dynamic_table.items.len > 0 and
                    self.calculateHpackTableSize() > self.peer_settings.header_table_size)
                {
                    const removed = self.hpack_encoder.dynamic_table.orderedRemove(0);
                    self.allocator.free(removed.name);
                    self.allocator.free(removed.value);
                }

                std.log.debug("Header table size changed: {} -> {}", .{ previous_settings.header_table_size, self.peer_settings.header_table_size });
            }

            // Handle MAX_FRAME_SIZE changes - validate future frame sizes
            if (self.peer_settings.max_frame_size != previous_settings.max_frame_size) {
                std.log.debug("Max frame size changed: {} -> {}", .{ previous_settings.max_frame_size, self.peer_settings.max_frame_size });
            }

            // Handle ENABLE_PUSH changes - track push capability
            if (self.peer_settings.enable_push != previous_settings.enable_push) {
                std.log.info("Server push capability changed: {} -> {}", .{ previous_settings.enable_push, self.peer_settings.enable_push });
            }
        }

        fn calculateHpackTableSize(self: *Http2Connection) u32 {
            var total_size: u32 = 0;
            for (self.hpack_encoder.dynamic_table.items) |entry| {
                // RFC 7541: size = name.len + value.len + 32
                total_size += @intCast(entry.name.len + entry.value.len + 32);
            }
            return total_size;
        }

        fn processWindowUpdateFrame(self: *Http2Connection, frame_header: http2.FrameHeader, payload: []const u8) !void {
            if (payload.len != 4) return error.InvalidWindowUpdate;

            const window_increment = mem.readInt(u32, payload[0..4], .big) & 0x7FFFFFFF;

            if (frame_header.stream_id == 0) {
                // Connection-level window update
                self.connection_window += @intCast(window_increment);
            } else {
                // Stream-level window update
                if (self.streams.getPtr(frame_header.stream_id)) |stream_state| {
                    stream_state.window_size += @intCast(window_increment);
                }
            }
        }

        fn processRstStreamFrame(self: *Http2Connection, frame_header: http2.FrameHeader, payload: []const u8) !void {
            if (payload.len != 4) return error.InvalidRstStreamFrame;

            const error_code_value = mem.readInt(u32, payload[0..4], .big);
            const error_code: http2.ErrorCode = @enumFromInt(error_code_value);

            std.log.debug("Received RST_STREAM for stream {}: {s}", .{ frame_header.stream_id, error_code.toString() });

            // Mark stream as closed and store error code
            if (self.streams.getPtr(frame_header.stream_id)) |stream_state| {
                stream_state.end_stream_received = true;
                stream_state.reset_error_code = error_code;
            }
        }

        fn processPingFrame(self: *Http2Connection, frame_header: http2.FrameHeader, payload: []const u8) !void {
            if (frame_header.flags.ack()) {
                // PING ACK - nothing to do
                return;
            }

            // Send PING ACK
            if (payload.len == 8) {
                var ping_data: [8]u8 = undefined;
                @memcpy(&ping_data, payload[0..8]);
                const ping_ack = http2.Frame.ping(ping_data, true);

                var frame_buffer = std.ArrayList(u8).init(self.allocator);
                defer frame_buffer.deinit();
                const frame_writer = frame_buffer.writer();
                try ping_ack.serialize(frame_writer);
                try self.socket_manager.writeSocket(self.socket.uuid, frame_buffer.items, null);
            }
        }

        fn processGoawayFrame(self: *Http2Connection, frame_header: http2.FrameHeader, payload: []const u8) !void {
            _ = frame_header;

            if (payload.len < 8) return error.InvalidGoawayFrame;

            const last_stream_id = mem.readInt(u32, payload[0..4], .big) & 0x7FFFFFFF;
            const error_code_value = mem.readInt(u32, payload[4..8], .big);
            const error_code: http2.ErrorCode = @enumFromInt(error_code_value);
            const debug_data = payload[8..];

            std.log.info("Received GOAWAY: last_stream_id={}, error={s}, debug_len={}", .{ last_stream_id, error_code.toString(), debug_data.len });

            if (debug_data.len > 0) {
                std.log.debug("GOAWAY debug data: {s}", .{debug_data});
            }

            // Mark connection as closing - no new streams can be created
            // Existing streams with ID <= last_stream_id may continue
            self.connection_window = 0; // Prevent further data sending

            // Close all streams with ID > last_stream_id
            var stream_iter = self.streams.iterator();
            while (stream_iter.next()) |entry| {
                if (entry.key_ptr.* > last_stream_id) {
                    entry.value_ptr.end_stream_received = true;
                    entry.value_ptr.reset_error_code = error_code;
                }
            }

            return error.ConnectionTerminated;
        }

        fn sendWindowUpdate(self: *Http2Connection, stream_id: u31, increment: u31) !void {
            const window_frame = http2.Frame.windowUpdate(stream_id, increment);

            var frame_buffer = std.ArrayList(u8).init(self.allocator);
            defer frame_buffer.deinit();
            const frame_writer = frame_buffer.writer();
            try window_frame.serialize(frame_writer);
            try self.socket_manager.writeSocket(self.socket.uuid, frame_buffer.items, null);
        }
    };

    fn createHttp2Connection(self: *Self, uri_info: UriInfo) !Http2Connection {
        // Create socket connection
        const address = try net.Address.resolveIp(uri_info.host, uri_info.port);
        var socket_manager = SocketManager.init(self.allocator);

        // Establish connection
        const protocol = Protocol{
            .onReady = null,
            .onData = null,
            .onError = null,
            .onClose = null,
        };

        const socket = try socket_manager.connect(SocketAddress.fromStdAddress(address), protocol);

        // Initialize HTTP/2 connection
        var http2_conn = Http2Connection.init(self.allocator, &socket_manager, socket);

        // Send connection preface and initial settings
        try http2_conn.sendConnectionPreface();

        return http2_conn;
    }
};

/// HTTP server with unified API
pub const Server = struct {
    allocator: Allocator,
    address: net.Address,
    supported_versions: []const HttpVersion,
    default_version: HttpVersion,
    socket_manager: ?*SocketManager,
    listener_socket: ?Socket,
    is_listening: bool,
    request_handler: ?*const fn (request: *Request, response: *Response) anyerror!void,
    max_connections: u32,
    active_connections: u32,

    const Self = @This();

    pub fn init(allocator: Allocator, address: net.Address) Self {
        const supported = &[_]HttpVersion{ .http_3_0, .http_2_0, .http_1_1 };
        return Self{
            .allocator = allocator,
            .address = address,
            .supported_versions = supported,
            .default_version = .http_3_0,
            .socket_manager = null,
            .listener_socket = null,
            .is_listening = false,
            .request_handler = null,
            .max_connections = 1000,
            .active_connections = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.listener_socket) |socket| {
            socket.close() catch {};
        }
    }

    /// Set the request handler function
    pub fn setRequestHandler(self: *Self, handler: *const fn (request: *Request, response: *Response) anyerror!void) void {
        self.request_handler = handler;
    }

    /// Set maximum concurrent connections
    pub fn setMaxConnections(self: *Self, max: u32) void {
        self.max_connections = max;
    }

    /// Start listening for incoming connections
    pub fn listen(self: *Self, socket_manager: *SocketManager) !void {
        if (self.is_listening) {
            return HttpServerError.AlreadyListening;
        }

        if (self.request_handler == null) {
            return HttpServerError.NoRequestHandler;
        }

        self.socket_manager = socket_manager;

        // Convert net.Address to SocketAddress
        const socket_address = try self.netAddressToSocketAddress(self.address);

        // Create protocol handler for accepting connections
        const protocol = Protocol{
            .onData = handleNewConnection,
            .onError = handleListenerError,
            .onClose = handleListenerClose,
            .user_data = @ptrCast(self),
        };

        // Start listening on the socket
        self.listener_socket = try socket_manager.listen(socket_address, protocol);
        self.is_listening = true;

        std.log.info("HTTP server listening on {any}", .{self.address});
    }

    /// Stop listening and close the server
    pub fn stop(self: *Self) !void {
        if (!self.is_listening) {
            return;
        }

        if (self.listener_socket) |socket| {
            try socket.close();
        }

        self.listener_socket = null;
        self.is_listening = false;
        self.socket_manager = null;

        std.log.info("HTTP server stopped", .{});
    }

    /// Check if server is currently listening
    pub fn isListening(self: *const Self) bool {
        return self.is_listening;
    }

    /// Get current number of active connections
    pub fn getActiveConnections(self: *const Self) u32 {
        return self.active_connections;
    }

    /// Convert net.Address to SocketAddress
    fn netAddressToSocketAddress(self: *const Self, address: net.Address) !SocketAddress {
        _ = self;
        return switch (address.any.family) {
            std.posix.AF.INET => SocketAddress{ .ipv4 = address },
            std.posix.AF.INET6 => SocketAddress{ .ipv6 = address },
            else => SocketError.InvalidAddress,
        };
    }

    /// Handle new incoming connections
    fn handleNewConnection(socket: Socket, data: []const u8) void {
        _ = data; // Accept events don't have data

        // Get server instance from socket user_data
        const server = @as(*Server, @ptrCast(@alignCast(socket.manager.sockets.get(socket.uuid).?.protocol.user_data.?)));

        if (server.active_connections >= server.max_connections) {
            std.log.warn("Maximum connections reached, rejecting new connection", .{});
            return;
        }

        // Accept the new connection
        server.acceptConnection(socket) catch |err| {
            std.log.err("Failed to accept connection: {}", .{err});
        };
    }

    /// Accept and handle a new connection
    fn acceptConnection(self: *Server, listener_socket: Socket) !void {
        const socket_manager = self.socket_manager orelse return HttpServerError.NotListening;

        // Create protocol for handling client data
        const client_protocol = Protocol{
            .onData = handleClientData,
            .onClose = handleClientClose,
            .onError = handleClientError,
            .user_data = @ptrCast(self),
        };

        // Accept the incoming connection
        if (try socket_manager.accept(listener_socket.uuid, client_protocol)) |client_socket| {
            self.active_connections += 1;
            std.log.debug("Accepted new connection, active: {}", .{self.active_connections});

            // Connection will be handled by the reactor through the protocol callbacks
            _ = client_socket;
        }
    }

    /// Handle data from client connections
    fn handleClientData(socket: Socket, data: []const u8) void {
        const server = @as(*Server, @ptrCast(@alignCast(socket.manager.sockets.get(socket.uuid).?.protocol.user_data.?)));

        server.processHttpRequest(socket, data) catch |err| {
            std.log.err("Failed to process HTTP request: {}", .{err});
            socket.close() catch {};
        };
    }

    /// Process HTTP request from client
    fn processHttpRequest(self: *Server, socket: Socket, data: []const u8) !void {
        // Simple HTTP request parsing for demonstration
        // In a production server, you'd want more robust parsing

        // Parse the request line (GET /path HTTP/1.1)
        const request_line_end = std.mem.indexOf(u8, data, "\r\n") orelse {
            // Incomplete request, wait for more data
            return;
        };

        const request_line = data[0..request_line_end];
        var parts = std.mem.splitSequence(u8, request_line, " ");

        const method_str = parts.next() orelse {
            try self.sendErrorResponse(socket, .bad_request);
            return;
        };

        const uri = parts.next() orelse {
            try self.sendErrorResponse(socket, .bad_request);
            return;
        };

        const version_str = parts.next() orelse {
            try self.sendErrorResponse(socket, .bad_request);
            return;
        };

        // Parse method
        const http1_method = http1.Method.fromString(method_str) orelse {
            try self.sendErrorResponse(socket, .method_not_allowed);
            return;
        };

        // Convert to unified method
        const method = switch (http1_method) {
            .GET => Method.GET,
            .POST => Method.POST,
            .PUT => Method.PUT,
            .DELETE => Method.DELETE,
            .HEAD => Method.HEAD,
            .OPTIONS => Method.OPTIONS,
            .PATCH => Method.PATCH,
            .TRACE => Method.TRACE,
            .CONNECT => Method.CONNECT,
        };

        // Parse version
        const version = http1.Version.fromString(version_str) orelse {
            try self.sendErrorResponse(socket, .http_version_not_supported);
            return;
        };

        // Check for end of headers
        const headers_end = std.mem.indexOf(u8, data, "\r\n\r\n");
        if (headers_end == null) {
            // Incomplete request, wait for more data
            return;
        }

        // Create request object
        var request = Request.init(self.allocator, method, uri);
        defer request.deinit();

        // Set HTTP version
        request.version = switch (version) {
            .http_1_0 => .http_1_0,
            .http_1_1 => .http_1_1,
            .http_2_0 => .http_2_0,
        };

        // Parse HTTP headers from the request
        try parseHttpHeaders(self.allocator, &request, data[0..headers_end.?]);

        // Create response object
        var response = Response.init(self.allocator, .ok);
        defer response.deinit();
        response.version = request.version;

        // Call the request handler
        if (self.request_handler) |handler| {
            handler(&request, &response) catch |err| {
                std.log.err("Request handler failed: {}", .{err});
                response.status = .internal_server_error;
                response.setBody("Internal Server Error");
            };
        } else {
            response.status = .not_implemented;
            response.setBody("No request handler configured");
        }

        // Send response back to client
        try self.sendHttpResponse(socket, &response);

        // Close connection for now (could implement keep-alive later)
        try socket.close();
    }

    /// Send error response to client
    fn sendErrorResponse(self: *Server, socket: Socket, status: StatusCode) !void {
        var response = Response.init(self.allocator, status);
        defer response.deinit();

        response.setBody(status.phrase());
        try response.setHeader("Content-Type", "text/plain");
        try response.setHeader("Connection", "close");

        try self.sendHttpResponse(socket, &response);
        try socket.close();
    }

    /// Send HTTP response to client
    fn sendHttpResponse(self: *Server, socket: Socket, response: *const Response) !void {
        var response_buffer = Buffer.init(self.allocator) catch return HttpServerError.OutOfMemory;
        defer response_buffer.deinit();

        // Build HTTP response
        try self.buildHttpResponse(response, &response_buffer);

        // Send response data
        const response_data = response_buffer.readable();
        try socket.write(response_data);
    }

    /// Build HTTP response in buffer
    fn buildHttpResponse(self: *Server, response: *const Response, buffer: *Buffer) !void {
        _ = self;

        // Status line
        const version_str = response.version.toString();
        const status_code = @intFromEnum(response.status);
        const status_phrase = response.status.phrase();

        _ = try buffer.write(version_str);
        _ = try buffer.write(" ");

        // Write status code
        var status_buf: [16]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{}", .{status_code}) catch return HttpServerError.OutOfMemory;
        _ = try buffer.write(status_str);

        _ = try buffer.write(" ");
        _ = try buffer.write(status_phrase);
        _ = try buffer.write("\r\n");

        // Headers
        var header_iter = response.headers.iter();
        while (header_iter.next()) |entry| {
            _ = try buffer.write(entry.key_ptr.*);
            _ = try buffer.write(": ");
            _ = try buffer.write(entry.value_ptr.*);
            _ = try buffer.write("\r\n");
        }

        // Content-Length header if body is present
        if (response.body) |body| {
            var length_buf: [32]u8 = undefined;
            const length_str = std.fmt.bufPrint(&length_buf, "{}", .{body.len}) catch return HttpServerError.OutOfMemory;
            _ = try buffer.write("Content-Length: ");
            _ = try buffer.write(length_str);
            _ = try buffer.write("\r\n");
        }

        // End of headers
        _ = try buffer.write("\r\n");

        // Body
        if (response.body) |body| {
            _ = try buffer.write(body);
        }
    }

    /// Handle client connection close
    fn handleClientClose(socket: Socket) void {
        const server = @as(*Server, @ptrCast(@alignCast(socket.manager.sockets.get(socket.uuid).?.protocol.user_data.?)));
        server.active_connections = @max(server.active_connections - 1, 0);
        std.log.debug("Client disconnected, active: {}", .{server.active_connections});
    }

    /// Handle client connection error
    fn handleClientError(socket: Socket, err: SocketError) void {
        const server = @as(*Server, @ptrCast(@alignCast(socket.manager.sockets.get(socket.uuid).?.protocol.user_data.?)));
        server.active_connections = @max(server.active_connections - 1, 0);
        std.log.warn("Client connection error: {}, active: {}", .{ err, server.active_connections });
    }

    /// Handle listener socket error
    fn handleListenerError(socket: Socket, err: SocketError) void {
        _ = socket;
        std.log.err("Listener socket error: {}", .{err});
    }

    /// Handle listener socket close
    fn handleListenerClose(socket: Socket) void {
        _ = socket;
        std.log.warn("Listener socket closed unexpectedly", .{});
    }

    pub fn setSupportedVersions(self: *Self, versions: []const HttpVersion) void {
        self.supported_versions = versions;
    }

    pub fn setDefaultVersion(self: *Self, version: HttpVersion) void {
        self.default_version = version;
    }
};

// Tests
test "HTTP version utilities" {
    try testing.expect(HttpVersion.http_3_0.supportsMultiplexing());
    try testing.expect(HttpVersion.http_3_0.requiresEncryption());
    try testing.expect(HttpVersion.http_3_0.usesUdp());

    try testing.expect(HttpVersion.http_2_0.supportsMultiplexing());
    try testing.expect(!HttpVersion.http_2_0.usesUdp());

    try testing.expect(!HttpVersion.http_1_1.supportsMultiplexing());
    try testing.expect(!HttpVersion.http_1_1.requiresEncryption());
}

test "HTTP method utilities" {
    try testing.expect(Method.GET.isSafe());
    try testing.expect(Method.GET.isIdempotent());
    try testing.expect(!Method.POST.isSafe());
    try testing.expect(!Method.POST.isIdempotent());

    try testing.expectEqualStrings(Method.GET.toString(), "GET");
    try testing.expect(Method.fromString("POST") == .POST);
    try testing.expect(Method.fromString("INVALID") == null);
}

test "HTTP status code utilities" {
    try testing.expect(StatusCode.ok.class() == .success);
    try testing.expect(StatusCode.not_found.class() == .client_error);
    try testing.expect(StatusCode.internal_server_error.class() == .server_error);

    try testing.expectEqualStrings(StatusCode.ok.phrase(), "OK");
    try testing.expectEqualStrings(StatusCode.not_found.phrase(), "Not Found");
}

test "Unified headers" {
    var headers = Headers.init(testing.allocator);
    defer headers.deinit();

    try headers.set("Content-Type", "application/json");
    try headers.set("content-length", "42");

    try testing.expectEqualStrings(headers.get("content-type").?, "application/json");
    try testing.expectEqualStrings(headers.get("Content-Length").?, "42");
    try testing.expect(headers.has("CONTENT-TYPE"));
    try testing.expect(!headers.has("nonexistent"));

    try testing.expect(headers.count() == 2);
    try testing.expect(headers.remove("content-type"));
    try testing.expect(headers.count() == 1);
}

test "HTTP request creation" {
    var request = Request.init(testing.allocator, .GET, "/test");
    defer request.deinit();

    try testing.expect(request.method == .GET);
    try testing.expectEqualStrings(request.uri, "/test");
    try testing.expect(request.version == .http_3_0); // Default to HTTP/3

    try request.setHeader("User-Agent", "Ferret/1.0");
    try testing.expectEqualStrings(request.headers.get("user-agent").?, "Ferret/1.0");

    request.setBody("{\"test\": true}");
    try testing.expectEqualStrings(request.body.?, "{\"test\": true}");
}

test "HTTP response creation" {
    var response = Response.init(testing.allocator, .ok);
    defer response.deinit();

    try testing.expect(response.status == .ok);
    try testing.expect(response.version == .http_3_0);
    try testing.expect(response.isSuccessful());
    try testing.expect(!response.isClientError());

    try response.setHeader("Content-Type", "text/plain");
    response.setBody("Hello, World!");

    try testing.expectEqualStrings(response.headers.get("content-type").?, "text/plain");
    try testing.expectEqualStrings(response.body.?, "Hello, World!");
}

test "HTTP client initialization" {
    var client = Client.init(testing.allocator);
    defer client.deinit();

    try testing.expect(client.default_version == .http_3_0);
    try testing.expect(client.timeout_ms == 30000);

    client.setDefaultVersion(.http_2_0);
    try testing.expect(client.default_version == .http_2_0);

    client.setTimeout(10000);
    try testing.expect(client.timeout_ms == 10000);
}

test "HTTP server initialization" {
    const address = try net.Address.parseIp4("127.0.0.1", 8080);
    var server = Server.init(testing.allocator, address);
    defer server.deinit();

    try testing.expect(server.default_version == .http_3_0);
    try testing.expect(server.max_connections == 1000);
    try testing.expect(server.active_connections == 0);
    try testing.expect(!server.isListening());

    server.setMaxConnections(500);
    try testing.expect(server.max_connections == 500);

    server.setDefaultVersion(.http_1_1);
    try testing.expect(server.default_version == .http_1_1);
}

test "HTTP server request handler" {
    const address = try net.Address.parseIp4("127.0.0.1", 8080);
    var server = Server.init(testing.allocator, address);
    defer server.deinit();

    // Test handler function
    const TestHandler = struct {
        fn handle(request: *Request, response: *Response) anyerror!void {
            try testing.expect(request.method == .GET);
            response.setBody("Hello, World!");
            try response.setHeader("Content-Type", "text/plain");
        }
    };

    server.setRequestHandler(TestHandler.handle);

    // We can't easily test the actual server listening without a full integration test,
    // but we can verify the handler is set
    try testing.expect(server.request_handler != null);
}

/// Parse HTTP headers from raw request data
/// Handles header folding, case-insensitive names, and proper value trimming
fn parseHttpHeaders(allocator: Allocator, request: *Request, data: []const u8) !void {
    // Find the start of headers (after the request line)
    const request_line_end = std.mem.indexOf(u8, data, "\r\n") orelse return HttpServerError.InvalidRequest;
    var pos = request_line_end + 2; // Skip past "\r\n"

    while (pos < data.len) {
        // Check if we've reached the end of headers
        if (pos + 1 < data.len and data[pos] == '\r' and data[pos + 1] == '\n') {
            break; // End of headers
        }

        // Find end of this header line
        const line_end = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse break;
        const line = data[pos..line_end];

        // Skip folded header continuation lines (they're handled by buildCompleteHeaderValue)
        if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
            pos = line_end + 2;
            continue;
        }

        // Parse header name and value
        const colon_pos = std.mem.indexOf(u8, line, ":") orelse {
            // Invalid header line, skip it
            pos = line_end + 2;
            continue;
        };

        if (colon_pos == 0) {
            // Empty header name, skip
            pos = line_end + 2;
            continue;
        }

        const header_name = line[0..colon_pos];
        const header_value_start = colon_pos + 1;

        // Validate header name first (RFC 7230: token characters only)
        if (!isValidHeaderName(header_name)) {
            pos = line_end + 2;
            continue;
        }

        // Extract and build complete header value (including folded lines)
        // This function will update pos to skip any consumed continuation lines
        const complete_header_value = try buildCompleteHeaderValue(allocator, data, header_value_start, line_end, &pos);
        defer if (complete_header_value.needs_free) allocator.free(complete_header_value.value);

        // Store the header (Headers.set handles case-insensitive storage)
        try request.setHeader(header_name, complete_header_value.value);
    }
}

/// Result of building a complete header value (may include folded content)
const HeaderValueResult = struct {
    value: []const u8,
    needs_free: bool,
};

/// Build complete header value including RFC 7230 header folding support
/// According to RFC 7230: header values can span multiple lines when continuation
/// lines start with SP or HTAB. Folding is unfolded by replacing CRLF 1*(SP/HTAB) with SP.
fn buildCompleteHeaderValue(
    allocator: Allocator,
    data: []const u8,
    value_start: usize,
    first_line_end: usize,
    pos: *usize,
) !HeaderValueResult {
    // Extract initial header value from first line
    const first_line_start = pos.*;
    const first_line = data[first_line_start..first_line_end];

    var initial_value = if (value_start < first_line.len)
        first_line[value_start..]
    else
        "";

    // Trim leading and trailing whitespace from initial value
    initial_value = std.mem.trim(u8, initial_value, " \t");

    // Look ahead to check if there are continuation lines
    var lookahead_pos = first_line_end + 2; // Move past current line's CRLF
    var has_folding = false;

    // Scan for folded lines
    while (lookahead_pos < data.len) {
        // Check for end of headers
        if (lookahead_pos + 1 < data.len and data[lookahead_pos] == '\r' and data[lookahead_pos + 1] == '\n') {
            break; // End of headers section
        }

        // Find end of this potential continuation line
        const continuation_line_end = std.mem.indexOfPos(u8, data, lookahead_pos, "\r\n") orelse break;
        const continuation_line = data[lookahead_pos..continuation_line_end];

        // Check if this is a folded continuation line
        if (continuation_line.len > 0 and (continuation_line[0] == ' ' or continuation_line[0] == '\t')) {
            has_folding = true;
            lookahead_pos = continuation_line_end + 2; // Move to next line
        } else {
            break; // Not a continuation line
        }
    }

    // If no folding, return the simple trimmed value
    if (!has_folding) {
        pos.* = first_line_end + 2; // Move past current line's CRLF
        return HeaderValueResult{
            .value = initial_value,
            .needs_free = false,
        };
    }

    // Build folded header value according to RFC 7230
    var folded_value = std.ArrayList(u8).init(allocator);
    defer folded_value.deinit();

    // Add initial value
    try folded_value.appendSlice(initial_value);

    // Process continuation lines
    var current_pos = first_line_end + 2; // Start after first line's CRLF
    while (current_pos < data.len) {
        // Check for end of headers
        if (current_pos + 1 < data.len and data[current_pos] == '\r' and data[current_pos + 1] == '\n') {
            break;
        }

        // Find end of this line
        const line_end = std.mem.indexOfPos(u8, data, current_pos, "\r\n") orelse break;
        const line = data[current_pos..line_end];

        // Check if this is a continuation line
        if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) {
            // This is a folded continuation line
            // RFC 7230: Replace CRLF 1*(SP/HTAB) with single SP
            try folded_value.append(' ');

            // Add the continuation content, trimming leading whitespace
            const continuation_content = std.mem.trimLeft(u8, line, " \t");
            try folded_value.appendSlice(continuation_content);

            current_pos = line_end + 2; // Move to next line
        } else {
            break; // Not a continuation line, stop processing
        }
    }

    // Update position to after all processed lines
    pos.* = current_pos;

    // Return allocated folded value (caller must free)
    const final_value = try folded_value.toOwnedSlice();
    const trimmed_value = std.mem.trim(u8, final_value, " \t");

    // If trimming removed characters, we need to create a new allocation
    if (trimmed_value.len != final_value.len) {
        const trimmed_copy = try allocator.dupe(u8, trimmed_value);
        allocator.free(final_value); // Free the original allocation
        return HeaderValueResult{
            .value = trimmed_copy,
            .needs_free = true,
        };
    }

    return HeaderValueResult{
        .value = final_value,
        .needs_free = true,
    };
}

/// Validate header name according to RFC 7230 token rules
/// token = 1*tchar
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
fn isValidHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;

    for (name) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
            else => return false,
        }
    }
    return true;
}

test "HTTP header parsing" {
    const test_request =
        "GET /api/users HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "User-Agent: TestAgent/1.0\r\n" ++
        "Accept: application/json\r\n" ++
        "Content-Type: application/x-www-form-urlencoded\r\n" ++
        "Content-Length: 42\r\n" ++
        "Authorization: Bearer token123\r\n" ++
        "X-Custom-Header: custom-value\r\n" ++
        "Cookie: session=abc123; theme=dark\r\n" ++
        "\r\n" ++
        "test body content";

    var request = Request.init(testing.allocator, .GET, "/api/users");
    defer request.deinit();

    try parseHttpHeaders(testing.allocator, &request, test_request);

    // Test that headers were parsed correctly
    try testing.expectEqualStrings("example.com", request.headers.get("Host").?);
    try testing.expectEqualStrings("TestAgent/1.0", request.headers.get("User-Agent").?);
    try testing.expectEqualStrings("application/json", request.headers.get("Accept").?);
    try testing.expectEqualStrings("application/x-www-form-urlencoded", request.headers.get("Content-Type").?);
    try testing.expectEqualStrings("42", request.headers.get("Content-Length").?);
    try testing.expectEqualStrings("Bearer token123", request.headers.get("Authorization").?);
    try testing.expectEqualStrings("custom-value", request.headers.get("X-Custom-Header").?);
    try testing.expectEqualStrings("session=abc123; theme=dark", request.headers.get("Cookie").?);

    // Test case-insensitive access
    try testing.expectEqualStrings("example.com", request.headers.get("host").?);
    try testing.expectEqualStrings("42", request.headers.get("content-length").?);
}

test "HTTP header parsing edge cases" {
    // Test malformed headers, whitespace handling, etc.
    const test_request =
        "GET / HTTP/1.1\r\n" ++
        "Valid-Header: value\r\n" ++
        "Whitespace-Value:   trimmed   \r\n" ++
        ": empty-name\r\n" ++ // Invalid: empty header name
        "No-Colon-Header\r\n" ++ // Invalid: no colon
        "Invalid@Char: value\r\n" ++ // Invalid: @ not allowed in header name
        "Valid-Empty: \r\n" ++ // Valid: empty value
        "\r\n";

    var request = Request.init(testing.allocator, .GET, "/");
    defer request.deinit();

    try parseHttpHeaders(testing.allocator, &request, test_request);

    // Test that valid headers were parsed
    try testing.expectEqualStrings("value", request.headers.get("Valid-Header").?);
    try testing.expectEqualStrings("trimmed", request.headers.get("Whitespace-Value").?);
    try testing.expectEqualStrings("", request.headers.get("Valid-Empty").?);

    // Test that invalid headers were ignored
    try testing.expect(request.headers.get("") == null); // Empty name header
    try testing.expect(request.headers.get("No-Colon-Header") == null);
    try testing.expect(request.headers.get("Invalid@Char") == null);
}

test "HTTP header folding support" {
    // Test RFC 7230 header folding with continuation lines
    const test_request =
        "GET /api/data HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Long-Header: this is a very long header value\r\n" ++
        " that continues on the next line\r\n" ++
        "\t and also continues with a tab prefix\r\n" ++
        "Another-Header: simple value\r\n" ++
        "Multi-Fold: start\r\n" ++
        "  second line\r\n" ++
        "   third line with more spaces\r\n" ++
        "\tfourth line with tab\r\n" ++
        "Normal-Header: normal value\r\n" ++
        "\r\n";

    var request = Request.init(testing.allocator, .GET, "/api/data");
    defer request.deinit();

    try parseHttpHeaders(testing.allocator, &request, test_request);

    // Test that folded headers were correctly unfolded
    try testing.expectEqualStrings("example.com", request.headers.get("Host").?);
    try testing.expectEqualStrings("this is a very long header value that continues on the next line and also continues with a tab prefix", request.headers.get("Long-Header").?);
    try testing.expectEqualStrings("simple value", request.headers.get("Another-Header").?);
    try testing.expectEqualStrings("start second line third line with more spaces fourth line with tab", request.headers.get("Multi-Fold").?);
    try testing.expectEqualStrings("normal value", request.headers.get("Normal-Header").?);
}

test "HTTP header folding edge cases" {
    // Test edge cases for header folding
    const test_request =
        "GET / HTTP/1.1\r\n" ++
        "Empty-Fold: value\r\n" ++
        " \r\n" ++ // Continuation line with only whitespace
        "Whitespace-Only:\r\n" ++
        "  \t  \r\n" ++ // Header with only whitespace in continuation
        "Mixed-Whitespace: start\r\n" ++
        " \t mixed whitespace prefix\r\n" ++
        "Trailing-Space: value with trailing space \r\n" ++
        "  continuation\r\n" ++
        "\r\n";

    var request = Request.init(testing.allocator, .GET, "/");
    defer request.deinit();

    try parseHttpHeaders(testing.allocator, &request, test_request);

    // Test edge case handling
    try testing.expectEqualStrings("value", request.headers.get("Empty-Fold").?);
    try testing.expectEqualStrings("", request.headers.get("Whitespace-Only").?);
    try testing.expectEqualStrings("start mixed whitespace prefix", request.headers.get("Mixed-Whitespace").?);
    try testing.expectEqualStrings("value with trailing space continuation", request.headers.get("Trailing-Space").?);
}

test "HTTP server error handling" {
    const address = try net.Address.parseIp4("127.0.0.1", 8080);
    var server = Server.init(testing.allocator, address);
    defer server.deinit();

    // Test error cases without actually starting server
    try testing.expect(!server.isListening());
    try testing.expect(server.request_handler == null);

    // Set a handler
    const TestHandler = struct {
        fn handle(request: *Request, response: *Response) anyerror!void {
            _ = request;
            response.setBody("OK");
        }
    };
    server.setRequestHandler(TestHandler.handle);

    // Verify handler is set
    try testing.expect(server.request_handler != null);

    // Test that server configuration works
    try testing.expect(server.getActiveConnections() == 0);
    try testing.expect(!server.isListening());
}

test "HTTP/2 Settings parsing - valid settings" {
    var reactor = try Reactor.init(testing.allocator);
    defer reactor.deinit();

    var socket_manager = SocketManager.init(testing.allocator, &reactor);
    defer socket_manager.deinit();

    const socket = Socket{ .uuid = SocketUUID{ .id = 1, .counter = 1 }, .manager = &socket_manager };
    var http2_conn = Client.Http2Connection.init(testing.allocator, &socket_manager, socket);
    defer http2_conn.deinit();

    // Test valid settings frame payload
    var payload = [_]u8{
        // SETTINGS_INITIAL_WINDOW_SIZE = 32768 (0x8000)
        0x00, 0x04, 0x00, 0x00, 0x80, 0x00,
        // SETTINGS_MAX_FRAME_SIZE = 32768 (0x8000)
        0x00, 0x05, 0x00, 0x00, 0x80, 0x00,
        // SETTINGS_ENABLE_PUSH = 0 (disabled)
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    };

    try http2_conn.parseAndApplySettings(&payload);

    // Verify settings were applied
    try testing.expectEqual(@as(u32, 32768), http2_conn.peer_settings.initial_window_size);
    try testing.expectEqual(@as(u32, 32768), http2_conn.peer_settings.max_frame_size);
    try testing.expectEqual(false, http2_conn.peer_settings.enable_push);
}

test "HTTP/2 Settings parsing - invalid payload length" {
    var reactor = try Reactor.init(testing.allocator);
    defer reactor.deinit();

    var socket_manager = SocketManager.init(testing.allocator, &reactor);
    defer socket_manager.deinit();

    const socket = Socket{ .uuid = SocketUUID{ .id = 1, .counter = 1 }, .manager = &socket_manager };
    var http2_conn = Client.Http2Connection.init(testing.allocator, &socket_manager, socket);
    defer http2_conn.deinit();

    // Invalid payload - not multiple of 6 bytes
    var invalid_payload = [_]u8{ 0x00, 0x01, 0x00, 0x00, 0x01 };
    try testing.expectError(error.InvalidSettingsFrame, http2_conn.parseAndApplySettings(&invalid_payload));
}

test "HTTP/2 Settings parsing - flow control error" {
    var reactor = try Reactor.init(testing.allocator);
    defer reactor.deinit();

    var socket_manager = SocketManager.init(testing.allocator, &reactor);
    defer socket_manager.deinit();

    const socket = Socket{ .uuid = SocketUUID{ .id = 1, .counter = 1 }, .manager = &socket_manager };
    var http2_conn = Client.Http2Connection.init(testing.allocator, &socket_manager, socket);
    defer http2_conn.deinit();

    // SETTINGS_INITIAL_WINDOW_SIZE with invalid value (> 2^31-1)
    var payload = [_]u8{
        0x00, 0x04, 0x80, 0x00, 0x00, 0x00, // Invalid window size
    };

    try testing.expectError(error.FlowControlError, http2_conn.parseAndApplySettings(&payload));
}

test "HTTP/2 Settings parsing - protocol error" {
    var reactor = try Reactor.init(testing.allocator);
    defer reactor.deinit();

    var socket_manager = SocketManager.init(testing.allocator, &reactor);
    defer socket_manager.deinit();

    const socket = Socket{ .uuid = SocketUUID{ .id = 1, .counter = 1 }, .manager = &socket_manager };
    var http2_conn = Client.Http2Connection.init(testing.allocator, &socket_manager, socket);
    defer http2_conn.deinit();

    // SETTINGS_MAX_FRAME_SIZE with invalid value (< 16384)
    var payload = [_]u8{
        0x00, 0x05, 0x00, 0x00, 0x10, 0x00, // 4096 < 16384
    };

    try testing.expectError(error.ProtocolError, http2_conn.parseAndApplySettings(&payload));
}

test "HTTP/2 Settings parsing - enable push validation" {
    var reactor = try Reactor.init(testing.allocator);
    defer reactor.deinit();

    var socket_manager = SocketManager.init(testing.allocator, &reactor);
    defer socket_manager.deinit();

    const socket = Socket{ .uuid = SocketUUID{ .id = 1, .counter = 1 }, .manager = &socket_manager };
    var http2_conn = Client.Http2Connection.init(testing.allocator, &socket_manager, socket);
    defer http2_conn.deinit();

    // SETTINGS_ENABLE_PUSH with invalid value (> 1)
    var payload = [_]u8{
        0x00, 0x02, 0x00, 0x00, 0x00, 0x02, // Invalid push setting
    };

    try testing.expectError(error.ProtocolError, http2_conn.parseAndApplySettings(&payload));
}

test "HTTP/2 Settings parsing - unknown settings ignored" {
    var reactor = try Reactor.init(testing.allocator);
    defer reactor.deinit();

    var socket_manager = SocketManager.init(testing.allocator, &reactor);
    defer socket_manager.deinit();

    const socket = Socket{ .uuid = SocketUUID{ .id = 1, .counter = 1 }, .manager = &socket_manager };
    var http2_conn = Client.Http2Connection.init(testing.allocator, &socket_manager, socket);
    defer http2_conn.deinit();

    // Unknown setting ID (0xFF) should be ignored
    var payload = [_]u8{
        0x00, 0xFF, 0x12, 0x34, 0x56, 0x78, // Unknown setting
        0x00, 0x04, 0x00, 0x01, 0x00, 0x00, // Valid setting: INITIAL_WINDOW_SIZE = 65536
    };

    try http2_conn.parseAndApplySettings(&payload);

    // Only valid setting should be applied
    try testing.expectEqual(@as(u32, 65536), http2_conn.peer_settings.initial_window_size);
}

test "HTTP/2 Settings parsing - window size updates" {
    var reactor = try Reactor.init(testing.allocator);
    defer reactor.deinit();

    var socket_manager = SocketManager.init(testing.allocator, &reactor);
    defer socket_manager.deinit();

    const socket = Socket{ .uuid = SocketUUID{ .id = 1, .counter = 1 }, .manager = &socket_manager };
    var http2_conn = Client.Http2Connection.init(testing.allocator, &socket_manager, socket);
    defer http2_conn.deinit();

    // Add a test stream
    const stream_id: u31 = 1;
    const initial_stream_window: i32 = 32768;
    const stream_state = Client.Http2Connection.Http2StreamState{
        .window_size = initial_stream_window,
        .headers_complete = false,
        .end_stream_received = false,
        .response_headers = ArrayList(http2.HeaderEntry).init(testing.allocator),
        .response_data = ArrayList(u8).init(testing.allocator),
        .reset_error_code = null,
    };
    try http2_conn.streams.put(stream_id, stream_state);

    // Update INITIAL_WINDOW_SIZE from default 65535 to 32768
    var payload = [_]u8{
        0x00, 0x04, 0x00, 0x00, 0x80, 0x00, // INITIAL_WINDOW_SIZE = 32768
    };

    try http2_conn.parseAndApplySettings(&payload);

    // Check that stream window was adjusted by the delta (-32767)
    const updated_stream = http2_conn.streams.get(stream_id).?;
    const expected_window = initial_stream_window + (32768 - 65535); // -32767
    try testing.expectEqual(expected_window, updated_stream.window_size);

    // Clean up
    var stream_cleanup = http2_conn.streams.getPtr(stream_id).?;
    stream_cleanup.response_headers.deinit();
    stream_cleanup.response_data.deinit();
}

test "HTTP/3 QPACK header conversion" {
    var client = Client.init(testing.allocator);
    defer client.deinit();

    var request = Request.init(testing.allocator, .GET, "https://example.com/test?param=value");
    defer request.deinit();

    try request.setHeader("User-Agent", "Ferret/1.0");
    try request.setHeader("Accept", "application/json");
    request.setBody("test body");

    const uri_info = try client.parseUri("https://example.com/test?param=value");
    defer testing.allocator.free(uri_info.host);
    defer testing.allocator.free(uri_info.path);

    var qpack_headers = try client.convertHeadersToQpack(&request, uri_info);
    defer client.deallocateQpackHeaders(&qpack_headers);

    // Verify pseudo-headers are present
    var has_method = false;
    var has_path = false;
    var has_scheme = false;
    var has_authority = false;
    var has_user_agent = false;
    var has_accept = false;
    var has_content_length = false;

    for (qpack_headers.items) |header| {
        if (mem.eql(u8, header.name, ":method")) {
            try testing.expectEqualStrings("GET", header.value);
            has_method = true;
        } else if (mem.eql(u8, header.name, ":path")) {
            try testing.expectEqualStrings("/test?param=value", header.value);
            has_path = true;
        } else if (mem.eql(u8, header.name, ":scheme")) {
            try testing.expectEqualStrings("https", header.value);
            has_scheme = true;
        } else if (mem.eql(u8, header.name, ":authority")) {
            try testing.expectEqualStrings("example.com", header.value);
            has_authority = true;
        } else if (mem.eql(u8, header.name, "user-agent")) {
            try testing.expectEqualStrings("Ferret/1.0", header.value);
            has_user_agent = true;
        } else if (mem.eql(u8, header.name, "accept")) {
            try testing.expectEqualStrings("application/json", header.value);
            has_accept = true;
        } else if (mem.eql(u8, header.name, "content-length")) {
            try testing.expectEqualStrings("9", header.value);
            has_content_length = true;
        }
    }

    try testing.expect(has_method);
    try testing.expect(has_path);
    try testing.expect(has_scheme);
    try testing.expect(has_authority);
    try testing.expect(has_user_agent);
    try testing.expect(has_accept);
    try testing.expect(has_content_length);
}

test "HTTP/3 response conversion" {
    var client = Client.init(testing.allocator);
    defer client.deinit();

    // Create a mock HTTP/3 response
    var http3_response = http3.Http3Response{
        .status = 200,
        .headers = std.ArrayList(http3.QpackDecoder.QpackEntry).init(testing.allocator),
        .body = std.ArrayList(u8).init(testing.allocator),
    };
    defer http3_response.deinit();

    // Add some mock headers
    try http3_response.headers.append(http3.QpackDecoder.QpackEntry{
        .name = try testing.allocator.dupe(u8, ":status"),
        .value = try testing.allocator.dupe(u8, "200"),
    });
    try http3_response.headers.append(http3.QpackDecoder.QpackEntry{
        .name = try testing.allocator.dupe(u8, "content-type"),
        .value = try testing.allocator.dupe(u8, "application/json"),
    });
    try http3_response.headers.append(http3.QpackDecoder.QpackEntry{
        .name = try testing.allocator.dupe(u8, "server"),
        .value = try testing.allocator.dupe(u8, "nginx/1.20"),
    });

    // Add body content
    try http3_response.body.appendSlice("Hello, HTTP/3!");

    // Convert to unified response
    var response = try client.convertHttp3Response(http3_response);
    defer response.deinit();

    try testing.expect(response.status == .ok);
    try testing.expect(response.version == .http_3_0);
    try testing.expectEqualStrings(response.headers.get("content-type").?, "application/json");
    try testing.expectEqualStrings(response.headers.get("server").?, "nginx/1.20");
    try testing.expectEqualStrings(response.body.?, "Hello, HTTP/3!");
}

test "HTTP/3 URI requirements" {
    var client = Client.init(testing.allocator);
    defer client.deinit();

    // Test that HTTP URLs are rejected for HTTP/3
    var http_request = Request.init(testing.allocator, .GET, "http://example.com/");
    defer http_request.deinit();
    http_request.version = .http_3_0;

    try testing.expectError(HttpClientError.Http3RequiresHttps, client.sendHttp3(&http_request));

    // Test that HTTPS URLs are accepted (would fail later at connection level)
    var https_request = Request.init(testing.allocator, .GET, "https://example.com/");
    defer https_request.deinit();
    https_request.version = .http_3_0;

    // This will fail at the network level since we can't actually connect,
    // but it should pass the HTTPS requirement check
    const result = client.sendHttp3(&https_request);
    try testing.expect(result != HttpClientError.Http3RequiresHttps);
}

test "HTTP/3 header name case conversion" {
    var client = Client.init(testing.allocator);
    defer client.deinit();

    var request = Request.init(testing.allocator, .POST, "https://api.example.com/data");
    defer request.deinit();

    // Add headers with mixed case
    try request.setHeader("Content-Type", "application/json");
    try request.setHeader("X-API-Key", "secret123");
    try request.setHeader("USER-AGENT", "Ferret/1.0");

    const uri_info = try client.parseUri("https://api.example.com/data");
    defer testing.allocator.free(uri_info.host);
    defer testing.allocator.free(uri_info.path);

    var qpack_headers = try client.convertHeadersToQpack(&request, uri_info);
    defer client.deallocateQpackHeaders(&qpack_headers);

    // Verify all header names are lowercase (except pseudo-headers)
    for (qpack_headers.items) |header| {
        if (header.name[0] != ':') { // Skip pseudo-headers
            for (header.name) |c| {
                try testing.expect(c == std.ascii.toLower(c));
            }
        }
    }

    // Verify specific headers were converted
    var found_content_type = false;
    var found_api_key = false;
    var found_user_agent = false;

    for (qpack_headers.items) |header| {
        if (mem.eql(u8, header.name, "content-type")) {
            try testing.expectEqualStrings("application/json", header.value);
            found_content_type = true;
        } else if (mem.eql(u8, header.name, "x-api-key")) {
            try testing.expectEqualStrings("secret123", header.value);
            found_api_key = true;
        } else if (mem.eql(u8, header.name, "user-agent")) {
            try testing.expectEqualStrings("Ferret/1.0", header.value);
            found_user_agent = true;
        }
    }

    try testing.expect(found_content_type);
    try testing.expect(found_api_key);
    try testing.expect(found_user_agent);
}
