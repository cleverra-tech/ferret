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
        var iterator = self.map.iterator();
        while (iterator.next()) |entry| {
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

    const Self = @This();

    pub fn init(allocator: Allocator, status: StatusCode) Self {
        return Self{
            .status = status,
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
        _ = self;
        _ = request;
        // Implementation would use HTTP/1.1 connection
        return error.NotImplemented;
    }

    fn sendHttp2(self: *Self, request: *Request) !Response {
        _ = self;
        _ = request;
        // Implementation would use HTTP/2 connection
        return error.NotImplemented;
    }

    fn sendHttp3(self: *Self, request: *Request) !Response {
        _ = self;
        _ = request;
        // Implementation would use HTTP/3 QUIC connection
        return error.NotImplemented;
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
};

/// HTTP server with unified API
pub const Server = struct {
    allocator: Allocator,
    address: net.Address,
    supported_versions: []const HttpVersion,
    default_version: HttpVersion,

    const Self = @This();

    pub fn init(allocator: Allocator, address: net.Address) Self {
        const supported = &[_]HttpVersion{ .http_3_0, .http_2_0, .http_1_1 };
        return Self{
            .allocator = allocator,
            .address = address,
            .supported_versions = supported,
            .default_version = .http_3_0,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn listen(self: *Self) !void {
        _ = self;
        // Implementation would start listening on the address
        // and handle incoming connections with protocol negotiation
        return error.NotImplemented;
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
