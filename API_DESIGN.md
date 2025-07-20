# Ferret API Design: Zig-Idiomatic Translation of facil-cstl

## Overview

This document outlines how facil-cstl's features will be translated into idiomatic Zig APIs, leveraging Zig's compile-time capabilities, explicit memory management, and type safety.

## Core Design Principles

### 1. Explicit Allocator Management
All APIs that may allocate memory require an explicit allocator parameter.

### 2. Compile-time Code Generation
Replace C macros with Zig's comptime functions for type-safe generics.

### 3. Error Handling
Use Zig's error unions for all fallible operations with clear error taxonomies.

### 4. Zero-Cost Abstractions
Leverage comptime to eliminate runtime overhead while maintaining ergonomics.

## API Mappings

### 1. Dynamic Arrays (FIO_ARRAY_NAME → Array)

**facil-cstl (C macro approach):**
```c
#define FIO_ARRAY_NAME    my_array
#define FIO_ARRAY_TYPE    my_struct_t
#include "fio-stl.h"

my_array_s arr = {0};
my_array_push(&arr, my_value);
```

**Ferret (Zig generic approach):**
```zig
const Array = @import("collections/array.zig").Array;

var arr = Array(MyStruct).init(allocator);
defer arr.deinit();
try arr.append(my_value);
```

**Advanced Features:**
```zig
pub fn Array(comptime T: type) type {
    return struct {
        const Self = @This();
        
        items: []T,
        capacity: usize,
        allocator: Allocator,
        
        pub fn init(allocator: Allocator) Self { ... }
        pub fn initCapacity(allocator: Allocator, capacity: usize) !Self { ... }
        pub fn deinit(self: *Self) void { ... }
        
        pub fn append(self: *Self, item: T) !void { ... }
        pub fn appendSlice(self: *Self, items: []const T) !void { ... }
        pub fn insert(self: *Self, index: usize, item: T) !void { ... }
        pub fn remove(self: *Self, index: usize) T { ... }
        pub fn pop(self: *Self) ?T { ... }
        
        pub fn get(self: Self, index: usize) ?T { ... }
        pub fn set(self: *Self, index: usize, item: T) void { ... }
        pub fn slice(self: Self) []T { ... }
        
        pub fn sort(self: *Self, comptime lessThan: fn(T, T) bool) void { ... }
        pub fn reverse(self: *Self) void { ... }
        pub fn find(self: Self, item: T) ?usize { ... }
    };
}
```

### 2. Hash Maps (FIO_MAP_NAME → HashMap)

**facil-cstl:**
```c
#define FIO_MAP_NAME      my_map
#define FIO_MAP_KEY       int
#define FIO_MAP_VALUE     char*
#include "fio-stl.h"

my_map_s map = {0};
my_map_set(&map, key, value);
```

**Ferret:**
```zig
const HashMap = @import("collections/hashmap.zig").HashMap;

var map = HashMap(i32, []const u8).init(allocator);
defer map.deinit();
try map.put(key, value);
```

**Advanced Features:**
```zig
pub fn HashMap(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        const Entry = struct { key: K, value: V };
        
        entries: []?Entry,
        count: usize,
        allocator: Allocator,
        
        pub fn init(allocator: Allocator) Self { ... }
        pub fn initCapacity(allocator: Allocator, capacity: usize) !Self { ... }
        pub fn deinit(self: *Self) void { ... }
        
        pub fn put(self: *Self, key: K, value: V) !void { ... }
        pub fn get(self: Self, key: K) ?V { ... }
        pub fn getPtr(self: *Self, key: K) ?*V { ... }
        pub fn remove(self: *Self, key: K) bool { ... }
        pub fn contains(self: Self, key: K) bool { ... }
        
        pub fn iterator(self: *const Self) Iterator { ... }
        pub fn keyIterator(self: *const Self) KeyIterator { ... }
        pub fn valueIterator(self: *const Self) ValueIterator { ... }
        
        pub fn clone(self: Self, allocator: Allocator) !Self { ... }
        pub fn count(self: Self) usize { ... }
        pub fn capacity(self: Self) usize { ... }
    };
}
```

### 3. Binary-Safe Strings (FIO_STR → String)

**facil-cstl:**
```c
fio_str_s str = FIO_STR_INIT;
fio_str_write(&str, "Hello", 5);
fio_str_printf(&str, " %s", "World");
```

**Ferret:**
```zig
const String = @import("collections/string.zig").String;

var str = String.init(allocator);
defer str.deinit();
try str.appendSlice("Hello");
try str.print(" {s}", .{"World"});
```

**Advanced Features:**
```zig
pub const String = struct {
    const Self = @This();
    
    data: []u8,
    len: usize,
    allocator: Allocator,
    
    pub fn init(allocator: Allocator) Self { ... }
    pub fn initCapacity(allocator: Allocator, capacity: usize) !Self { ... }
    pub fn initFromSlice(allocator: Allocator, slice: []const u8) !Self { ... }
    pub fn deinit(self: *Self) void { ... }
    
    pub fn append(self: *Self, ch: u8) !void { ... }
    pub fn appendSlice(self: *Self, slice: []const u8) !void { ... }
    pub fn appendString(self: *Self, other: String) !void { ... }
    pub fn print(self: *Self, comptime fmt: []const u8, args: anytype) !void { ... }
    
    pub fn slice(self: Self) []const u8 { ... }
    pub fn toOwned(self: Self, allocator: Allocator) ![]u8 { ... }
    pub fn clone(self: Self, allocator: Allocator) !Self { ... }
    
    pub fn startsWith(self: Self, prefix: []const u8) bool { ... }
    pub fn endsWith(self: Self, suffix: []const u8) bool { ... }
    pub fn contains(self: Self, needle: []const u8) bool { ... }
    pub fn find(self: Self, needle: []const u8) ?usize { ... }
    pub fn replace(self: *Self, needle: []const u8, replacement: []const u8) !void { ... }
    
    pub fn split(self: Self, delimiter: []const u8, allocator: Allocator) ![]String { ... }
    pub fn trim(self: Self) []const u8 { ... }
    pub fn toLower(self: *Self) void { ... }
    pub fn toUpper(self: *Self) void { ... }
};
```

### 4. I/O Reactor (FIO_IO → Reactor)

**facil-cstl:**
```c
void on_data(fio_s *io) {
    // Handle data
}

fio_listen(.port = "8080", .on_data = on_data);
fio_start(.threads = 1);
```

**Ferret:**
```zig
const Reactor = @import("io/reactor.zig").Reactor;
const Socket = @import("io/socket.zig").Socket;

fn onData(socket: *Socket) void {
    // Handle data
}

var reactor = try Reactor.init(allocator);
defer reactor.deinit();

var listener = try reactor.listen("127.0.0.1", 8080);
listener.setCallback(.data, onData);

try reactor.run();
```

**Advanced Features:**
```zig
pub const Reactor = struct {
    const Self = @This();
    const Callback = fn(*Socket) void;
    
    pub const Event = enum { read, write, close, error };
    
    allocator: Allocator,
    sockets: HashMap(i32, *Socket),
    running: bool,
    
    pub fn init(allocator: Allocator) !Self { ... }
    pub fn deinit(self: *Self) void { ... }
    
    pub fn addSocket(self: *Self, socket: *Socket) !void { ... }
    pub fn removeSocket(self: *Self, socket: *Socket) void { ... }
    
    pub fn listen(self: *Self, host: []const u8, port: u16) !*Socket { ... }
    pub fn connect(self: *Self, host: []const u8, port: u16) !*Socket { ... }
    
    pub fn run(self: *Self) !void { ... }
    pub fn stop(self: *Self) void { ... }
    
    pub fn setTimeout(self: *Self, socket: *Socket, ms: u64, callback: Callback) !void { ... }
    pub fn clearTimeout(self: *Self, socket: *Socket) void { ... }
};
```

### 5. HTTP Server (FIO_HTTP → HttpServer)

**facil-cstl:**
```c
void on_request(fio_http_s *h) {
    fio_http_send_body(h, "Hello World", 11);
}

fio_http_listen("8080", NULL, .on_request = on_request);
```

**Ferret:**
```zig
const HttpServer = @import("protocols/http.zig").HttpServer;
const HttpRequest = @import("protocols/http.zig").HttpRequest;
const HttpResponse = @import("protocols/http.zig").HttpResponse;

fn handleRequest(req: *HttpRequest, res: *HttpResponse) !void {
    try res.sendBody("Hello World");
}

var server = try HttpServer.init(allocator, .{
    .host = "127.0.0.1",
    .port = 8080,
    .handler = handleRequest,
});
defer server.deinit();

try server.start();
```

**Advanced Features:**
```zig
pub const HttpServer = struct {
    const Self = @This();
    const Handler = fn(*HttpRequest, *HttpResponse) anyerror!void;
    
    pub const Config = struct {
        host: []const u8 = "127.0.0.1",
        port: u16 = 8080,
        handler: Handler,
        max_connections: u32 = 1024,
        timeout_ms: u32 = 30000,
        keep_alive: bool = true,
    };
    
    allocator: Allocator,
    reactor: *Reactor,
    config: Config,
    
    pub fn init(allocator: Allocator, config: Config) !Self { ... }
    pub fn deinit(self: *Self) void { ... }
    
    pub fn start(self: *Self) !void { ... }
    pub fn stop(self: *Self) void { ... }
    
    pub fn addMiddleware(self: *Self, middleware: Middleware) !void { ... }
    pub fn addRoute(self: *Self, method: Method, path: []const u8, handler: Handler) !void { ... }
};

pub const HttpRequest = struct {
    method: Method,
    path: []const u8,
    version: Version,
    headers: HashMap([]const u8, []const u8),
    body: []const u8,
    
    pub fn getHeader(self: Self, name: []const u8) ?[]const u8 { ... }
    pub fn getQuery(self: Self, name: []const u8) ?[]const u8 { ... }
    pub fn getParam(self: Self, name: []const u8) ?[]const u8 { ... }
};

pub const HttpResponse = struct {
    status: u16 = 200,
    headers: HashMap([]const u8, []const u8),
    body: String,
    
    pub fn setStatus(self: *Self, status: u16) void { ... }
    pub fn setHeader(self: *Self, name: []const u8, value: []const u8) !void { ... }
    pub fn sendBody(self: *Self, body: []const u8) !void { ... }
    pub fn sendJson(self: *Self, value: anytype) !void { ... }
    pub fn redirect(self: *Self, location: []const u8) !void { ... }
};
```

### 6. JSON Processing (FIO_JSON → Json)

**facil-cstl:**
```c
FIOBJ json = fiobj_json_parse(data, len, NULL);
FIOBJ value = fiobj_hash_get(json, key);
```

**Ferret:**
```zig
const Json = @import("protocols/json.zig");

const parsed = try Json.parse(allocator, data);
defer parsed.deinit();

const value = parsed.get("key");
```

**Advanced Features:**
```zig
pub const Json = struct {
    const Self = @This();
    
    pub const Value = union(enum) {
        null,
        bool: bool,
        int: i64,
        float: f64,
        string: []const u8,
        array: Array(Value),
        object: HashMap([]const u8, Value),
    };
    
    value: Value,
    allocator: Allocator,
    
    pub fn parse(allocator: Allocator, data: []const u8) !Self { ... }
    pub fn parseFromFile(allocator: Allocator, path: []const u8) !Self { ... }
    pub fn deinit(self: *Self) void { ... }
    
    pub fn get(self: Self, key: []const u8) ?Value { ... }
    pub fn getString(self: Self, key: []const u8) ?[]const u8 { ... }
    pub fn getInt(self: Self, key: []const u8) ?i64 { ... }
    pub fn getBool(self: Self, key: []const u8) ?bool { ... }
    
    pub fn stringify(self: Self, allocator: Allocator) ![]u8 { ... }
    pub fn stringifyPretty(self: Self, allocator: Allocator, indent: u32) ![]u8 { ... }
    
    pub fn fromStruct(allocator: Allocator, value: anytype) !Self { ... }
    pub fn toStruct(self: Self, comptime T: type, allocator: Allocator) !T { ... }
};
```

### 7. Command Line Interface (FIO_CLI → Cli)

**facil-cstl:**
```c
fio_cli_start(argc, argv, 0, 0, NULL,
    FIO_CLI_STRING("-host -h host address"),
    FIO_CLI_INT("-port -p port number"));
```

**Ferret:**
```zig
const Cli = @import("cli/args.zig").Cli;

const Args = struct {
    host: []const u8 = "localhost",
    port: u16 = 8080,
    verbose: bool = false,
};

var cli = Cli(Args).init(allocator);
defer cli.deinit();

const args = try cli.parse();
```

**Advanced Features:**
```zig
pub fn Cli(comptime ArgsType: type) type {
    return struct {
        const Self = @This();
        
        allocator: Allocator,
        program_name: []const u8,
        description: ?[]const u8,
        
        pub fn init(allocator: Allocator) Self { ... }
        pub fn deinit(self: *Self) void { ... }
        
        pub fn description(self: *Self, desc: []const u8) *Self { ... }
        pub fn version(self: *Self, ver: []const u8) *Self { ... }
        
        pub fn parse(self: *Self) !ArgsType { ... }
        pub fn parseFrom(self: *Self, args: [][]const u8) !ArgsType { ... }
        
        pub fn printHelp(self: Self) void { ... }
        pub fn printVersion(self: Self) void { ... }
    };
}
```

## Error Handling Strategy

### Hierarchical Error Types
```zig
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

pub const HttpError = error{
    InvalidMethod,
    InvalidPath,
    InvalidHeader,
    RequestTooLarge,
    UnsupportedVersion,
} || Error;

pub const JsonError = error{
    UnexpectedToken,
    InvalidNumber,
    InvalidString,
    UnexpectedEnd,
    TooDeep,
} || Error;
```

### Error Context
```zig
pub const ErrorContext = struct {
    message: []const u8,
    line: ?u32 = null,
    column: ?u32 = null,
    
    pub fn format(self: ErrorContext, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("{s}", .{self.message});
        if (self.line) |line| {
            try writer.print(" at line {}", .{line});
            if (self.column) |col| {
                try writer.print(":{}", .{col});
            }
        }
    }
};
```

## Memory Management Patterns

### Arena Allocator for Request Handling
```zig
pub fn handleRequest(req: *HttpRequest, res: *HttpResponse) !void {
    var arena = std.heap.ArenaAllocator.init(req.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    const data = try parseJson(allocator, req.body);
    try res.sendJson(data);
}
```

### Pool Allocator for High-Frequency Objects
```zig
pub const ConnectionPool = struct {
    pool: std.heap.MemoryPool(Connection),
    
    pub fn acquire(self: *Self) !*Connection { ... }
    pub fn release(self: *Self, conn: *Connection) void { ... }
};
```

## Testing Strategy

### Unit Tests with Allocator Tracking
```zig
test "HashMap basic operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.testing.expect(!gpa.deinit());
    const allocator = gpa.allocator();
    
    var map = HashMap([]const u8, i32).init(allocator);
    defer map.deinit();
    
    try map.put("key", 42);
    try std.testing.expectEqual(@as(?i32, 42), map.get("key"));
}
```

### Integration Tests
```zig
test "HTTP server request handling" {
    const allocator = std.testing.allocator;
    
    var server = try HttpServer.init(allocator, .{
        .port = 0, // OS assigns port
        .handler = testHandler,
    });
    defer server.deinit();
    
    try server.start();
    const port = server.getPort();
    
    // Make test request
    const response = try makeRequest(allocator, "localhost", port, "GET", "/test");
    try std.testing.expectEqualStrings("OK", response.body);
}
```

This API design provides a solid foundation for implementing facil-cstl's functionality in idiomatic Zig while maintaining performance and adding type safety.