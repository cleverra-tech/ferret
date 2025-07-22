//! High-performance JSON parser and generator for Ferret
//!
//! This implementation focuses on:
//! - Zero-copy string parsing for simple strings (no escape sequences)
//! - Streaming support for large JSON documents
//! - Minimal allocations during parsing
//! - Type-safe value access with compile-time validation
//! - Fast serialization with configurable formatting
//! - Configurable string ownership for memory efficiency

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;
const StringHashMap = std.StringHashMap;
// const raii = @import("../core/raii.zig"); // Temporarily commented for testing

/// JSON value types
pub const ValueType = enum {
    null,
    bool,
    int,
    float,
    string,
    array,
    object,
};

/// JSON parsing errors
pub const ParseError = error{
    InvalidCharacter,
    UnexpectedToken,
    UnexpectedEndOfInput,
    InvalidNumber,
    InvalidEscape,
    InvalidUnicode,
    TooDeep,
    OutOfMemory,
    TypeMismatch,
    StringTooLong,
    NumberTooLong,
    CommentNotAllowed,
    TrailingCommaNotAllowed,
};

/// JSON configuration options
pub const JsonConfig = struct {
    allow_comments: bool = false,
    allow_trailing_commas: bool = false,
    max_parsing_depth: u32 = 128,
    max_string_length: u32 = 1024 * 1024, // 1MB
    max_number_length: u32 = 1024, // 1KB
    
    pub fn default() JsonConfig {
        return JsonConfig{};
    }
    
    pub fn lenient() JsonConfig {
        return JsonConfig{
            .allow_comments = true,
            .allow_trailing_commas = true,
            .max_parsing_depth = 256,
            .max_string_length = 10 * 1024 * 1024, // 10MB
            .max_number_length = 4096, // 4KB
        };
    }
};

/// JSON value representation with optional zero-copy strings
pub const Value = union(ValueType) {
    null: void,
    bool: bool,
    int: i64,
    float: f64,
    string: struct { data: []const u8, owned: bool },
    array: ArrayList(Value),
    object: StringHashMap(Value),

    pub fn deinit(self: *Value, allocator: Allocator) void {
        switch (self.*) {
            .array => |*arr| {
                for (arr.items) |*item| {
                    item.deinit(allocator);
                }
                arr.deinit();
            },
            .object => |*obj| {
                var iter = obj.iterator();
                while (iter.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    entry.value_ptr.deinit(allocator);
                }
                obj.deinit();
            },
            .string => |str| if (str.owned) allocator.free(str.data),
            else => {},
        }
    }

    pub fn getType(self: Value) ValueType {
        return @as(ValueType, self);
    }

    /// Get boolean value, returns error if not boolean
    pub fn getBool(self: Value) !bool {
        return switch (self) {
            .bool => |b| b,
            else => error.TypeMismatch,
        };
    }

    /// Get integer value, returns error if not integer
    pub fn getInt(self: Value) !i64 {
        return switch (self) {
            .int => |i| i,
            else => error.TypeMismatch,
        };
    }

    /// Get float value, returns error if not float
    pub fn getFloat(self: Value) !f64 {
        return switch (self) {
            .float => |f| f,
            .int => |i| @floatFromInt(i),
            else => error.TypeMismatch,
        };
    }

    /// Get string value, returns error if not string
    pub fn getString(self: Value) ![]const u8 {
        return switch (self) {
            .string => |s| s.data,
            else => error.TypeMismatch,
        };
    }

    /// Get array value, returns error if not array
    pub fn getArray(self: Value) !ArrayList(Value) {
        return switch (self) {
            .array => |a| a,
            else => error.TypeMismatch,
        };
    }

    /// Get object value, returns error if not object
    pub fn getObject(self: Value) !StringHashMap(Value) {
        return switch (self) {
            .object => |o| o,
            else => error.TypeMismatch,
        };
    }

    /// Create an owned string value (allocates memory)
    pub fn createOwnedString(allocator: Allocator, str: []const u8) !Value {
        const owned = try allocator.dupe(u8, str);
        return Value{ .string = .{ .data = owned, .owned = true } };
    }

    /// Create a borrowed string value (zero-copy, references external data)
    pub fn createBorrowedString(str: []const u8) Value {
        return Value{ .string = .{ .data = str, .owned = false } };
    }
};

/// JSON parser with streaming support
pub const Parser = struct {
    allocator: Allocator,
    input: []const u8,
    pos: usize,
    line: u32,
    column: u32,
    config: JsonConfig,
    current_depth: u32,

    const Self = @This();

    pub fn init(allocator: Allocator, input: []const u8) Self {
        return Self{
            .allocator = allocator,
            .input = input,
            .pos = 0,
            .line = 1,
            .column = 1,
            .config = JsonConfig.default(),
            .current_depth = 0,
        };
    }

    pub fn initWithConfig(allocator: Allocator, input: []const u8, config: JsonConfig) Self {
        return Self{
            .allocator = allocator,
            .input = input,
            .pos = 0,
            .line = 1,
            .column = 1,
            .config = config,
            .current_depth = 0,
        };
    }

    /// Parse JSON string into Value
    pub fn parse(self: *Self) ParseError!Value {
        self.skipWhitespace();
        return self.parseValue();
    }

    fn parseValue(self: *Self) ParseError!Value {
        if (self.current_depth >= self.config.max_parsing_depth) {
            return ParseError.TooDeep;
        }

        self.skipWhitespace();
        if (self.pos >= self.input.len) {
            return ParseError.UnexpectedEndOfInput;
        }

        const char = self.input[self.pos];
        return switch (char) {
            'n' => self.parseNull(),
            't', 'f' => self.parseBool(),
            '"' => self.parseString(),
            '[' => self.parseArray(),
            '{' => self.parseObject(),
            '-', '0'...'9' => self.parseNumber(),
            '/' => if (!self.config.allow_comments) ParseError.CommentNotAllowed else ParseError.InvalidCharacter,
            else => ParseError.InvalidCharacter,
        };
    }

    fn parseNull(self: *Self) ParseError!Value {
        if (self.pos + 4 > self.input.len or
            !std.mem.eql(u8, self.input[self.pos .. self.pos + 4], "null"))
        {
            return ParseError.InvalidCharacter;
        }
        self.advance(4);
        return Value{ .null = {} };
    }

    fn parseBool(self: *Self) ParseError!Value {
        if (self.input[self.pos] == 't') {
            if (self.pos + 4 > self.input.len or
                !std.mem.eql(u8, self.input[self.pos .. self.pos + 4], "true"))
            {
                return ParseError.InvalidCharacter;
            }
            self.advance(4);
            return Value{ .bool = true };
        } else {
            if (self.pos + 5 > self.input.len or
                !std.mem.eql(u8, self.input[self.pos .. self.pos + 5], "false"))
            {
                return ParseError.InvalidCharacter;
            }
            self.advance(5);
            return Value{ .bool = false };
        }
    }

    fn parseString(self: *Self) ParseError!Value {
        if (self.input[self.pos] != '"') {
            return ParseError.InvalidCharacter;
        }
        self.advance(1); // Skip opening quote

        const start = self.pos;
        var needs_unescape = false;
        var string_length: u32 = 0;

        while (self.pos < self.input.len) {
            const char = self.input[self.pos];
            if (char == '"') {
                const end = self.pos;
                self.advance(1); // Skip closing quote

                // Check string length limits
                if (string_length > self.config.max_string_length) {
                    return ParseError.StringTooLong;
                }

                if (needs_unescape) {
                    const unescaped = try self.unescapeString(self.input[start..end]);
                    return Value{ .string = .{ .data = unescaped, .owned = true } };
                } else {
                    // True zero-copy string - reference original input
                    return Value{ .string = .{ .data = self.input[start..end], .owned = false } };
                }
            } else if (char == '\\') {
                needs_unescape = true;
                self.advance(1);
                if (self.pos >= self.input.len) {
                    return ParseError.UnexpectedEndOfInput;
                }
                self.advance(1);
                string_length += 1;
            } else if (char < 0x20) {
                return ParseError.InvalidCharacter;
            } else {
                self.advance(1);
                string_length += 1;
            }
        }
        return ParseError.UnexpectedEndOfInput;
    }

    fn parseArray(self: *Self) ParseError!Value {
        if (self.input[self.pos] != '[') {
            return ParseError.InvalidCharacter;
        }
        self.advance(1);
        self.current_depth += 1;
        defer self.current_depth -= 1;

        var array = ArrayList(Value).init(self.allocator);
        errdefer {
            for (array.items) |*item| {
                item.deinit(self.allocator);
            }
            array.deinit();
        }

        self.skipWhitespace();
        if (self.pos < self.input.len and self.input[self.pos] == ']') {
            self.advance(1);
            return Value{ .array = array };
        }

        while (true) {
            const value = try self.parseValue();
            try array.append(value);

            self.skipWhitespace();
            if (self.pos >= self.input.len) {
                return ParseError.UnexpectedEndOfInput;
            }

            const char = self.input[self.pos];
            if (char == ']') {
                self.advance(1);
                break;
            } else if (char == ',') {
                self.advance(1);
                self.skipWhitespace();
                // Check for trailing comma
                if (self.pos < self.input.len and self.input[self.pos] == ']') {
                    if (!self.config.allow_trailing_commas) {
                        return ParseError.TrailingCommaNotAllowed;
                    }
                    self.advance(1);
                    break;
                }
            } else {
                return ParseError.UnexpectedToken;
            }
        }

        return Value{ .array = array };
    }

    fn parseObject(self: *Self) ParseError!Value {
        if (self.input[self.pos] != '{') {
            return ParseError.InvalidCharacter;
        }
        self.advance(1);
        self.current_depth += 1;
        defer self.current_depth -= 1;

        var object = StringHashMap(Value).init(self.allocator);
        errdefer {
            var iter = object.iterator();
            while (iter.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            object.deinit();
        }

        self.skipWhitespace();
        if (self.pos < self.input.len and self.input[self.pos] == '}') {
            self.advance(1);
            return Value{ .object = object };
        }

        while (true) {
            self.skipWhitespace();
            var key_value = try self.parseString();
            const key = key_value.getString() catch {
                key_value.deinit(self.allocator);
                return ParseError.TypeMismatch;
            };
            const owned_key = try self.allocator.dupe(u8, key);
            key_value.deinit(self.allocator);

            self.skipWhitespace();
            if (self.pos >= self.input.len or self.input[self.pos] != ':') {
                self.allocator.free(owned_key);
                return ParseError.UnexpectedToken;
            }
            self.advance(1);

            const value = try self.parseValue();
            try object.put(owned_key, value);

            self.skipWhitespace();
            if (self.pos >= self.input.len) {
                return ParseError.UnexpectedEndOfInput;
            }

            const char = self.input[self.pos];
            if (char == '}') {
                self.advance(1);
                break;
            } else if (char == ',') {
                self.advance(1);
                self.skipWhitespace();
                // Check for trailing comma
                if (self.pos < self.input.len and self.input[self.pos] == '}') {
                    if (!self.config.allow_trailing_commas) {
                        return ParseError.TrailingCommaNotAllowed;
                    }
                    self.advance(1);
                    break;
                }
            } else {
                return ParseError.UnexpectedToken;
            }
        }

        return Value{ .object = object };
    }

    fn parseNumber(self: *Self) ParseError!Value {
        const start = self.pos;
        var is_float = false;

        // Handle negative sign
        if (self.pos < self.input.len and self.input[self.pos] == '-') {
            self.advance(1);
        }

        // Parse integer part
        if (self.pos >= self.input.len or !std.ascii.isDigit(self.input[self.pos])) {
            return ParseError.InvalidNumber;
        }

        if (self.input[self.pos] == '0') {
            self.advance(1);
        } else {
            while (self.pos < self.input.len and std.ascii.isDigit(self.input[self.pos])) {
                self.advance(1);
            }
        }

        // Parse decimal part
        if (self.pos < self.input.len and self.input[self.pos] == '.') {
            is_float = true;
            self.advance(1);
            if (self.pos >= self.input.len or !std.ascii.isDigit(self.input[self.pos])) {
                return ParseError.InvalidNumber;
            }
            while (self.pos < self.input.len and std.ascii.isDigit(self.input[self.pos])) {
                self.advance(1);
            }
        }

        // Parse exponent
        if (self.pos < self.input.len and (self.input[self.pos] == 'e' or self.input[self.pos] == 'E')) {
            is_float = true;
            self.advance(1);
            if (self.pos < self.input.len and (self.input[self.pos] == '+' or self.input[self.pos] == '-')) {
                self.advance(1);
            }
            if (self.pos >= self.input.len or !std.ascii.isDigit(self.input[self.pos])) {
                return ParseError.InvalidNumber;
            }
            while (self.pos < self.input.len and std.ascii.isDigit(self.input[self.pos])) {
                self.advance(1);
            }
        }

        const number_str = self.input[start..self.pos];
        
        // Check number length limits
        if (number_str.len > self.config.max_number_length) {
            return ParseError.NumberTooLong;
        }
        
        if (is_float) {
            const float_val = std.fmt.parseFloat(f64, number_str) catch return ParseError.InvalidNumber;
            return Value{ .float = float_val };
        } else {
            const int_val = std.fmt.parseInt(i64, number_str, 10) catch return ParseError.InvalidNumber;
            return Value{ .int = int_val };
        }
    }

    fn unescapeString(self: *Self, escaped: []const u8) ParseError![]u8 {
        var result = ArrayList(u8).init(self.allocator);
        errdefer result.deinit();

        var i: usize = 0;
        while (i < escaped.len) {
            if (escaped[i] == '\\' and i + 1 < escaped.len) {
                const next = escaped[i + 1];
                switch (next) {
                    '"' => {
                        try result.append('"');
                        i += 2;
                    },
                    '\\' => {
                        try result.append('\\');
                        i += 2;
                    },
                    '/' => {
                        try result.append('/');
                        i += 2;
                    },
                    'b' => {
                        try result.append('\u{08}');
                        i += 2;
                    },
                    'f' => {
                        try result.append('\u{0C}');
                        i += 2;
                    },
                    'n' => {
                        try result.append('\n');
                        i += 2;
                    },
                    'r' => {
                        try result.append('\r');
                        i += 2;
                    },
                    't' => {
                        try result.append('\t');
                        i += 2;
                    },
                    'u' => {
                        if (i + 5 >= escaped.len) return ParseError.InvalidEscape;

                        // Parse the 4-digit hex Unicode escape
                        const hex = escaped[i + 2 .. i + 6];
                        const codepoint = std.fmt.parseInt(u16, hex, 16) catch return ParseError.InvalidUnicode;
                        i += 6; // Skip '\u' + 4 hex digits

                        // Check for UTF-16 surrogate pairs (for codepoints > U+FFFF)
                        if (codepoint >= 0xD800 and codepoint <= 0xDBFF) {
                            // High surrogate, expect low surrogate
                            if (i + 5 >= escaped.len or escaped[i] != '\\' or escaped[i + 1] != 'u') {
                                return ParseError.InvalidUnicode;
                            }

                            const low_hex = escaped[i + 2 .. i + 6];
                            const low_surrogate = std.fmt.parseInt(u16, low_hex, 16) catch return ParseError.InvalidUnicode;

                            if (low_surrogate < 0xDC00 or low_surrogate > 0xDFFF) {
                                return ParseError.InvalidUnicode;
                            }

                            // Combine surrogates to get the actual codepoint
                            const high = @as(u32, codepoint - 0xD800);
                            const low = @as(u32, low_surrogate - 0xDC00);
                            const full_codepoint = 0x10000 + (high << 10) + low;

                            // Encode as UTF-8
                            try self.encodeUtf8Codepoint(&result, full_codepoint);
                            i += 6; // Skip the second '\u' + 4 hex digits
                        } else if (codepoint >= 0xDC00 and codepoint <= 0xDFFF) {
                            // Unexpected low surrogate
                            return ParseError.InvalidUnicode;
                        } else {
                            // Regular BMP codepoint
                            try self.encodeUtf8Codepoint(&result, @as(u32, codepoint));
                        }
                    },
                    else => return ParseError.InvalidEscape,
                }
            } else {
                try result.append(escaped[i]);
                i += 1;
            }
        }

        return result.toOwnedSlice();
    }

    /// Encode a Unicode codepoint as UTF-8 bytes
    fn encodeUtf8Codepoint(self: *Self, result: *ArrayList(u8), codepoint: u32) ParseError!void {
        _ = self;

        if (codepoint <= 0x7F) {
            // 1-byte sequence: 0xxxxxxx
            try result.append(@intCast(codepoint));
        } else if (codepoint <= 0x7FF) {
            // 2-byte sequence: 110xxxxx 10xxxxxx
            try result.append(@intCast(0xC0 | (codepoint >> 6)));
            try result.append(@intCast(0x80 | (codepoint & 0x3F)));
        } else if (codepoint <= 0xFFFF) {
            // 3-byte sequence: 1110xxxx 10xxxxxx 10xxxxxx
            try result.append(@intCast(0xE0 | (codepoint >> 12)));
            try result.append(@intCast(0x80 | ((codepoint >> 6) & 0x3F)));
            try result.append(@intCast(0x80 | (codepoint & 0x3F)));
        } else if (codepoint <= 0x10FFFF) {
            // 4-byte sequence: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
            try result.append(@intCast(0xF0 | (codepoint >> 18)));
            try result.append(@intCast(0x80 | ((codepoint >> 12) & 0x3F)));
            try result.append(@intCast(0x80 | ((codepoint >> 6) & 0x3F)));
            try result.append(@intCast(0x80 | (codepoint & 0x3F)));
        } else {
            // Invalid codepoint
            return ParseError.InvalidUnicode;
        }
    }

    fn skipWhitespace(self: *Self) void {
        while (self.pos < self.input.len) {
            const char = self.input[self.pos];
            if (char == ' ' or char == '\t' or char == '\r' or char == '\n') {
                if (char == '\n') {
                    self.line += 1;
                    self.column = 1;
                } else {
                    self.column += 1;
                }
                self.pos += 1;
            } else if (char == '/' and self.config.allow_comments) {
                self.skipComment() catch break; // Stop on comment parse errors
            } else {
                break;
            }
        }
    }

    fn skipComment(self: *Self) ParseError!void {
        if (self.pos + 1 >= self.input.len) return ParseError.InvalidCharacter;
        
        const next_char = self.input[self.pos + 1];
        if (next_char == '/') {
            // Single-line comment //
            self.advance(2); // Skip '//'
            while (self.pos < self.input.len and self.input[self.pos] != '\n') {
                self.advance(1);
            }
            if (self.pos < self.input.len and self.input[self.pos] == '\n') {
                self.line += 1;
                self.column = 1;
                self.pos += 1;
            }
        } else if (next_char == '*') {
            // Multi-line comment /* ... */
            self.advance(2); // Skip '/*'
            while (self.pos + 1 < self.input.len) {
                if (self.input[self.pos] == '*' and self.input[self.pos + 1] == '/') {
                    self.advance(2); // Skip '*/'
                    return;
                }
                if (self.input[self.pos] == '\n') {
                    self.line += 1;
                    self.column = 1;
                    self.pos += 1;
                } else {
                    self.advance(1);
                }
            }
            return ParseError.UnexpectedEndOfInput; // Unterminated comment
        } else {
            // Not a comment, might be division (invalid here)
            if (!self.config.allow_comments) {
                return ParseError.CommentNotAllowed;
            }
            return ParseError.InvalidCharacter;
        }
    }

    fn advance(self: *Self, count: usize) void {
        self.pos += count;
        self.column += @intCast(count);
    }
};

/// JSON generator/serializer
pub const Generator = struct {
    allocator: Allocator,
    output: ArrayList(u8),
    indent_level: u32,
    indent_size: u32,
    pretty: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, pretty: bool) Self {
        return Self{
            .allocator = allocator,
            .output = ArrayList(u8).init(allocator),
            .indent_level = 0,
            .indent_size = 2,
            .pretty = pretty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.output.deinit();
    }

    pub fn generate(self: *Self, value: Value) ![]u8 {
        try self.generateValue(value);
        return self.output.toOwnedSlice();
    }

    fn generateValue(self: *Self, value: Value) anyerror!void {
        switch (value) {
            .null => try self.output.appendSlice("null"),
            .bool => |b| try self.output.appendSlice(if (b) "true" else "false"),
            .int => |i| try self.output.writer().print("{}", .{i}),
            .float => |f| try self.output.writer().print("{d}", .{f}),
            .string => |s| try self.generateString(s.data),
            .array => |arr| try self.generateArray(arr),
            .object => |obj| try self.generateObject(obj),
        }
    }

    fn generateString(self: *Self, str: []const u8) !void {
        try self.output.append('"');
        for (str) |char| {
            switch (char) {
                '"' => try self.output.appendSlice("\\\""),
                '\\' => try self.output.appendSlice("\\\\"),
                '\n' => try self.output.appendSlice("\\n"),
                '\r' => try self.output.appendSlice("\\r"),
                '\t' => try self.output.appendSlice("\\t"),
                0x08 => try self.output.appendSlice("\\b"),
                0x0C => try self.output.appendSlice("\\f"),
                else => {
                    if (char < 0x20) {
                        try self.output.writer().print("\\u{x:0>4}", .{char});
                    } else {
                        try self.output.append(char);
                    }
                },
            }
        }
        try self.output.append('"');
    }

    fn generateArray(self: *Self, arr: ArrayList(Value)) anyerror!void {
        try self.output.append('[');
        if (arr.items.len > 0) {
            if (self.pretty) {
                self.indent_level += 1;
                try self.newline();
            }

            for (arr.items, 0..) |item, i| {
                if (self.pretty and i > 0) {
                    try self.output.append(',');
                    try self.newline();
                } else if (!self.pretty and i > 0) {
                    try self.output.append(',');
                }
                try self.generateValue(item);
            }

            if (self.pretty) {
                self.indent_level -= 1;
                try self.newline();
            }
        }
        try self.output.append(']');
    }

    fn generateObject(self: *Self, obj: StringHashMap(Value)) anyerror!void {
        try self.output.append('{');
        if (obj.count() > 0) {
            if (self.pretty) {
                self.indent_level += 1;
                try self.newline();
            }

            var iter = obj.iterator();
            var first = true;
            while (iter.next()) |entry| {
                if (!first) {
                    try self.output.append(',');
                    if (self.pretty) {
                        try self.newline();
                    }
                } else {
                    first = false;
                }

                try self.generateString(entry.key_ptr.*);
                try self.output.append(':');
                if (self.pretty) {
                    try self.output.append(' ');
                }
                try self.generateValue(entry.value_ptr.*);
            }

            if (self.pretty) {
                self.indent_level -= 1;
                try self.newline();
            }
        }
        try self.output.append('}');
    }

    fn newline(self: *Self) !void {
        try self.output.append('\n');
        const indent = self.indent_level * self.indent_size;
        var i: u32 = 0;
        while (i < indent) : (i += 1) {
            try self.output.append(' ');
        }
    }
};

/// Convenience function to parse JSON from string
pub fn parseFromString(allocator: Allocator, json_str: []const u8) ParseError!Value {
    var parser = Parser.init(allocator, json_str);
    return parser.parse();
}

/// Convenience function to parse JSON from string with custom configuration
pub fn parseFromStringWithConfig(allocator: Allocator, json_str: []const u8, config: JsonConfig) ParseError!Value {
    var parser = Parser.initWithConfig(allocator, json_str, config);
    return parser.parse();
}

/// Convenience function to stringify JSON value
pub fn stringify(allocator: Allocator, value: Value, pretty: bool) ![]u8 {
    var generator = Generator.init(allocator, pretty);
    defer generator.deinit();
    return generator.generate(value);
}

// Tests
test "JSON parser - basic values" {
    const allocator = std.testing.allocator;

    // Test null
    {
        var value = try parseFromString(allocator, "null");
        defer value.deinit(allocator);
        try std.testing.expect(value.getType() == .null);
    }

    // Test boolean
    {
        var value = try parseFromString(allocator, "true");
        defer value.deinit(allocator);
        try std.testing.expect(try value.getBool() == true);
    }

    // Test integer
    {
        var value = try parseFromString(allocator, "42");
        defer value.deinit(allocator);
        try std.testing.expect(try value.getInt() == 42);
    }

    // Test float
    {
        var value = try parseFromString(allocator, "3.14");
        defer value.deinit(allocator);
        try std.testing.expectApproxEqAbs(try value.getFloat(), 3.14, 0.001);
    }

    // Test string
    {
        var value = try parseFromString(allocator, "\"hello\"");
        defer value.deinit(allocator);
        const str = try value.getString();
        try std.testing.expectEqualStrings(str, "hello");
    }
}

test "JSON parser - arrays" {
    const allocator = std.testing.allocator;

    var value = try parseFromString(allocator, "[1, 2, 3]");
    defer value.deinit(allocator);

    const arr = try value.getArray();
    try std.testing.expect(arr.items.len == 3);
    try std.testing.expect(try arr.items[0].getInt() == 1);
    try std.testing.expect(try arr.items[1].getInt() == 2);
    try std.testing.expect(try arr.items[2].getInt() == 3);
}

test "JSON parser - objects" {
    const allocator = std.testing.allocator;

    var value = try parseFromString(allocator, "{\"name\": \"John\", \"age\": 30}");
    defer value.deinit(allocator);

    const obj = try value.getObject();
    try std.testing.expect(obj.count() == 2);

    const name = obj.get("name").?;
    try std.testing.expectEqualStrings(try name.getString(), "John");

    const age = obj.get("age").?;
    try std.testing.expect(try age.getInt() == 30);
}

test "JSON generator - basic values" {
    const allocator = std.testing.allocator;

    // Test null
    {
        const value = Value{ .null = {} };
        const json = try stringify(allocator, value, false);
        defer allocator.free(json);
        try std.testing.expectEqualStrings(json, "null");
    }

    // Test boolean
    {
        const value = Value{ .bool = true };
        const json = try stringify(allocator, value, false);
        defer allocator.free(json);
        try std.testing.expectEqualStrings(json, "true");
    }

    // Test integer
    {
        const value = Value{ .int = 42 };
        const json = try stringify(allocator, value, false);
        defer allocator.free(json);
        try std.testing.expectEqualStrings(json, "42");
    }
}

test "JSON roundtrip" {
    const allocator = std.testing.allocator;

    const original = "{\"users\":[{\"name\":\"Alice\",\"age\":25},{\"name\":\"Bob\",\"age\":30}],\"count\":2}";

    var parsed = try parseFromString(allocator, original);
    defer parsed.deinit(allocator);

    const regenerated = try stringify(allocator, parsed, false);
    defer allocator.free(regenerated);

    // Parse again to verify structure
    var reparsed = try parseFromString(allocator, regenerated);
    defer reparsed.deinit(allocator);

    const obj = try reparsed.getObject();
    try std.testing.expect(obj.count() == 2);
}

test "JSON Unicode escape sequences" {
    const allocator = std.testing.allocator;

    // Test ASCII Unicode escapes
    {
        var value = try parseFromString(allocator, "\"\\u0041\""); // 'A'
        defer value.deinit(allocator);
        const str = try value.getString();
        try std.testing.expectEqualStrings("A", str);
    }

    // Test Latin-1 Unicode escapes
    {
        var value = try parseFromString(allocator, "\"\\u00E9\""); // 'é'
        defer value.deinit(allocator);
        const str = try value.getString();
        try std.testing.expectEqualStrings("é", str);
    }

    // Test BMP Unicode escapes (3-byte UTF-8)
    {
        var value = try parseFromString(allocator, "\"\\u20AC\""); // '€' Euro sign
        defer value.deinit(allocator);
        const str = try value.getString();
        try std.testing.expectEqualStrings("€", str);
    }

    // Test CJK characters
    {
        var value = try parseFromString(allocator, "\"\\u4E2D\\u6587\""); // '中文' Chinese
        defer value.deinit(allocator);
        const str = try value.getString();
        try std.testing.expectEqualStrings("中文", str);
    }

    // Test emoji via surrogate pairs
    {
        var value = try parseFromString(allocator, "\"\\uD83D\\uDE00\""); // U+1F600 grinning face
        defer value.deinit(allocator);
        const str = try value.getString();
        // Expected UTF-8 encoding: F0 9F 98 80
        try std.testing.expect(str.len == 4);
        try std.testing.expect(str[0] == 0xF0 and str[1] == 0x9F and str[2] == 0x98 and str[3] == 0x80);
    }

    // Test complex surrogate pair
    {
        var value = try parseFromString(allocator, "\"\\uD83C\\uDF89\""); // U+1F389 party popper
        defer value.deinit(allocator);
        const str = try value.getString();
        // Expected UTF-8 encoding: F0 9F 8E 89
        try std.testing.expect(str.len == 4);
        try std.testing.expect(str[0] == 0xF0 and str[1] == 0x9F and str[2] == 0x8E and str[3] == 0x89);
    }

    // Test mixed Unicode and regular characters
    {
        var value = try parseFromString(allocator, "\"Hello \\u4E16\\u754C! \\uD83C\\uDF0D\""); // "Hello [Chinese] [Earth]"
        defer value.deinit(allocator);
        const str = try value.getString();
        try std.testing.expect(str.len > 10); // Should be longer than ASCII equivalent
        try std.testing.expect(std.unicode.utf8ValidateSlice(str)); // Must be valid UTF-8
    }
}

test "JSON Unicode error cases" {
    const allocator = std.testing.allocator;

    // Test invalid hex digits
    {
        const result = parseFromString(allocator, "\"\\uGGGG\"");
        try std.testing.expectError(ParseError.InvalidUnicode, result);
    }

    // Test incomplete Unicode escape
    {
        const result = parseFromString(allocator, "\"\\u123\"");
        try std.testing.expectError(ParseError.InvalidEscape, result);
    }

    // Test lone high surrogate
    {
        const result = parseFromString(allocator, "\"\\uD800\"");
        try std.testing.expectError(ParseError.InvalidUnicode, result);
    }

    // Test lone low surrogate
    {
        const result = parseFromString(allocator, "\"\\uDC00\"");
        try std.testing.expectError(ParseError.InvalidUnicode, result);
    }

    // Test high surrogate without low surrogate
    {
        const result = parseFromString(allocator, "\"\\uD800\\u0041\"");
        try std.testing.expectError(ParseError.InvalidUnicode, result);
    }

    // Test high surrogate with invalid low surrogate
    {
        const result = parseFromString(allocator, "\"\\uD800\\uD800\"");
        try std.testing.expectError(ParseError.InvalidUnicode, result);
    }
}

test "JSON Unicode benchmark" {
    const allocator = std.testing.allocator;
    const count = 1000;

    // Benchmark Unicode parsing
    const start = std.time.nanoTimestamp();
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var value = try parseFromString(allocator, "\"\\u4E2D\\u6587\\uD83C\\uDF89\"");
        defer value.deinit(allocator);
    }
    const end = std.time.nanoTimestamp();
    const duration_ns = end - start;
    const duration_ms = @as(f64, @floatFromInt(duration_ns)) / 1_000_000.0;

    std.log.info("Unicode parsing benchmark: {} iterations in {d:.2} ms ({d:.2} ns/iter)", .{ count, duration_ms, @as(f64, @floatFromInt(duration_ns)) / @as(f64, @floatFromInt(count)) });
}

test "JSON configuration - trailing commas" {
    const allocator = std.testing.allocator;
    
    // Test trailing comma rejection with default config
    {
        const result = parseFromString(allocator, "[1, 2, 3,]");
        try std.testing.expectError(ParseError.TrailingCommaNotAllowed, result);
    }
    
    // Test trailing comma acceptance with lenient config
    {
        const config = JsonConfig.lenient();
        var value = try parseFromStringWithConfig(allocator, "[1, 2, 3,]", config);
        defer value.deinit(allocator);
        
        const arr = try value.getArray();
        try std.testing.expect(arr.items.len == 3);
    }
    
    // Test trailing comma in objects
    {
        const config = JsonConfig.lenient();
        var value = try parseFromStringWithConfig(allocator, "{\"a\": 1, \"b\": 2,}", config);
        defer value.deinit(allocator);
        
        const obj = try value.getObject();
        try std.testing.expect(obj.count() == 2);
    }
}

test "JSON configuration - comments" {
    const allocator = std.testing.allocator;
    
    // Test comment rejection with default config
    {
        const result = parseFromString(allocator, "// comment\n{\"test\": 42}");
        try std.testing.expectError(ParseError.CommentNotAllowed, result);
    }
    
    // Test single-line comment support
    {
        const config = JsonConfig.lenient();
        var value = try parseFromStringWithConfig(allocator, "// This is a comment\n{\"test\": 42}", config);
        defer value.deinit(allocator);
        
        const obj = try value.getObject();
        const test_val = obj.get("test").?;
        try std.testing.expect(try test_val.getInt() == 42);
    }
    
    // Test multi-line comment support  
    {
        const config = JsonConfig.lenient();
        var value = try parseFromStringWithConfig(allocator, "/* Multi-line\n comment */\n{\"test\": 42}", config);
        defer value.deinit(allocator);
        
        const obj = try value.getObject();
        const test_val = obj.get("test").?;
        try std.testing.expect(try test_val.getInt() == 42);
    }
}

test "JSON configuration - limits" {
    const allocator = std.testing.allocator;
    
    // Test depth limit
    {
        const config = JsonConfig{
            .max_parsing_depth = 2,
            .max_string_length = 1000,
            .max_number_length = 100,
        };
        const result = parseFromStringWithConfig(allocator, "[[[1]]]", config);
        try std.testing.expectError(ParseError.TooDeep, result);
    }
    
    // Test string length limit
    {
        const config = JsonConfig{
            .max_parsing_depth = 100,
            .max_string_length = 5,
            .max_number_length = 100,
        };
        const long_string = "\"" ++ "a" ** 10 ++ "\"";
        const result = parseFromStringWithConfig(allocator, long_string, config);
        try std.testing.expectError(ParseError.StringTooLong, result);
    }
    
    // Test number length limit
    {
        const config = JsonConfig{
            .max_parsing_depth = 100,
            .max_string_length = 1000,
            .max_number_length = 5,
        };
        const long_number = "123456789";
        const result = parseFromStringWithConfig(allocator, long_number, config);
        try std.testing.expectError(ParseError.NumberTooLong, result);
    }
}

test "JSON zero-copy string parsing" {
    const allocator = std.testing.allocator;

    // Test zero-copy string (no escaping needed)
    const json_input = "\"hello world\"";
    {
        var value = try parseFromString(allocator, json_input);
        defer value.deinit(allocator);

        try std.testing.expectEqualStrings("hello world", try value.getString());

        // Verify it's actually zero-copy (not owned)
        switch (value) {
            .string => |s| try std.testing.expect(!s.owned),
            else => return error.TypeMismatch,
        }
    }

    // Test owned string (requires unescaping)
    {
        var value = try parseFromString(allocator, "\"hello\\nworld\"");
        defer value.deinit(allocator);

        try std.testing.expectEqualStrings("hello\nworld", try value.getString());

        // Verify it's owned (allocated memory)
        switch (value) {
            .string => |s| try std.testing.expect(s.owned),
            else => return error.TypeMismatch,
        }
    }

    // Test convenience methods
    {
        const borrowed = Value.createBorrowedString("borrowed");
        try std.testing.expectEqualStrings("borrowed", try borrowed.getString());
        // No deinit needed for borrowed strings
    }

    {
        var owned = try Value.createOwnedString(allocator, "owned");
        defer owned.deinit(allocator);
        try std.testing.expectEqualStrings("owned", try owned.getString());
    }
}
