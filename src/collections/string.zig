//! Binary-safe string implementation for Ferret
//!
//! Provides a mutable string type with efficient operations and
//! explicit memory management through allocators.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Binary-safe dynamic string implementation
pub const String = struct {
    const Self = @This();

    data: []u8,
    len: usize,
    allocator: Allocator,

    /// Initialize empty string
    pub fn init(allocator: Allocator) Self {
        return Self{
            .data = &[_]u8{},
            .len = 0,
            .allocator = allocator,
        };
    }

    /// Initialize string with capacity
    pub fn initCapacity(allocator: Allocator, initial_capacity: usize) !Self {
        if (initial_capacity == 0) {
            return init(allocator);
        }

        const data = try allocator.alloc(u8, initial_capacity);
        return Self{
            .data = data,
            .len = 0,
            .allocator = allocator,
        };
    }

    /// Initialize from slice (copies data)
    pub fn initFromSlice(allocator: Allocator, input: []const u8) !Self {
        if (input.len == 0) {
            return init(allocator);
        }

        const data = try allocator.dupe(u8, input);
        return Self{
            .data = data,
            .len = input.len,
            .allocator = allocator,
        };
    }

    /// Take ownership of existing slice
    pub fn fromSlice(allocator: Allocator, input: []u8) Self {
        return Self{
            .data = input,
            .len = input.len,
            .allocator = allocator,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: *Self) void {
        if (self.data.len > 0) {
            self.allocator.free(self.data);
        }
    }

    /// Get current length
    pub fn length(self: Self) usize {
        return self.len;
    }

    /// Get current capacity
    pub fn capacity(self: Self) usize {
        return self.data.len;
    }

    /// Check if string is empty
    pub fn isEmpty(self: Self) bool {
        return self.len == 0;
    }

    /// Get byte at index
    pub fn at(self: Self, index: usize) u8 {
        return self.data[index];
    }

    /// Get byte at index with bounds checking
    pub fn get(self: Self, index: usize) ?u8 {
        if (index >= self.len) {
            return null;
        }
        return self.data[index];
    }

    /// Set byte at index
    pub fn set(self: *Self, index: usize, byte: u8) !void {
        if (index >= self.len) {
            return error.IndexOutOfBounds;
        }
        self.data[index] = byte;
    }

    /// Get slice view of string content
    pub fn slice(self: Self) []const u8 {
        return self.data[0..self.len];
    }

    /// Get mutable slice view of string content
    pub fn sliceMut(self: *Self) []u8 {
        return self.data[0..self.len];
    }

    /// Ensure capacity for at least `new_capacity` bytes
    pub fn ensureCapacity(self: *Self, new_capacity: usize) !void {
        if (new_capacity <= self.data.len) {
            return;
        }

        const better_capacity = growCapacity(self.data.len, new_capacity);
        return self.ensureTotalCapacity(better_capacity);
    }

    /// Ensure exact capacity
    pub fn ensureTotalCapacity(self: *Self, new_capacity: usize) !void {
        if (new_capacity <= self.data.len) {
            return;
        }

        if (self.allocator.resize(self.data, new_capacity)) {
            self.data.len = new_capacity;
        } else {
            const new_data = try self.allocator.alloc(u8, new_capacity);
            @memcpy(new_data[0..self.len], self.data[0..self.len]);

            if (self.data.len > 0) {
                self.allocator.free(self.data);
            }

            self.data = new_data;
        }
    }

    /// Append a single byte
    pub fn append(self: *Self, byte: u8) !void {
        try self.ensureCapacity(self.len + 1);
        self.data[self.len] = byte;
        self.len += 1;
    }

    /// Append a slice of bytes
    pub fn appendSlice(self: *Self, bytes: []const u8) !void {
        if (bytes.len == 0) return;

        try self.ensureCapacity(self.len + bytes.len);
        @memcpy(self.data[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    /// Append another string
    pub fn appendString(self: *Self, other: String) !void {
        try self.appendSlice(other.slice());
    }

    /// Append formatted string
    pub fn print(self: *Self, comptime fmt: []const u8, args: anytype) !void {
        // Simple implementation using ArrayList-style formatting
        const formatted = try std.fmt.allocPrint(self.allocator, fmt, args);
        defer self.allocator.free(formatted);
        try self.appendSlice(formatted);
    }

    /// Get a writer for the string
    pub fn writer(self: *Self) Writer {
        return Writer{ .context = self };
    }

    pub const Writer = std.io.GenericWriter(*String, Allocator.Error, writeToString);

    fn writeToString(string: *String, bytes: []const u8) Allocator.Error!usize {
        try string.appendSlice(bytes);
        return bytes.len;
    }

    /// Insert byte at index
    pub fn insert(self: *Self, index: usize, byte: u8) !void {
        if (index > self.len) {
            return error.IndexOutOfBounds;
        }

        try self.ensureCapacity(self.len + 1);

        if (index < self.len) {
            std.mem.copyBackwards(u8, self.data[index + 1 .. self.len + 1], self.data[index..self.len]);
        }

        self.data[index] = byte;
        self.len += 1;
    }

    /// Insert slice at index
    pub fn insertSlice(self: *Self, index: usize, bytes: []const u8) !void {
        if (index > self.len) {
            return error.IndexOutOfBounds;
        }

        if (bytes.len == 0) return;

        try self.ensureCapacity(self.len + bytes.len);

        if (index < self.len) {
            std.mem.copyBackwards(u8, self.data[index + bytes.len .. self.len + bytes.len], self.data[index..self.len]);
        }

        @memcpy(self.data[index .. index + bytes.len], bytes);
        self.len += bytes.len;
    }

    /// Remove byte at index
    pub fn remove(self: *Self, index: usize) !u8 {
        if (index >= self.len) {
            return error.IndexOutOfBounds;
        }

        const byte = self.data[index];

        if (index < self.len - 1) {
            std.mem.copyForwards(u8, self.data[index .. self.len - 1], self.data[index + 1 .. self.len]);
        }

        self.len -= 1;
        return byte;
    }

    /// Remove range of bytes
    pub fn removeRange(self: *Self, start: usize, end: usize) !void {
        if (start > end or end > self.len) {
            return error.InvalidRange;
        }

        if (start == end) return;

        const remove_len = end - start;

        if (end < self.len) {
            std.mem.copyForwards(u8, self.data[start .. self.len - remove_len], self.data[end..self.len]);
        }

        self.len -= remove_len;
    }

    /// Pop last byte
    pub fn pop(self: *Self) ?u8 {
        if (self.len == 0) {
            return null;
        }

        self.len -= 1;
        return self.data[self.len];
    }

    /// Clear string but keep capacity
    pub fn clear(self: *Self) void {
        self.len = 0;
    }

    /// Resize string to new length, filling with byte if growing
    pub fn resize(self: *Self, new_len: usize, fill_byte: u8) !void {
        if (new_len > self.len) {
            try self.ensureCapacity(new_len);
            @memset(self.data[self.len..new_len], fill_byte);
        }
        self.len = new_len;
    }

    /// Check if string starts with prefix
    pub fn startsWith(self: Self, prefix: []const u8) bool {
        if (prefix.len > self.len) {
            return false;
        }
        return std.mem.eql(u8, self.data[0..prefix.len], prefix);
    }

    /// Check if string ends with suffix
    pub fn endsWith(self: Self, suffix: []const u8) bool {
        if (suffix.len > self.len) {
            return false;
        }
        const start = self.len - suffix.len;
        return std.mem.eql(u8, self.data[start..self.len], suffix);
    }

    /// Check if string contains substring
    pub fn contains(self: Self, needle: []const u8) bool {
        return self.find(needle) != null;
    }

    /// Find first occurrence of substring
    pub fn find(self: Self, needle: []const u8) ?usize {
        if (needle.len == 0) return 0;
        if (needle.len > self.len) return null;

        const haystack = self.slice();
        return std.mem.indexOf(u8, haystack, needle);
    }

    /// Find last occurrence of substring
    pub fn findLast(self: Self, needle: []const u8) ?usize {
        if (needle.len == 0) return self.len;
        if (needle.len > self.len) return null;

        const haystack = self.slice();
        return std.mem.lastIndexOf(u8, haystack, needle);
    }

    /// Replace all occurrences of needle with replacement
    pub fn replace(self: *Self, needle: []const u8, replacement: []const u8) !void {
        if (needle.len == 0) return;

        var result = String.init(self.allocator);
        defer result.deinit();

        var start: usize = 0;
        while (start < self.len) {
            if (self.find(needle)) |pos| {
                if (pos < start) break; // Found earlier occurrence

                // Add text before match
                try result.appendSlice(self.data[start..pos]);
                // Add replacement
                try result.appendSlice(replacement);
                start = pos + needle.len;
            } else {
                // No more matches, add rest of string
                try result.appendSlice(self.data[start..self.len]);
                break;
            }
        }

        // Replace our data with the result
        self.deinit();
        self.* = result;
        result = String.init(self.allocator); // Prevent double-free
    }

    /// Split string by delimiter
    pub fn split(self: Self, delimiter: []const u8, allocator: Allocator) ![]String {
        if (delimiter.len == 0) {
            return error.EmptyDelimiter;
        }

        var parts = std.ArrayList(String).init(allocator);
        defer parts.deinit();

        var start: usize = 0;
        const data = self.slice();

        while (std.mem.indexOf(u8, data[start..], delimiter)) |pos| {
            const absolute_pos = start + pos;
            const part = try String.initFromSlice(allocator, data[start..absolute_pos]);
            try parts.append(part);
            start = absolute_pos + delimiter.len;
        }

        // Add the remaining part
        const part = try String.initFromSlice(allocator, data[start..]);
        try parts.append(part);

        return parts.toOwnedSlice();
    }

    /// Trim whitespace from both ends
    pub fn trim(self: Self) []const u8 {
        return std.mem.trim(u8, self.slice(), " \t\n\r");
    }

    /// Convert to lowercase in-place
    pub fn toLower(self: *Self) void {
        for (self.data[0..self.len]) |*byte| {
            byte.* = std.ascii.toLower(byte.*);
        }
    }

    /// Convert to uppercase in-place
    pub fn toUpper(self: *Self) void {
        for (self.data[0..self.len]) |*byte| {
            byte.* = std.ascii.toUpper(byte.*);
        }
    }

    /// Clone string with new allocator
    pub fn clone(self: Self, allocator: Allocator) !Self {
        return Self.initFromSlice(allocator, self.slice());
    }

    /// Create owned slice copy
    pub fn toOwned(self: Self, allocator: Allocator) ![]u8 {
        return allocator.dupe(u8, self.slice());
    }

    /// Compare strings for equality
    pub fn eql(self: Self, other: []const u8) bool {
        return std.mem.eql(u8, self.slice(), other);
    }

    /// Compare strings lexicographically
    pub fn cmp(self: Self, other: []const u8) std.math.Order {
        return std.mem.order(u8, self.slice(), other);
    }
};

/// Calculate better capacity for growing strings
fn growCapacity(current: usize, minimum: usize) usize {
    var new_capacity = current;
    while (true) {
        new_capacity +|= new_capacity / 2 + 8;
        if (new_capacity >= minimum) {
            return new_capacity;
        }
    }
}

test "String basic operations" {
    const allocator = std.testing.allocator;

    var str = String.init(allocator);
    defer str.deinit();

    try std.testing.expect(str.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), str.length());

    try str.appendSlice("Hello");
    try std.testing.expectEqual(@as(usize, 5), str.length());
    try std.testing.expectEqualStrings("Hello", str.slice());

    try str.append(' ');
    try str.appendSlice("World!");
    try std.testing.expectEqualStrings("Hello World!", str.slice());

    try std.testing.expectEqual(@as(u8, 'H'), str.at(0));
    try std.testing.expectEqual(@as(?u8, '!'), str.get(11));
    try std.testing.expectEqual(@as(?u8, null), str.get(20));
}

test "String insertion and removal" {
    const allocator = std.testing.allocator;

    var str = try String.initFromSlice(allocator, "Hello World!");
    defer str.deinit();

    try str.insert(5, ',');
    try std.testing.expectEqualStrings("Hello, World!", str.slice());

    _ = try str.remove(5);
    try std.testing.expectEqualStrings("Hello World!", str.slice());

    try str.removeRange(5, 11);
    try std.testing.expectEqualStrings("Hello!", str.slice());

    const popped = str.pop();
    try std.testing.expectEqual(@as(?u8, '!'), popped);
    try std.testing.expectEqualStrings("Hello", str.slice());
}

test "String search operations" {
    const allocator = std.testing.allocator;

    var str = try String.initFromSlice(allocator, "Hello World Hello");
    defer str.deinit();

    try std.testing.expect(str.startsWith("Hello"));
    try std.testing.expect(!str.startsWith("World"));

    try std.testing.expect(str.endsWith("Hello"));
    try std.testing.expect(!str.endsWith("World"));

    try std.testing.expect(str.contains("World"));
    try std.testing.expect(!str.contains("xyz"));

    try std.testing.expectEqual(@as(?usize, 0), str.find("Hello"));
    try std.testing.expectEqual(@as(?usize, 12), str.findLast("Hello"));
    try std.testing.expectEqual(@as(?usize, null), str.find("xyz"));
}

test "String formatting" {
    const allocator = std.testing.allocator;

    var str = String.init(allocator);
    defer str.deinit();

    try str.print("Hello {s}! The answer is {d}.", .{ "World", 42 });
    try std.testing.expectEqualStrings("Hello World! The answer is 42.", str.slice());

    str.clear();
    const writer = str.writer();
    try writer.writeAll("Test ");
    try writer.writeByte('X');
    try writer.print(" {d}", .{123});

    try std.testing.expectEqualStrings("Test X 123", str.slice());
}

test "String manipulation" {
    const allocator = std.testing.allocator;

    var str = try String.initFromSlice(allocator, "HELLO world");
    defer str.deinit();

    str.toLower();
    try std.testing.expectEqualStrings("hello world", str.slice());

    str.toUpper();
    try std.testing.expectEqualStrings("HELLO WORLD", str.slice());

    try str.replace("WORLD", "ZIG");
    try std.testing.expectEqualStrings("HELLO ZIG", str.slice());
}
