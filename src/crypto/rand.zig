//! Cryptographically secure random number generation for Ferret
//!
//! This implementation provides:
//! - Cryptographically secure random number generation
//! - Multiple distribution types (uniform, normal, exponential)
//! - UUID generation (v4)
//! - Random string and identifier generation
//! - Seeded deterministic random for testing

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const math = std.math;
const testing = std.testing;
const Allocator = mem.Allocator;

/// Cryptographically secure random number generator
pub const SecureRandom = struct {
    /// Fill buffer with cryptographically secure random bytes
    pub fn bytes(buffer: []u8) void {
        crypto.random.bytes(buffer);
    }

    /// Generate random u8
    pub fn randomU8() u8 {
        var buffer: [1]u8 = undefined;
        crypto.random.bytes(&buffer);
        return buffer[0];
    }

    /// Generate random u16
    pub fn randomU16() u16 {
        var buffer: [2]u8 = undefined;
        crypto.random.bytes(&buffer);
        return mem.readInt(u16, &buffer, .little);
    }

    /// Generate random u32
    pub fn randomU32() u32 {
        var buffer: [4]u8 = undefined;
        crypto.random.bytes(&buffer);
        return mem.readInt(u32, &buffer, .little);
    }

    /// Generate random u64
    pub fn randomU64() u64 {
        var buffer: [8]u8 = undefined;
        crypto.random.bytes(&buffer);
        return mem.readInt(u64, &buffer, .little);
    }

    /// Generate random integer in range [min, max)
    pub fn intRange(comptime T: type, min: T, max: T) T {
        if (min >= max) return min;
        const range = max - min;
        const rand_val = switch (T) {
            u8 => randomU8(),
            u16 => randomU16(),
            u32 => randomU32(),
            u64 => randomU64(),
            usize => if (@sizeOf(usize) == 8) @as(usize, randomU64()) else @as(usize, randomU32()),
            else => @compileError("Unsupported type for intRange"),
        };
        return min + (rand_val % range);
    }

    /// Generate random float in range [0.0, 1.0)
    pub fn float(comptime T: type) T {
        return switch (T) {
            f32 => @as(f32, @floatFromInt(randomU32())) / @as(f32, @floatFromInt(math.maxInt(u32))),
            f64 => @as(f64, @floatFromInt(randomU64())) / @as(f64, @floatFromInt(math.maxInt(u64))),
            else => @compileError("Unsupported type for float"),
        };
    }

    /// Generate random float in range [min, max)
    pub fn floatRange(comptime T: type, min: T, max: T) T {
        return min + (max - min) * float(T);
    }

    /// Generate random boolean
    pub fn boolean() bool {
        return (randomU8() & 1) == 1;
    }

    /// Choose random element from slice
    pub fn choice(comptime T: type, slice: []const T) ?T {
        if (slice.len == 0) return null;
        const index = intRange(usize, 0, slice.len);
        return slice[index];
    }

    /// Shuffle slice in place using Fisher-Yates algorithm
    pub fn shuffle(comptime T: type, slice: []T) void {
        if (slice.len <= 1) return;
        var i = slice.len - 1;
        while (i > 0) : (i -= 1) {
            const j = intRange(usize, 0, i + 1);
            mem.swap(T, &slice[i], &slice[j]);
        }
    }
};

/// UUID v4 generation (random)
pub const Uuid = struct {
    bytes: [16]u8,

    const Self = @This();

    /// Generate random UUID v4
    pub fn v4() Self {
        var uuid: Self = undefined;
        SecureRandom.bytes(&uuid.bytes);

        // Set version (4) and variant bits according to RFC 4122
        uuid.bytes[6] = (uuid.bytes[6] & 0x0f) | 0x40; // Version 4
        uuid.bytes[8] = (uuid.bytes[8] & 0x3f) | 0x80; // Variant bits

        return uuid;
    }

    /// Parse UUID from string (with or without hyphens)
    pub fn fromString(str: []const u8) !Self {
        var uuid: Self = undefined;
        var clean_str: [32]u8 = undefined;
        var clean_len: usize = 0;

        // Remove hyphens
        for (str) |char| {
            if (char != '-') {
                if (clean_len >= 32) return error.InvalidUuidFormat;
                clean_str[clean_len] = char;
                clean_len += 1;
            }
        }

        if (clean_len != 32) return error.InvalidUuidFormat;

        // Parse hex
        _ = try std.fmt.hexToBytes(&uuid.bytes, clean_str[0..32]);
        return uuid;
    }

    /// Format as standard UUID string with hyphens
    pub fn toString(self: *const Self, allocator: Allocator) ![]u8 {
        const hex_chars = "0123456789abcdef";
        var result = try allocator.alloc(u8, 36); // 32 hex + 4 hyphens

        var i: usize = 0;
        var pos: usize = 0;

        while (i < 16) : (i += 1) {
            const byte = self.bytes[i];
            result[pos] = hex_chars[byte >> 4];
            result[pos + 1] = hex_chars[byte & 0xf];
            pos += 2;

            // Add hyphens at positions 8, 13, 18, 23
            if (pos == 8 or pos == 13 or pos == 18 or pos == 23) {
                result[pos] = '-';
                pos += 1;
            }
        }

        return result;
    }

    /// Format as compact hex string (no hyphens)
    pub fn toHex(self: *const Self, allocator: Allocator) ![]u8 {
        const hex_chars = "0123456789abcdef";
        var result = try allocator.alloc(u8, 32);
        for (self.bytes, 0..) |byte, i| {
            result[i * 2] = hex_chars[byte >> 4];
            result[i * 2 + 1] = hex_chars[byte & 0xf];
        }
        return result;
    }

    /// Get bytes as slice
    pub fn slice(self: *const Self) []const u8 {
        return &self.bytes;
    }
};

/// Random string generation
pub const RandomString = struct {
    /// Character sets for different string types
    pub const charset_alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    pub const charset_lowercase = "abcdefghijklmnopqrstuvwxyz";
    pub const charset_uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    pub const charset_digits = "0123456789";
    pub const charset_hex = "0123456789abcdef";
    pub const charset_base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    pub const charset_base64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Generate random string from character set
    pub fn fromCharset(allocator: Allocator, length: usize, charset: []const u8) ![]u8 {
        if (charset.len == 0) return error.EmptyCharset;

        const result = try allocator.alloc(u8, length);
        for (result) |*char| {
            char.* = charset[SecureRandom.intRange(usize, 0, charset.len)];
        }
        return result;
    }

    /// Generate alphanumeric string
    pub fn alphanumeric(allocator: Allocator, length: usize) ![]u8 {
        return fromCharset(allocator, length, charset_alphanumeric);
    }

    /// Generate lowercase string
    pub fn lowercase(allocator: Allocator, length: usize) ![]u8 {
        return fromCharset(allocator, length, charset_lowercase);
    }

    /// Generate hex string
    pub fn hex(allocator: Allocator, length: usize) ![]u8 {
        return fromCharset(allocator, length, charset_hex);
    }

    /// Generate Base58 string (useful for IDs)
    pub fn base58(allocator: Allocator, length: usize) ![]u8 {
        return fromCharset(allocator, length, charset_base58);
    }

    /// Generate URL-safe Base64 string
    pub fn base64url(allocator: Allocator, length: usize) ![]u8 {
        return fromCharset(allocator, length, charset_base64url);
    }

    /// Generate secure token (URL-safe, high entropy)
    pub fn token(allocator: Allocator, length: usize) ![]u8 {
        return base64url(allocator, length);
    }
};

/// Pseudo-random number generator for testing and deterministic scenarios
pub const PseudoRandom = struct {
    rng: std.Random.Xoshiro256,

    const Self = @This();

    /// Initialize with seed
    pub fn init(seed: u64) Self {
        return Self{
            .rng = std.Random.Xoshiro256.init(seed),
        };
    }

    /// Generate random bytes (deterministic)
    pub fn bytes(self: *Self, buffer: []u8) void {
        self.rng.random().bytes(buffer);
    }

    /// Generate random u32
    pub fn randomU32(self: *Self) u32 {
        return self.rng.random().int(u32);
    }

    /// Generate random u64
    pub fn randomU64(self: *Self) u64 {
        return self.rng.random().int(u64);
    }

    /// Generate random integer in range [min, max)
    pub fn intRange(self: *Self, comptime T: type, min: T, max: T) T {
        return self.rng.random().intRangeLessThan(T, min, max);
    }

    /// Generate random float in range [0.0, 1.0)
    pub fn float(self: *Self, comptime T: type) T {
        return self.rng.random().float(T);
    }

    /// Choose random element from slice
    pub fn choice(self: *Self, comptime T: type, slice: []const T) ?T {
        if (slice.len == 0) return null;
        const index = self.intRange(usize, 0, slice.len);
        return slice[index];
    }

    /// Shuffle slice in place
    pub fn shuffle(self: *Self, comptime T: type, slice: []T) void {
        self.rng.random().shuffle(T, slice);
    }
};

/// Distribution functions
pub const Distribution = struct {
    /// Generate normally distributed random number (Box-Muller transform)
    pub fn normal(mean: f64, std_dev: f64) f64 {
        // Static variables for Box-Muller
        const Static = struct {
            var has_spare: bool = false;
            var spare: f64 = undefined;
        };

        if (Static.has_spare) {
            Static.has_spare = false;
            return Static.spare * std_dev + mean;
        }

        Static.has_spare = true;
        const u = SecureRandom.float(f64);
        const v = SecureRandom.float(f64);
        const mag = std_dev * @sqrt(-2.0 * @log(u));
        Static.spare = mag * @cos(2.0 * math.pi * v);
        return mag * @sin(2.0 * math.pi * v) + mean;
    }

    /// Generate exponentially distributed random number
    pub fn exponential(lambda: f64) f64 {
        const u = SecureRandom.float(f64);
        return -@log(1.0 - u) / lambda;
    }
};

// Tests
test "SecureRandom - basic generation" {
    // Test basic integer generation
    const val1 = SecureRandom.randomU32();
    const val2 = SecureRandom.randomU32();
    try testing.expect(val1 != val2); // Very unlikely to be equal

    // Test range
    for (0..100) |_| {
        const val = SecureRandom.intRange(u32, 10, 20);
        try testing.expect(val >= 10 and val < 20);
    }

    // Test float range
    const f = SecureRandom.floatRange(f64, 1.0, 2.0);
    try testing.expect(f >= 1.0 and f < 2.0);
}

test "UUID - v4 generation and formatting" {
    const uuid1 = Uuid.v4();
    const uuid2 = Uuid.v4();

    // Should be different
    try testing.expect(!mem.eql(u8, uuid1.slice(), uuid2.slice()));

    // Check version and variant bits
    try testing.expect((uuid1.bytes[6] & 0xf0) == 0x40); // Version 4
    try testing.expect((uuid1.bytes[8] & 0xc0) == 0x80); // Variant bits

    // Test string formatting
    const str = try uuid1.toString(testing.allocator);
    defer testing.allocator.free(str);
    try testing.expect(str.len == 36); // Standard UUID format

    // Test parsing
    const parsed = try Uuid.fromString(str);
    try testing.expectEqualSlices(u8, uuid1.slice(), parsed.slice());
}

test "RandomString - generation" {
    // Test alphanumeric
    const alphanum = try RandomString.alphanumeric(testing.allocator, 16);
    defer testing.allocator.free(alphanum);
    try testing.expect(alphanum.len == 16);

    // Test hex
    const hex_str = try RandomString.hex(testing.allocator, 32);
    defer testing.allocator.free(hex_str);
    try testing.expect(hex_str.len == 32);

    // Verify hex characters
    for (hex_str) |char| {
        try testing.expect((char >= '0' and char <= '9') or
            (char >= 'a' and char <= 'f'));
    }
}

test "PseudoRandom - deterministic" {
    var rng1 = PseudoRandom.init(12345);
    var rng2 = PseudoRandom.init(12345);

    // Same seed should produce same values
    try testing.expect(rng1.randomU32() == rng2.randomU32());
    try testing.expect(rng1.randomU64() == rng2.randomU64());

    // Test range
    const val = rng1.intRange(u32, 5, 15);
    try testing.expect(val >= 5 and val < 15);
}

test "SecureRandom - array operations" {
    var data = [_]u32{ 1, 2, 3, 4, 5 };
    const original = data;

    // Shuffle
    SecureRandom.shuffle(u32, &data);

    // Should contain same elements (though order may be same by chance)
    var sorted_data = data;
    var sorted_original = original;
    mem.sort(u32, &sorted_data, {}, comptime std.sort.asc(u32));
    mem.sort(u32, &sorted_original, {}, comptime std.sort.asc(u32));
    try testing.expectEqualSlices(u32, &sorted_original, &sorted_data);

    // Test choice
    const choice = SecureRandom.choice(u32, &data);
    try testing.expect(choice != null);
    try testing.expect(mem.indexOfScalar(u32, &data, choice.?) != null);
}

test "Distribution - normal and exponential" {
    // Test normal distribution (basic sanity check)
    var sum: f64 = 0;
    const count = 1000;
    for (0..count) |_| {
        sum += Distribution.normal(0.0, 1.0);
    }
    const mean = sum / @as(f64, @floatFromInt(count));

    // Should be roughly centered around 0 (within reasonable tolerance)
    try testing.expect(@abs(mean) < 0.2);

    // Test exponential (should be positive)
    for (0..100) |_| {
        const val = Distribution.exponential(1.0);
        try testing.expect(val >= 0.0);
    }
}
