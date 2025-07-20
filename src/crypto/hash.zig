//! Cryptographic hash functions for Ferret
//!
//! This implementation provides:
//! - SHA-256, SHA-512 secure hash functions
//! - HMAC (Hash-based Message Authentication Code)
//! - BLAKE3 for high-performance hashing
//! - Streaming and one-shot APIs
//! - Type-safe digest handling
//! - Constant-time operations where applicable

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;

/// Hash algorithm identifiers
pub const Algorithm = enum {
    sha256,
    sha512,
    blake3,

    /// Get the digest length for this algorithm
    pub fn digestLength(self: Algorithm) u8 {
        return switch (self) {
            .sha256 => 32,
            .sha512 => 64,
            .blake3 => 32,
        };
    }

    /// Get the block size for this algorithm
    pub fn blockSize(self: Algorithm) u16 {
        return switch (self) {
            .sha256 => 64,
            .sha512 => 128,
            .blake3 => 64,
        };
    }
};

/// Generic digest wrapper for type safety
pub fn Digest(comptime algorithm: Algorithm) type {
    return struct {
        bytes: [algorithm.digestLength()]u8,

        const Self = @This();

        /// Create digest from byte array
        pub fn fromBytes(bytes: [algorithm.digestLength()]u8) Self {
            return Self{ .bytes = bytes };
        }

        /// Create digest from slice (must be exact length)
        pub fn fromSlice(data: []const u8) !Self {
            if (data.len != algorithm.digestLength()) {
                return error.InvalidDigestLength;
            }
            var digest: Self = undefined;
            @memcpy(&digest.bytes, data);
            return digest;
        }

        /// Get digest as byte slice
        pub fn slice(self: *const Self) []const u8 {
            return &self.bytes;
        }

        /// Format digest as lowercase hex string
        pub fn hex(self: *const Self, allocator: Allocator) ![]u8 {
            const hex_chars = "0123456789abcdef";
            var result = try allocator.alloc(u8, self.bytes.len * 2);
            for (self.bytes, 0..) |byte, i| {
                result[i * 2] = hex_chars[byte >> 4];
                result[i * 2 + 1] = hex_chars[byte & 0xf];
            }
            return result;
        }

        /// Parse digest from hex string
        pub fn fromHex(hex_str: []const u8) !Self {
            if (hex_str.len != algorithm.digestLength() * 2) {
                return error.InvalidHexLength;
            }
            var digest: Self = undefined;
            _ = try std.fmt.hexToBytes(&digest.bytes, hex_str);
            return digest;
        }

        /// Constant-time comparison
        pub fn eql(self: *const Self, other: *const Self) bool {
            var result: u8 = 0;
            for (self.bytes, other.bytes) |a, b| {
                result |= a ^ b;
            }
            return result == 0;
        }

        /// Copy digest bytes to provided buffer
        pub fn copyTo(self: *const Self, buffer: []u8) !void {
            if (buffer.len < algorithm.digestLength()) {
                return error.BufferTooSmall;
            }
            @memcpy(buffer[0..algorithm.digestLength()], &self.bytes);
        }
    };
}

/// SHA-256 digest type
pub const Sha256Digest = Digest(.sha256);

/// SHA-512 digest type
pub const Sha512Digest = Digest(.sha512);

/// BLAKE3 digest type
pub const Blake3Digest = Digest(.blake3);

/// Generic hasher interface
pub fn Hasher(comptime algorithm: Algorithm) type {
    const HashImpl = switch (algorithm) {
        .sha256 => crypto.hash.sha2.Sha256,
        .sha512 => crypto.hash.sha2.Sha512,
        .blake3 => crypto.hash.Blake3,
    };

    return struct {
        impl: HashImpl,

        const Self = @This();
        const DigestType = Digest(algorithm);

        /// Initialize hasher
        pub fn init() Self {
            return Self{ .impl = HashImpl.init(.{}) };
        }

        /// Update hasher with data
        pub fn update(self: *Self, data: []const u8) void {
            self.impl.update(data);
        }

        /// Finalize and get digest
        pub fn final(self: *Self) DigestType {
            var digest_bytes: [algorithm.digestLength()]u8 = undefined;
            self.impl.final(&digest_bytes);
            return DigestType.fromBytes(digest_bytes);
        }

        /// Reset hasher for reuse
        pub fn reset(self: *Self) void {
            self.impl = HashImpl.init(.{});
        }
    };
}

/// SHA-256 hasher
pub const Sha256 = Hasher(.sha256);

/// SHA-512 hasher
pub const Sha512 = Hasher(.sha512);

/// BLAKE3 hasher
pub const Blake3 = Hasher(.blake3);

/// One-shot hash functions
pub const Hash = struct {
    /// Compute SHA-256 hash of data
    pub fn sha256(data: []const u8) Sha256Digest {
        var hasher = Sha256.init();
        hasher.update(data);
        return hasher.final();
    }

    /// Compute SHA-512 hash of data
    pub fn sha512(data: []const u8) Sha512Digest {
        var hasher = Sha512.init();
        hasher.update(data);
        return hasher.final();
    }

    /// Compute BLAKE3 hash of data
    pub fn blake3(data: []const u8) Blake3Digest {
        var hasher = Blake3.init();
        hasher.update(data);
        return hasher.final();
    }
};

/// HMAC implementation
pub fn Hmac(comptime algorithm: Algorithm) type {
    const HashType = Hasher(algorithm);
    const DigestType = Digest(algorithm);
    const block_size = algorithm.blockSize();
    const digest_length = algorithm.digestLength();

    return struct {
        inner_hasher: HashType,
        outer_hasher: HashType,

        const Self = @This();

        /// Initialize HMAC with key
        pub fn init(key: []const u8) Self {
            var normalized_key: [block_size]u8 = [_]u8{0} ** block_size;

            if (key.len > block_size) {
                // Hash long keys
                var key_hasher = HashType.init();
                key_hasher.update(key);
                const key_digest = key_hasher.final();
                @memcpy(normalized_key[0..digest_length], key_digest.slice());
            } else {
                // Copy short keys
                @memcpy(normalized_key[0..key.len], key);
            }

            // Create inner and outer padding
            var inner_pad: [block_size]u8 = undefined;
            var outer_pad: [block_size]u8 = undefined;

            for (0..block_size) |i| {
                inner_pad[i] = normalized_key[i] ^ 0x36;
                outer_pad[i] = normalized_key[i] ^ 0x5c;
            }

            // Initialize hashers
            var inner_hasher = HashType.init();
            inner_hasher.update(&inner_pad);

            var outer_hasher = HashType.init();
            outer_hasher.update(&outer_pad);

            return Self{
                .inner_hasher = inner_hasher,
                .outer_hasher = outer_hasher,
            };
        }

        /// Update HMAC with data
        pub fn update(self: *Self, data: []const u8) void {
            self.inner_hasher.update(data);
        }

        /// Finalize and get HMAC digest
        pub fn final(self: *Self) DigestType {
            const inner_digest = self.inner_hasher.final();
            self.outer_hasher.update(inner_digest.slice());
            return self.outer_hasher.final();
        }
    };
}

/// HMAC-SHA256
pub const HmacSha256 = Hmac(.sha256);

/// HMAC-SHA512
pub const HmacSha512 = Hmac(.sha512);

/// HMAC-BLAKE3
pub const HmacBlake3 = Hmac(.blake3);

/// One-shot HMAC functions
pub const MacAuth = struct {
    /// Compute HMAC-SHA256
    pub fn hmacSha256(key: []const u8, data: []const u8) Sha256Digest {
        var hmac = HmacSha256.init(key);
        hmac.update(data);
        return hmac.final();
    }

    /// Compute HMAC-SHA512
    pub fn hmacSha512(key: []const u8, data: []const u8) Sha512Digest {
        var hmac = HmacSha512.init(key);
        hmac.update(data);
        return hmac.final();
    }

    /// Compute HMAC-BLAKE3
    pub fn hmacBlake3(key: []const u8, data: []const u8) Blake3Digest {
        var hmac = HmacBlake3.init(key);
        hmac.update(data);
        return hmac.final();
    }
};

/// Password-based key derivation
pub const Pbkdf2 = struct {
    /// PBKDF2 errors
    pub const Error = error{
        InvalidIterations,
        DerivedKeyTooLong,
        OutOfMemory,
    };

    /// PBKDF2 with HMAC-SHA256
    pub fn hmacSha256(allocator: Allocator, password: []const u8, salt: []const u8, iterations: u32, derived_key_len: usize) Error![]u8 {
        if (iterations == 0) return Error.InvalidIterations;
        if (derived_key_len > 0xffffffff * 32) return Error.DerivedKeyTooLong;

        const derived_key = try allocator.alloc(u8, derived_key_len);
        errdefer allocator.free(derived_key);

        var derived_pos: usize = 0;
        var block_index: u32 = 1;

        while (derived_pos < derived_key_len) {
            var hmac = HmacSha256.init(password);
            hmac.update(salt);

            // Add block index as big-endian u32
            const block_bytes = mem.toBytes(mem.nativeToBig(u32, block_index));
            hmac.update(&block_bytes);

            var u = hmac.final();
            var result = u;

            // Iterate
            for (1..iterations) |_| {
                hmac = HmacSha256.init(password);
                hmac.update(u.slice());
                u = hmac.final();

                // XOR with result
                for (0..32) |i| {
                    result.bytes[i] ^= u.bytes[i];
                }
            }

            // Copy to derived key
            const copy_len = @min(32, derived_key_len - derived_pos);
            @memcpy(derived_key[derived_pos .. derived_pos + copy_len], result.slice()[0..copy_len]);
            derived_pos += copy_len;
            block_index += 1;
        }

        return derived_key;
    }
};

/// Secure random number generation
pub const Random = struct {
    /// Generate cryptographically secure random bytes
    pub fn bytes(buffer: []u8) void {
        crypto.random.bytes(buffer);
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

    /// Generate random bytes and encode as hex
    pub fn hex(allocator: Allocator, length: usize) ![]u8 {
        const random_bytes = try allocator.alloc(u8, length);
        defer allocator.free(random_bytes);

        crypto.random.bytes(random_bytes);
        const hex_chars = "0123456789abcdef";
        var result = try allocator.alloc(u8, length * 2);
        for (random_bytes, 0..) |byte, i| {
            result[i * 2] = hex_chars[byte >> 4];
            result[i * 2 + 1] = hex_chars[byte & 0xf];
        }
        return result;
    }
};

// Tests
test "Hash - SHA256 one-shot" {
    const data = "hello world";
    const digest = Hash.sha256(data);

    // Known SHA256 hash of "hello world"
    const expected = try Sha256Digest.fromHex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    try testing.expect(digest.eql(&expected));
}

test "Hash - SHA256 streaming" {
    var hasher = Sha256.init();
    hasher.update("hello ");
    hasher.update("world");
    const digest = hasher.final();

    const expected = try Sha256Digest.fromHex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    try testing.expect(digest.eql(&expected));
}

test "Hash - BLAKE3" {
    const data = "hello world";
    const digest = Hash.blake3(data);

    // Verify digest length
    try testing.expect(digest.slice().len == 32);

    // Test hex formatting
    const hex_str = try digest.hex(testing.allocator);
    defer testing.allocator.free(hex_str);
    try testing.expect(hex_str.len == 64);
}

test "HMAC - SHA256" {
    const key = "secret key";
    const data = "hello world";

    const mac = MacAuth.hmacSha256(key, data);

    // Test streaming API
    var hmac = HmacSha256.init(key);
    hmac.update("hello ");
    hmac.update("world");
    const mac2 = hmac.final();

    try testing.expect(mac.eql(&mac2));
}

test "Digest - hex conversion" {
    const data = "test";
    const digest = Hash.sha256(data);

    const hex_str = try digest.hex(testing.allocator);
    defer testing.allocator.free(hex_str);

    const parsed_digest = try Sha256Digest.fromHex(hex_str);
    try testing.expect(digest.eql(&parsed_digest));
}

test "PBKDF2 - basic derivation" {
    const password = "password";
    const salt = "salt";
    const iterations = 1000;
    const key_len = 32;

    const derived_key = try Pbkdf2.hmacSha256(testing.allocator, password, salt, iterations, key_len);
    defer testing.allocator.free(derived_key);

    try testing.expect(derived_key.len == key_len);

    // Ensure deterministic
    const derived_key2 = try Pbkdf2.hmacSha256(testing.allocator, password, salt, iterations, key_len);
    defer testing.allocator.free(derived_key2);

    try testing.expectEqualSlices(u8, derived_key, derived_key2);
}

test "Random - generation" {
    var buffer1: [32]u8 = undefined;
    var buffer2: [32]u8 = undefined;

    Random.bytes(&buffer1);
    Random.bytes(&buffer2);

    // Should be different (probability of collision is negligible)
    try testing.expect(!mem.eql(u8, &buffer1, &buffer2));

    // Test hex generation
    const hex_str = try Random.hex(testing.allocator, 16);
    defer testing.allocator.free(hex_str);
    try testing.expect(hex_str.len == 32); // 16 bytes = 32 hex chars
}

test "Algorithm - properties" {
    try testing.expect(Algorithm.sha256.digestLength() == 32);
    try testing.expect(Algorithm.sha512.digestLength() == 64);
    try testing.expect(Algorithm.blake3.digestLength() == 32);

    try testing.expect(Algorithm.sha256.blockSize() == 64);
    try testing.expect(Algorithm.sha512.blockSize() == 128);
    try testing.expect(Algorithm.blake3.blockSize() == 64);
}
