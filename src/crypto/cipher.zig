//! Symmetric encryption ciphers for Ferret
//!
//! This implementation provides:
//! - AES-256-GCM for authenticated encryption
//! - ChaCha20-Poly1305 for high-performance AEAD
//! - Secure key generation and management
//! - Type-safe nonce handling
//! - Streaming encryption/decryption APIs

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;

/// Cipher algorithm identifiers
pub const Algorithm = enum {
    aes256_gcm,
    chacha20_poly1305,

    /// Get key length for this algorithm
    pub fn keyLength(self: Algorithm) u8 {
        return switch (self) {
            .aes256_gcm => 32,
            .chacha20_poly1305 => 32,
        };
    }

    /// Get nonce length for this algorithm
    pub fn nonceLength(self: Algorithm) u8 {
        return switch (self) {
            .aes256_gcm => 12,
            .chacha20_poly1305 => 12,
        };
    }

    /// Get authentication tag length
    pub fn tagLength(self: Algorithm) u8 {
        return switch (self) {
            .aes256_gcm => 16,
            .chacha20_poly1305 => 16,
        };
    }
};

/// Generic key wrapper for type safety
pub fn Key(comptime algorithm: Algorithm) type {
    return struct {
        bytes: [algorithm.keyLength()]u8,

        const Self = @This();

        /// Create key from byte array
        pub fn fromBytes(bytes: [algorithm.keyLength()]u8) Self {
            return Self{ .bytes = bytes };
        }

        /// Create key from slice (must be exact length)
        pub fn fromSlice(data: []const u8) !Self {
            if (data.len != algorithm.keyLength()) {
                return error.InvalidKeyLength;
            }
            var key: Self = undefined;
            @memcpy(&key.bytes, data);
            return key;
        }

        /// Get key as byte slice
        pub fn slice(self: *const Self) []const u8 {
            return &self.bytes;
        }

        /// Generate random key
        pub fn random() Self {
            var key: Self = undefined;
            crypto.random.bytes(&key.bytes);
            return key;
        }

        /// Securely clear key from memory
        pub fn clear(self: *Self) void {
            @memset(&self.bytes, 0);
        }
    };
}

/// Generic nonce wrapper for type safety
pub fn Nonce(comptime algorithm: Algorithm) type {
    return struct {
        bytes: [algorithm.nonceLength()]u8,

        const Self = @This();

        /// Create nonce from byte array
        pub fn fromBytes(bytes: [algorithm.nonceLength()]u8) Self {
            return Self{ .bytes = bytes };
        }

        /// Create nonce from slice (must be exact length)
        pub fn fromSlice(data: []const u8) !Self {
            if (data.len != algorithm.nonceLength()) {
                return error.InvalidNonceLength;
            }
            var nonce: Self = undefined;
            @memcpy(&nonce.bytes, data);
            return nonce;
        }

        /// Get nonce as byte slice
        pub fn slice(self: *const Self) []const u8 {
            return &self.bytes;
        }

        /// Generate random nonce
        pub fn random() Self {
            var nonce: Self = undefined;
            crypto.random.bytes(&nonce.bytes);
            return nonce;
        }

        /// Create nonce from counter (useful for CTR mode)
        pub fn fromCounter(counter: u64) Self {
            var nonce: Self = undefined;
            @memset(&nonce.bytes, 0);
            // Put counter in last 8 bytes, big-endian
            const counter_bytes = mem.toBytes(mem.nativeToBig(u64, counter));
            const offset = nonce.bytes.len - 8;
            @memcpy(nonce.bytes[offset..], &counter_bytes);
            return nonce;
        }
    };
}

/// Generic authentication tag wrapper
pub fn Tag(comptime algorithm: Algorithm) type {
    return struct {
        bytes: [algorithm.tagLength()]u8,

        const Self = @This();

        /// Create tag from byte array
        pub fn fromBytes(bytes: [algorithm.tagLength()]u8) Self {
            return Self{ .bytes = bytes };
        }

        /// Create tag from slice (must be exact length)
        pub fn fromSlice(data: []const u8) !Self {
            if (data.len != algorithm.tagLength()) {
                return error.InvalidTagLength;
            }
            var tag: Self = undefined;
            @memcpy(&tag.bytes, data);
            return tag;
        }

        /// Get tag as byte slice
        pub fn slice(self: *const Self) []const u8 {
            return &self.bytes;
        }

        /// Constant-time comparison
        pub fn eql(self: *const Self, other: *const Self) bool {
            var result: u8 = 0;
            for (self.bytes, other.bytes) |a, b| {
                result |= a ^ b;
            }
            return result == 0;
        }
    };
}

/// AES-256-GCM key, nonce, and tag types
pub const Aes256GcmKey = Key(.aes256_gcm);
pub const Aes256GcmNonce = Nonce(.aes256_gcm);
pub const Aes256GcmTag = Tag(.aes256_gcm);

/// ChaCha20-Poly1305 key, nonce, and tag types
pub const ChaCha20Poly1305Key = Key(.chacha20_poly1305);
pub const ChaCha20Poly1305Nonce = Nonce(.chacha20_poly1305);
pub const ChaCha20Poly1305Tag = Tag(.chacha20_poly1305);

/// Encryption/decryption errors
pub const CipherError = error{
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidTagLength,
    AuthenticationFailed,
    OutOfMemory,
};

/// AES-256-GCM implementation
pub const Aes256Gcm = struct {
    /// Encrypt data with AES-256-GCM
    pub fn encrypt(
        allocator: Allocator,
        plaintext: []const u8,
        additional_data: ?[]const u8,
        key: Aes256GcmKey,
        nonce: Aes256GcmNonce,
    ) CipherError!struct { ciphertext: []u8, tag: Aes256GcmTag } {
        const ciphertext = try allocator.alloc(u8, plaintext.len);
        errdefer allocator.free(ciphertext);

        var tag_bytes: [16]u8 = undefined;
        crypto.aead.aes_gcm.Aes256Gcm.encrypt(
            ciphertext,
            &tag_bytes,
            plaintext,
            additional_data orelse &[_]u8{},
            nonce.bytes,
            key.bytes,
        );

        return .{
            .ciphertext = ciphertext,
            .tag = Aes256GcmTag.fromBytes(tag_bytes),
        };
    }

    /// Decrypt data with AES-256-GCM
    pub fn decrypt(
        allocator: Allocator,
        ciphertext: []const u8,
        tag: Aes256GcmTag,
        additional_data: ?[]const u8,
        key: Aes256GcmKey,
        nonce: Aes256GcmNonce,
    ) CipherError![]u8 {
        const plaintext = try allocator.alloc(u8, ciphertext.len);
        errdefer allocator.free(plaintext);

        crypto.aead.aes_gcm.Aes256Gcm.decrypt(
            plaintext,
            ciphertext,
            tag.bytes,
            additional_data orelse &[_]u8{},
            nonce.bytes,
            key.bytes,
        ) catch {
            return CipherError.AuthenticationFailed;
        };

        return plaintext;
    }
};

/// ChaCha20-Poly1305 implementation
pub const ChaCha20Poly1305 = struct {
    /// Encrypt data with ChaCha20-Poly1305
    pub fn encrypt(
        allocator: Allocator,
        plaintext: []const u8,
        additional_data: ?[]const u8,
        key: ChaCha20Poly1305Key,
        nonce: ChaCha20Poly1305Nonce,
    ) CipherError!struct { ciphertext: []u8, tag: ChaCha20Poly1305Tag } {
        const ciphertext = try allocator.alloc(u8, plaintext.len);
        errdefer allocator.free(ciphertext);

        var tag_bytes: [16]u8 = undefined;
        crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext,
            &tag_bytes,
            plaintext,
            additional_data orelse &[_]u8{},
            nonce.bytes,
            key.bytes,
        );

        return .{
            .ciphertext = ciphertext,
            .tag = ChaCha20Poly1305Tag.fromBytes(tag_bytes),
        };
    }

    /// Decrypt data with ChaCha20-Poly1305
    pub fn decrypt(
        allocator: Allocator,
        ciphertext: []const u8,
        tag: ChaCha20Poly1305Tag,
        additional_data: ?[]const u8,
        key: ChaCha20Poly1305Key,
        nonce: ChaCha20Poly1305Nonce,
    ) CipherError![]u8 {
        const plaintext = try allocator.alloc(u8, ciphertext.len);
        errdefer allocator.free(plaintext);

        crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext,
            tag.bytes,
            additional_data orelse &[_]u8{},
            nonce.bytes,
            key.bytes,
        ) catch {
            return CipherError.AuthenticationFailed;
        };

        return plaintext;
    }
};

/// Convenience functions for common encryption patterns
pub const Cipher = struct {
    /// Encrypt with AES-256-GCM using random nonce
    pub fn encryptAes256Gcm(
        allocator: Allocator,
        plaintext: []const u8,
        additional_data: ?[]const u8,
        key: Aes256GcmKey,
    ) CipherError!struct { ciphertext: []u8, nonce: Aes256GcmNonce, tag: Aes256GcmTag } {
        const nonce = Aes256GcmNonce.random();
        const result = try Aes256Gcm.encrypt(allocator, plaintext, additional_data, key, nonce);
        return .{
            .ciphertext = result.ciphertext,
            .nonce = nonce,
            .tag = result.tag,
        };
    }

    /// Encrypt with ChaCha20-Poly1305 using random nonce
    pub fn encryptChaCha20Poly1305(
        allocator: Allocator,
        plaintext: []const u8,
        additional_data: ?[]const u8,
        key: ChaCha20Poly1305Key,
    ) CipherError!struct { ciphertext: []u8, nonce: ChaCha20Poly1305Nonce, tag: ChaCha20Poly1305Tag } {
        const nonce = ChaCha20Poly1305Nonce.random();
        const result = try ChaCha20Poly1305.encrypt(allocator, plaintext, additional_data, key, nonce);
        return .{
            .ciphertext = result.ciphertext,
            .nonce = nonce,
            .tag = result.tag,
        };
    }
};

/// Secure key derivation from password
pub const KeyDerivation = struct {
    /// Derive AES-256-GCM key from password using PBKDF2
    pub fn deriveAes256GcmKey(
        allocator: Allocator,
        password: []const u8,
        salt: []const u8,
        iterations: u32,
    ) !Aes256GcmKey {
        const hash = @import("hash.zig");
        const derived_key = try hash.Pbkdf2.hmacSha256(allocator, password, salt, iterations, 32);
        defer allocator.free(derived_key);

        return Aes256GcmKey.fromSlice(derived_key);
    }

    /// Derive ChaCha20-Poly1305 key from password using PBKDF2
    pub fn deriveChaCha20Poly1305Key(
        allocator: Allocator,
        password: []const u8,
        salt: []const u8,
        iterations: u32,
    ) !ChaCha20Poly1305Key {
        const hash = @import("hash.zig");
        const derived_key = try hash.Pbkdf2.hmacSha256(allocator, password, salt, iterations, 32);
        defer allocator.free(derived_key);

        return ChaCha20Poly1305Key.fromSlice(derived_key);
    }
};

// Tests
test "AES-256-GCM - encryption and decryption" {
    const plaintext = "Hello, secure world!";
    const additional_data = "metadata";
    const key = Aes256GcmKey.random();
    const nonce = Aes256GcmNonce.random();

    // Encrypt
    const encrypted = try Aes256Gcm.encrypt(
        testing.allocator,
        plaintext,
        additional_data,
        key,
        nonce,
    );
    defer testing.allocator.free(encrypted.ciphertext);

    // Decrypt
    const decrypted = try Aes256Gcm.decrypt(
        testing.allocator,
        encrypted.ciphertext,
        encrypted.tag,
        additional_data,
        key,
        nonce,
    );
    defer testing.allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "ChaCha20-Poly1305 - encryption and decryption" {
    const plaintext = "Hello, fast world!";
    const key = ChaCha20Poly1305Key.random();
    const nonce = ChaCha20Poly1305Nonce.random();

    // Encrypt
    const encrypted = try ChaCha20Poly1305.encrypt(
        testing.allocator,
        plaintext,
        null, // No additional data
        key,
        nonce,
    );
    defer testing.allocator.free(encrypted.ciphertext);

    // Decrypt
    const decrypted = try ChaCha20Poly1305.decrypt(
        testing.allocator,
        encrypted.ciphertext,
        encrypted.tag,
        null,
        key,
        nonce,
    );
    defer testing.allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "Cipher - convenience functions" {
    const plaintext = "Test message";
    const key = Aes256GcmKey.random();

    // Encrypt with random nonce
    const encrypted = try Cipher.encryptAes256Gcm(
        testing.allocator,
        plaintext,
        null,
        key,
    );
    defer testing.allocator.free(encrypted.ciphertext);

    // Decrypt
    const decrypted = try Aes256Gcm.decrypt(
        testing.allocator,
        encrypted.ciphertext,
        encrypted.tag,
        null,
        key,
        encrypted.nonce,
    );
    defer testing.allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "Key - type safety and operations" {
    // Test key generation
    const key1 = Aes256GcmKey.random();
    const key2 = Aes256GcmKey.random();

    // Keys should be different
    try testing.expect(!mem.eql(u8, key1.slice(), key2.slice()));

    // Test key from slice
    const key_data = [_]u8{0} ** 32;
    const key3 = try Aes256GcmKey.fromSlice(&key_data);
    try testing.expectEqualSlices(u8, &key_data, key3.slice());

    // Test invalid length
    const invalid_data = [_]u8{0} ** 16;
    try testing.expectError(error.InvalidKeyLength, Aes256GcmKey.fromSlice(&invalid_data));
}

test "Nonce - counter mode" {
    const nonce1 = ChaCha20Poly1305Nonce.fromCounter(0);
    const nonce2 = ChaCha20Poly1305Nonce.fromCounter(1);

    // Should be different
    try testing.expect(!mem.eql(u8, nonce1.slice(), nonce2.slice()));

    // Should have counter in last 8 bytes
    try testing.expect(nonce1.slice()[4] == 0); // First part should be zero
    try testing.expect(nonce2.slice()[11] == 1); // Last byte should be 1
}

test "Authentication - tag verification" {
    const plaintext = "Important data";
    const key = Aes256GcmKey.random();
    const nonce = Aes256GcmNonce.random();

    // Encrypt
    const encrypted = try Aes256Gcm.encrypt(
        testing.allocator,
        plaintext,
        null,
        key,
        nonce,
    );
    defer testing.allocator.free(encrypted.ciphertext);

    // Tamper with tag
    var tampered_tag = encrypted.tag;
    tampered_tag.bytes[0] ^= 1;

    // Should fail to decrypt
    try testing.expectError(
        error.AuthenticationFailed,
        Aes256Gcm.decrypt(
            testing.allocator,
            encrypted.ciphertext,
            tampered_tag,
            null,
            key,
            nonce,
        ),
    );
}

test "Algorithm - properties" {
    try testing.expect(Algorithm.aes256_gcm.keyLength() == 32);
    try testing.expect(Algorithm.aes256_gcm.nonceLength() == 12);
    try testing.expect(Algorithm.aes256_gcm.tagLength() == 16);

    try testing.expect(Algorithm.chacha20_poly1305.keyLength() == 32);
    try testing.expect(Algorithm.chacha20_poly1305.nonceLength() == 12);
    try testing.expect(Algorithm.chacha20_poly1305.tagLength() == 16);
}
