//! Asymmetric cryptography for Ferret
//!
//! This implementation provides:
//! - Elliptic Curve Diffie-Hellman (ECDH) key exchange
//! - Digital signatures (ECDSA, Ed25519)
//! - Public key encryption (X25519)
//! - Key generation and management
//! - Type-safe key handling
//! - Secure key serialization/deserialization

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const assert = std.debug.assert;

/// Asymmetric cryptography errors
pub const AsymmetricError = error{
    InvalidKeyLength,
    InvalidSignatureLength,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidSignature,
    KeyGenerationFailed,
    SignatureFailed,
    VerificationFailed,
    KeyExchangeFailed,
    OutOfMemory,
};

/// Key exchange algorithms
pub const KeyExchangeAlgorithm = enum {
    x25519,

    /// Get private key length for this algorithm
    pub fn privateKeyLength(self: KeyExchangeAlgorithm) u8 {
        return switch (self) {
            .x25519 => 32,
        };
    }

    /// Get public key length for this algorithm
    pub fn publicKeyLength(self: KeyExchangeAlgorithm) u8 {
        return switch (self) {
            .x25519 => 32,
        };
    }

    /// Get shared secret length for this algorithm
    pub fn sharedSecretLength(self: KeyExchangeAlgorithm) u8 {
        return switch (self) {
            .x25519 => 32,
        };
    }
};

/// Digital signature algorithms
pub const SignatureAlgorithm = enum {
    ed25519,
    ecdsa_secp256k1,

    /// Get private key length for this algorithm
    pub fn privateKeyLength(self: SignatureAlgorithm) u8 {
        return switch (self) {
            .ed25519 => 64, // Ed25519 secret key in std.crypto is 64 bytes
            .ecdsa_secp256k1 => 32,
        };
    }

    /// Get public key length for this algorithm
    pub fn publicKeyLength(self: SignatureAlgorithm) u8 {
        return switch (self) {
            .ed25519 => 32,
            .ecdsa_secp256k1 => 33, // Compressed format
        };
    }

    /// Get signature length for this algorithm
    pub fn signatureLength(self: SignatureAlgorithm) u8 {
        return switch (self) {
            .ed25519 => 64,
            .ecdsa_secp256k1 => 64,
        };
    }
};

/// Generic key exchange implementation
pub fn KeyExchange(comptime algorithm: KeyExchangeAlgorithm) type {
    return struct {
        /// Private key
        pub const PrivateKey = struct {
            bytes: [algorithm.privateKeyLength()]u8,

            const Self = @This();

            /// Generate new private key
            pub fn generate() Self {
                var key: Self = undefined;
                crypto.random.bytes(&key.bytes);
                return key;
            }

            /// Create private key from bytes
            pub fn fromBytes(bytes: [algorithm.privateKeyLength()]u8) Self {
                return Self{ .bytes = bytes };
            }

            /// Create private key from slice
            pub fn fromSlice(data: []const u8) AsymmetricError!Self {
                if (data.len != algorithm.privateKeyLength()) {
                    return AsymmetricError.InvalidKeyLength;
                }
                var key: Self = undefined;
                @memcpy(&key.bytes, data);
                return key;
            }

            /// Get private key as byte slice
            pub fn slice(self: *const Self) []const u8 {
                return &self.bytes;
            }

            /// Derive public key from private key
            pub fn publicKey(self: *const Self) AsymmetricError!PublicKey {
                switch (algorithm) {
                    .x25519 => {
                        const public_bytes = crypto.dh.X25519.recoverPublicKey(self.bytes) catch {
                            return AsymmetricError.KeyGenerationFailed;
                        };
                        return PublicKey.fromBytes(public_bytes);
                    },
                }
            }

            /// Perform key exchange to generate shared secret
            pub fn exchange(self: *const Self, peer_public: PublicKey) AsymmetricError!SharedSecret {
                switch (algorithm) {
                    .x25519 => {
                        const shared_bytes = crypto.dh.X25519.scalarmult(self.bytes, peer_public.bytes) catch {
                            return AsymmetricError.KeyExchangeFailed;
                        };
                        return SharedSecret.fromBytes(shared_bytes);
                    },
                }
            }

            /// Securely clear private key from memory
            pub fn clear(self: *Self) void {
                @memset(&self.bytes, 0);
            }
        };

        /// Public key
        pub const PublicKey = struct {
            bytes: [algorithm.publicKeyLength()]u8,

            const Self = @This();

            /// Create public key from bytes
            pub fn fromBytes(bytes: [algorithm.publicKeyLength()]u8) Self {
                return Self{ .bytes = bytes };
            }

            /// Create public key from slice
            pub fn fromSlice(data: []const u8) AsymmetricError!Self {
                if (data.len != algorithm.publicKeyLength()) {
                    return AsymmetricError.InvalidKeyLength;
                }
                var key: Self = undefined;
                @memcpy(&key.bytes, data);
                return key;
            }

            /// Get public key as byte slice
            pub fn slice(self: *const Self) []const u8 {
                return &self.bytes;
            }

            /// Encode public key as hexadecimal
            pub fn hex(self: *const Self, allocator: Allocator) ![]u8 {
                const hex_chars = "0123456789abcdef";
                var result = try allocator.alloc(u8, self.bytes.len * 2);
                for (self.bytes, 0..) |byte, i| {
                    result[i * 2] = hex_chars[byte >> 4];
                    result[i * 2 + 1] = hex_chars[byte & 0xf];
                }
                return result;
            }

            /// Parse public key from hexadecimal
            pub fn fromHex(hex_str: []const u8) AsymmetricError!Self {
                if (hex_str.len != algorithm.publicKeyLength() * 2) {
                    return AsymmetricError.InvalidKeyLength;
                }
                var key: Self = undefined;
                _ = std.fmt.hexToBytes(&key.bytes, hex_str) catch {
                    return AsymmetricError.InvalidPublicKey;
                };
                return key;
            }
        };

        /// Shared secret from key exchange
        pub const SharedSecret = struct {
            bytes: [algorithm.sharedSecretLength()]u8,

            const Self = @This();

            /// Create shared secret from bytes
            pub fn fromBytes(bytes: [algorithm.sharedSecretLength()]u8) Self {
                return Self{ .bytes = bytes };
            }

            /// Get shared secret as byte slice
            pub fn slice(self: *const Self) []const u8 {
                return &self.bytes;
            }

            /// Derive symmetric key from shared secret using HKDF
            pub fn deriveKey(self: *const Self, allocator: Allocator, info: []const u8, length: usize) ![]u8 {
                // TODO: Implement proper HKDF when available in std.crypto
                // For now, use HMAC-based key derivation
                const hash = @import("hash.zig");

                // Use shared secret as HMAC key, info as data
                const hmac_result = hash.MacAuth.hmacSha256(self.slice(), info);

                if (length <= 32) {
                    const result = try allocator.alloc(u8, length);
                    @memcpy(result, hmac_result.slice()[0..length]);
                    return result;
                } else {
                    // For longer keys, concatenate multiple HMAC rounds
                    const result = try allocator.alloc(u8, length);
                    var offset: usize = 0;
                    var counter: u8 = 1;

                    while (offset < length) {
                        var hmac_input = std.ArrayList(u8).init(allocator);
                        defer hmac_input.deinit();

                        try hmac_input.appendSlice(info);
                        try hmac_input.append(counter);

                        const hmac_result_round = hash.MacAuth.hmacSha256(self.slice(), hmac_input.items);
                        const copy_len = @min(32, length - offset);
                        @memcpy(result[offset .. offset + copy_len], hmac_result_round.slice()[0..copy_len]);

                        offset += copy_len;
                        counter += 1;
                    }

                    return result;
                }
            }

            /// Securely clear shared secret from memory
            pub fn clear(self: *Self) void {
                @memset(&self.bytes, 0);
            }
        };

        /// Generate a new key pair
        pub fn generateKeyPair() AsymmetricError!struct { private_key: PrivateKey, public_key: PublicKey } {
            const private_key = PrivateKey.generate();
            const public_key = try private_key.publicKey();
            return .{ .private_key = private_key, .public_key = public_key };
        }
    };
}

/// Generic digital signature implementation
pub fn Signature(comptime algorithm: SignatureAlgorithm) type {
    return struct {
        /// Private signing key
        pub const PrivateKey = struct {
            bytes: [algorithm.privateKeyLength()]u8,

            const Self = @This();

            /// Generate new private key
            pub fn generate() Self {
                switch (algorithm) {
                    .ed25519 => {
                        // Use Zig's built-in Ed25519 key generation
                        const keypair = crypto.sign.Ed25519.KeyPair.generate();
                        return Self{ .bytes = keypair.secret_key.bytes };
                    },
                    .ecdsa_secp256k1 => {
                        var key: Self = undefined;
                        crypto.random.bytes(&key.bytes);
                        return key;
                    },
                }
            }

            /// Create private key from bytes
            pub fn fromBytes(bytes: [algorithm.privateKeyLength()]u8) Self {
                return Self{ .bytes = bytes };
            }

            /// Create private key from slice
            pub fn fromSlice(data: []const u8) AsymmetricError!Self {
                if (data.len != algorithm.privateKeyLength()) {
                    return AsymmetricError.InvalidKeyLength;
                }
                var key: Self = undefined;
                @memcpy(&key.bytes, data);
                return key;
            }

            /// Get private key as byte slice
            pub fn slice(self: *const Self) []const u8 {
                return &self.bytes;
            }

            /// Derive public key from private key
            pub fn publicKey(self: *const Self) AsymmetricError!PublicKey {
                switch (algorithm) {
                    .ed25519 => {
                        const secret_key = crypto.sign.Ed25519.SecretKey.fromBytes(self.bytes) catch {
                            return AsymmetricError.InvalidPrivateKey;
                        };
                        const keypair = crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch {
                            return AsymmetricError.KeyGenerationFailed;
                        };
                        return PublicKey.fromBytes(keypair.public_key.bytes);
                    },
                    .ecdsa_secp256k1 => {
                        // TODO: Implement ECDSA secp256k1 when available in std.crypto
                        return AsymmetricError.KeyGenerationFailed;
                    },
                }
            }

            /// Sign message
            pub fn sign(self: *const Self, message: []const u8) AsymmetricError!SignatureValue {
                switch (algorithm) {
                    .ed25519 => {
                        const secret_key = crypto.sign.Ed25519.SecretKey.fromBytes(self.bytes) catch {
                            return AsymmetricError.InvalidPrivateKey;
                        };
                        const keypair = crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key) catch {
                            return AsymmetricError.SignatureFailed;
                        };
                        const signature = keypair.sign(message, null) catch {
                            return AsymmetricError.SignatureFailed;
                        };
                        return SignatureValue.fromBytes(signature.toBytes());
                    },
                    .ecdsa_secp256k1 => {
                        // TODO: Implement ECDSA secp256k1 when available in std.crypto
                        return AsymmetricError.SignatureFailed;
                    },
                }
            }

            /// Securely clear private key from memory
            pub fn clear(self: *Self) void {
                @memset(&self.bytes, 0);
            }
        };

        /// Public verification key
        pub const PublicKey = struct {
            bytes: [algorithm.publicKeyLength()]u8,

            const Self = @This();

            /// Create public key from bytes
            pub fn fromBytes(bytes: [algorithm.publicKeyLength()]u8) Self {
                return Self{ .bytes = bytes };
            }

            /// Create public key from slice
            pub fn fromSlice(data: []const u8) AsymmetricError!Self {
                if (data.len != algorithm.publicKeyLength()) {
                    return AsymmetricError.InvalidKeyLength;
                }
                var key: Self = undefined;
                @memcpy(&key.bytes, data);
                return key;
            }

            /// Get public key as byte slice
            pub fn slice(self: *const Self) []const u8 {
                return &self.bytes;
            }

            /// Verify signature
            pub fn verify(self: *const Self, signature: SignatureValue, message: []const u8) bool {
                switch (algorithm) {
                    .ed25519 => {
                        const public_key = crypto.sign.Ed25519.PublicKey.fromBytes(self.bytes) catch {
                            return false;
                        };
                        const sig = crypto.sign.Ed25519.Signature.fromBytes(signature.bytes);
                        sig.verify(message, public_key) catch {
                            return false;
                        };
                        return true;
                    },
                    .ecdsa_secp256k1 => {
                        // TODO: Implement ECDSA secp256k1 when available in std.crypto
                        return false;
                    },
                }
            }

            /// Encode public key as hexadecimal
            pub fn hex(self: *const Self, allocator: Allocator) ![]u8 {
                const hex_chars = "0123456789abcdef";
                var result = try allocator.alloc(u8, self.bytes.len * 2);
                for (self.bytes, 0..) |byte, i| {
                    result[i * 2] = hex_chars[byte >> 4];
                    result[i * 2 + 1] = hex_chars[byte & 0xf];
                }
                return result;
            }

            /// Parse public key from hexadecimal
            pub fn fromHex(hex_str: []const u8) AsymmetricError!Self {
                if (hex_str.len != algorithm.publicKeyLength() * 2) {
                    return AsymmetricError.InvalidKeyLength;
                }
                var key: Self = undefined;
                _ = std.fmt.hexToBytes(&key.bytes, hex_str) catch {
                    return AsymmetricError.InvalidPublicKey;
                };
                return key;
            }
        };

        /// Digital signature value
        pub const SignatureValue = struct {
            bytes: [algorithm.signatureLength()]u8,

            const Self = @This();

            /// Create signature from bytes
            pub fn fromBytes(bytes: [algorithm.signatureLength()]u8) Self {
                return Self{ .bytes = bytes };
            }

            /// Create signature from slice
            pub fn fromSlice(data: []const u8) AsymmetricError!Self {
                if (data.len != algorithm.signatureLength()) {
                    return AsymmetricError.InvalidSignatureLength;
                }
                var signature: Self = undefined;
                @memcpy(&signature.bytes, data);
                return signature;
            }

            /// Get signature as byte slice
            pub fn slice(self: *const Self) []const u8 {
                return &self.bytes;
            }

            /// Encode signature as hexadecimal
            pub fn hex(self: *const Self, allocator: Allocator) ![]u8 {
                const hex_chars = "0123456789abcdef";
                var result = try allocator.alloc(u8, self.bytes.len * 2);
                for (self.bytes, 0..) |byte, i| {
                    result[i * 2] = hex_chars[byte >> 4];
                    result[i * 2 + 1] = hex_chars[byte & 0xf];
                }
                return result;
            }

            /// Parse signature from hexadecimal
            pub fn fromHex(hex_str: []const u8) AsymmetricError!Self {
                if (hex_str.len != algorithm.signatureLength() * 2) {
                    return AsymmetricError.InvalidSignatureLength;
                }
                var signature: Self = undefined;
                _ = std.fmt.hexToBytes(&signature.bytes, hex_str) catch {
                    return AsymmetricError.InvalidSignature;
                };
                return signature;
            }
        };

        /// Generate a new signing key pair
        pub fn generateKeyPair() AsymmetricError!struct { private_key: PrivateKey, public_key: PublicKey } {
            switch (algorithm) {
                .ed25519 => {
                    // Use Zig's built-in Ed25519 key pair generation
                    const keypair = crypto.sign.Ed25519.KeyPair.generate();
                    const private_key = PrivateKey.fromBytes(keypair.secret_key.bytes);
                    const public_key = PublicKey.fromBytes(keypair.public_key.bytes);
                    return .{ .private_key = private_key, .public_key = public_key };
                },
                .ecdsa_secp256k1 => {
                    const private_key = PrivateKey.generate();
                    const public_key = try private_key.publicKey();
                    return .{ .private_key = private_key, .public_key = public_key };
                },
            }
        }
    };
}

/// X25519 key exchange
pub const X25519 = KeyExchange(.x25519);

/// Ed25519 digital signatures
pub const Ed25519 = Signature(.ed25519);

/// ECDSA with secp256k1 curve (placeholder for future implementation)
pub const EcdsaSecp256k1 = Signature(.ecdsa_secp256k1);

/// High-level key management utilities
pub const KeyManager = struct {
    /// Generate and store a key pair for key exchange
    pub const KeyExchangeKeyPair = struct {
        algorithm: KeyExchangeAlgorithm,
        private_key: []u8,
        public_key: []u8,
        allocator: Allocator,

        const Self = @This();

        /// Generate new key exchange key pair
        pub fn generate(allocator: Allocator, algorithm: KeyExchangeAlgorithm) !Self {
            switch (algorithm) {
                .x25519 => {
                    const keypair = try X25519.generateKeyPair();
                    const private_key = try allocator.dupe(u8, keypair.private_key.slice());
                    const public_key = try allocator.dupe(u8, keypair.public_key.slice());

                    return Self{
                        .algorithm = algorithm,
                        .private_key = private_key,
                        .public_key = public_key,
                        .allocator = allocator,
                    };
                },
            }
        }

        /// Perform key exchange
        pub fn exchange(self: *const Self, peer_public_key: []const u8) ![]u8 {
            switch (self.algorithm) {
                .x25519 => {
                    const private = try X25519.PrivateKey.fromSlice(self.private_key);
                    const peer_public = try X25519.PublicKey.fromSlice(peer_public_key);
                    const shared_secret = try private.exchange(peer_public);

                    return self.allocator.dupe(u8, shared_secret.slice());
                },
            }
        }

        /// Cleanup allocated memory
        pub fn deinit(self: *Self) void {
            // Clear sensitive data
            @memset(self.private_key, 0);
            self.allocator.free(self.private_key);
            self.allocator.free(self.public_key);
        }
    };

    /// Generate and store a key pair for digital signatures
    pub const SignatureKeyPair = struct {
        algorithm: SignatureAlgorithm,
        private_key: []u8,
        public_key: []u8,
        allocator: Allocator,

        const Self = @This();

        /// Generate new signature key pair
        pub fn generate(allocator: Allocator, algorithm: SignatureAlgorithm) !Self {
            switch (algorithm) {
                .ed25519 => {
                    const keypair = try Ed25519.generateKeyPair();
                    const private_key = try allocator.dupe(u8, keypair.private_key.slice());
                    const public_key = try allocator.dupe(u8, keypair.public_key.slice());

                    return Self{
                        .algorithm = algorithm,
                        .private_key = private_key,
                        .public_key = public_key,
                        .allocator = allocator,
                    };
                },
                .ecdsa_secp256k1 => {
                    return AsymmetricError.KeyGenerationFailed;
                },
            }
        }

        /// Sign message
        pub fn sign(self: *const Self, message: []const u8) ![]u8 {
            switch (self.algorithm) {
                .ed25519 => {
                    const private = try Ed25519.PrivateKey.fromSlice(self.private_key);
                    const signature = try private.sign(message);

                    return self.allocator.dupe(u8, signature.slice());
                },
                .ecdsa_secp256k1 => {
                    return AsymmetricError.SignatureFailed;
                },
            }
        }

        /// Cleanup allocated memory
        pub fn deinit(self: *Self) void {
            // Clear sensitive data
            @memset(self.private_key, 0);
            self.allocator.free(self.private_key);
            self.allocator.free(self.public_key);
        }
    };
};

// Tests
test "X25519 - key exchange" {
    // Generate two key pairs
    const alice_keypair = try X25519.generateKeyPair();
    const bob_keypair = try X25519.generateKeyPair();

    // Perform key exchange
    const alice_shared = try alice_keypair.private_key.exchange(bob_keypair.public_key);
    const bob_shared = try bob_keypair.private_key.exchange(alice_keypair.public_key);

    // Shared secrets should be equal
    try testing.expectEqualSlices(u8, alice_shared.slice(), bob_shared.slice());
}

test "X25519 - key derivation" {
    const keypair = try X25519.generateKeyPair();
    const peer_keypair = try X25519.generateKeyPair();

    const shared_secret = try keypair.private_key.exchange(peer_keypair.public_key);

    // Derive symmetric keys
    const key1 = try shared_secret.deriveKey(testing.allocator, "test-context", 32);
    defer testing.allocator.free(key1);

    const key2 = try shared_secret.deriveKey(testing.allocator, "test-context", 32);
    defer testing.allocator.free(key2);

    // Should be deterministic
    try testing.expectEqualSlices(u8, key1, key2);

    // Different context should produce different key
    const key3 = try shared_secret.deriveKey(testing.allocator, "different-context", 32);
    defer testing.allocator.free(key3);

    try testing.expect(!mem.eql(u8, key1, key3));
}

test "Ed25519 - signing and verification" {
    const keypair = try Ed25519.generateKeyPair();
    const message = "Hello, digital signatures!";

    // Sign message
    const signature = try keypair.private_key.sign(message);

    // Verify signature
    try testing.expect(keypair.public_key.verify(signature, message));

    // Verification should fail with different message
    try testing.expect(!keypair.public_key.verify(signature, "Different message"));

    // Verification should fail with wrong public key
    const other_keypair = try Ed25519.generateKeyPair();
    try testing.expect(!other_keypair.public_key.verify(signature, message));
}

test "Key serialization - hex encoding" {
    const keypair = try X25519.generateKeyPair();

    // Test public key hex encoding
    const public_hex = try keypair.public_key.hex(testing.allocator);
    defer testing.allocator.free(public_hex);

    try testing.expect(public_hex.len == 64); // 32 bytes * 2 hex chars

    // Test round-trip conversion
    const parsed_public = try X25519.PublicKey.fromHex(public_hex);
    try testing.expectEqualSlices(u8, keypair.public_key.slice(), parsed_public.slice());
}

test "KeyManager - key exchange workflow" {
    var alice_keypair = try KeyManager.KeyExchangeKeyPair.generate(testing.allocator, .x25519);
    defer alice_keypair.deinit();

    var bob_keypair = try KeyManager.KeyExchangeKeyPair.generate(testing.allocator, .x25519);
    defer bob_keypair.deinit();

    // Perform key exchange
    const alice_shared = try alice_keypair.exchange(bob_keypair.public_key);
    defer testing.allocator.free(alice_shared);

    const bob_shared = try bob_keypair.exchange(alice_keypair.public_key);
    defer testing.allocator.free(bob_shared);

    // Should produce same shared secret
    try testing.expectEqualSlices(u8, alice_shared, bob_shared);
}

test "KeyManager - signature workflow" {
    var keypair = try KeyManager.SignatureKeyPair.generate(testing.allocator, .ed25519);
    defer keypair.deinit();

    const message = "Test message for signing";
    const signature_bytes = try keypair.sign(message);
    defer testing.allocator.free(signature_bytes);

    // Verify using low-level API
    const public_key = try Ed25519.PublicKey.fromSlice(keypair.public_key);
    const signature = try Ed25519.SignatureValue.fromSlice(signature_bytes);

    try testing.expect(public_key.verify(signature, message));
}

test "Algorithm properties" {
    // Key exchange algorithms
    try testing.expect(KeyExchangeAlgorithm.x25519.privateKeyLength() == 32);
    try testing.expect(KeyExchangeAlgorithm.x25519.publicKeyLength() == 32);
    try testing.expect(KeyExchangeAlgorithm.x25519.sharedSecretLength() == 32);

    // Signature algorithms
    try testing.expect(SignatureAlgorithm.ed25519.privateKeyLength() == 64);
    try testing.expect(SignatureAlgorithm.ed25519.publicKeyLength() == 32);
    try testing.expect(SignatureAlgorithm.ed25519.signatureLength() == 64);
}

test "Error handling" {
    // Test invalid key lengths
    const short_key = [_]u8{0} ** 16;
    try testing.expectError(AsymmetricError.InvalidKeyLength, X25519.PrivateKey.fromSlice(&short_key));

    // Test invalid hex parsing
    try testing.expectError(AsymmetricError.InvalidKeyLength, X25519.PublicKey.fromHex("invalid"));
    // Test invalid hex characters
    try testing.expectError(AsymmetricError.InvalidPublicKey, X25519.PublicKey.fromHex("00112233445566778899aabbccddeeffgg112233445566778899aabbccddeeff"));
}
