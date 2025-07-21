//! Advanced Cryptography Performance Benchmark
//!
//! This benchmark measures the performance of asymmetric cryptographic operations:
//! - Key generation (X25519, Ed25519)
//! - Key exchange (ECDH)
//! - Digital signatures (signing and verification)
//! - Key derivation from shared secrets
//! - Key serialization/deserialization

const std = @import("std");
const ferret = @import("ferret");
const testing = std.testing;
const print = std.debug.print;

const ITERATIONS = 100;
const WARMUP_ITERATIONS = 10;
const KEY_EXCHANGE_ITERATIONS = 100; // Lower for expensive operations
const SIGNATURE_ITERATIONS = 100;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("=== Advanced Cryptography Performance Benchmark ===\n\n", .{});

    // 1. Key Generation Benchmarks
    try benchmarkKeyGeneration();

    // 2. Key Exchange Benchmarks
    try benchmarkKeyExchange();

    // 3. Digital Signature Benchmarks
    try benchmarkDigitalSignatures();

    // 4. Key Derivation Benchmarks
    try benchmarkKeyDerivation(allocator);

    // 5. Key Management Benchmarks
    try benchmarkKeyManagement(allocator);

    // 6. Serialization Benchmarks
    try benchmarkSerialization(allocator);

    print("\n=== Advanced Cryptography Benchmark Complete ===\n", .{});
}

fn benchmarkKeyGeneration() !void {
    print("1. Asymmetric Key Generation Performance\n", .{});
    print("   =====================================\n", .{});

    // X25519 Key Generation
    {
        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            _ = ferret.asymmetric.X25519.generateKeyPair() catch unreachable;
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            _ = ferret.asymmetric.X25519.generateKeyPair() catch unreachable;
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   X25519 key generation: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per key: {d:.2} μs\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
    }

    // Ed25519 Key Generation
    {
        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            _ = ferret.asymmetric.Ed25519.generateKeyPair() catch unreachable;
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            _ = ferret.asymmetric.Ed25519.generateKeyPair() catch unreachable;
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Ed25519 key generation: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per key: {d:.2} μs\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
    }

    // ECDSA secp256k1 Key Generation
    {
        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            _ = ferret.asymmetric.EcdsaSecp256k1.generateKeyPair() catch unreachable;
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            _ = ferret.asymmetric.EcdsaSecp256k1.generateKeyPair() catch unreachable;
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   ECDSA secp256k1 key generation: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per key: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
    }
}

fn benchmarkKeyExchange() !void {
    print("2. Key Exchange Performance\n", .{});
    print("   =========================\n", .{});

    // Pre-generate key pairs
    const alice_keypair = ferret.asymmetric.X25519.generateKeyPair() catch unreachable;
    const bob_keypair = ferret.asymmetric.X25519.generateKeyPair() catch unreachable;

    // Warmup
    for (0..WARMUP_ITERATIONS) |_| {
        _ = alice_keypair.private_key.exchange(bob_keypair.public_key) catch unreachable;
    }

    // Benchmark
    const start_time = std.time.nanoTimestamp();
    for (0..KEY_EXCHANGE_ITERATIONS) |_| {
        _ = alice_keypair.private_key.exchange(bob_keypair.public_key) catch unreachable;
    }
    const end_time = std.time.nanoTimestamp();

    const duration = end_time - start_time;
    const ops_per_sec = (@as(f64, KEY_EXCHANGE_ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

    print("   X25519 key exchange: {d:.2} ops/sec\n", .{ops_per_sec});
    print("   Average time per exchange: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (KEY_EXCHANGE_ITERATIONS * 1000.0)});
}

fn benchmarkDigitalSignatures() !void {
    print("3. Digital Signature Performance\n", .{});
    print("   ===============================\n", .{});

    const keypair = try ferret.asymmetric.Ed25519.generateKeyPair();
    const message = "This is a test message for digital signature benchmarking";

    // Signing Performance
    {
        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            _ = keypair.private_key.sign(message) catch unreachable;
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..SIGNATURE_ITERATIONS) |_| {
            _ = keypair.private_key.sign(message) catch unreachable;
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, SIGNATURE_ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Ed25519 signing: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per signature: {d:.2} μs\n", .{@as(f64, @floatFromInt(duration)) / (SIGNATURE_ITERATIONS * 1000.0)});
    }

    // Verification Performance
    {
        const signature = try keypair.private_key.sign(message);

        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            _ = keypair.public_key.verify(signature, message);
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..SIGNATURE_ITERATIONS) |_| {
            _ = keypair.public_key.verify(signature, message);
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, SIGNATURE_ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Ed25519 verification: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time per verification: {d:.2} μs\n", .{@as(f64, @floatFromInt(duration)) / (SIGNATURE_ITERATIONS * 1000.0)});
    }

    // ECDSA secp256k1 Performance
    {
        const secp256k1_keypair = try ferret.asymmetric.EcdsaSecp256k1.generateKeyPair();

        // Signing Performance
        {
            // Warmup
            for (0..WARMUP_ITERATIONS) |_| {
                _ = secp256k1_keypair.private_key.sign(message) catch unreachable;
            }

            // Benchmark
            const start_time = std.time.nanoTimestamp();
            for (0..SIGNATURE_ITERATIONS) |_| {
                _ = secp256k1_keypair.private_key.sign(message) catch unreachable;
            }
            const end_time = std.time.nanoTimestamp();

            const duration = end_time - start_time;
            const ops_per_sec = (@as(f64, SIGNATURE_ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

            print("   ECDSA secp256k1 signing: {d:.2} ops/sec\n", .{ops_per_sec});
            print("   Average time per signature: {d:.2} μs\n", .{@as(f64, @floatFromInt(duration)) / (SIGNATURE_ITERATIONS * 1000.0)});
        }

        // Verification Performance
        {
            const secp256k1_signature = try secp256k1_keypair.private_key.sign(message);

            // Warmup
            for (0..WARMUP_ITERATIONS) |_| {
                _ = secp256k1_keypair.public_key.verify(secp256k1_signature, message);
            }

            // Benchmark
            const start_time = std.time.nanoTimestamp();
            for (0..SIGNATURE_ITERATIONS) |_| {
                _ = secp256k1_keypair.public_key.verify(secp256k1_signature, message);
            }
            const end_time = std.time.nanoTimestamp();

            const duration = end_time - start_time;
            const ops_per_sec = (@as(f64, SIGNATURE_ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

            print("   ECDSA secp256k1 verification: {d:.2} ops/sec\n", .{ops_per_sec});
            print("   Average time per verification: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (SIGNATURE_ITERATIONS * 1000.0)});
        }
    }
}

fn benchmarkKeyDerivation(allocator: std.mem.Allocator) !void {
    print("4. Key Derivation Performance\n", .{});
    print("   ===========================\n", .{});

    // Generate shared secret from key exchange
    const alice_keypair = ferret.asymmetric.X25519.generateKeyPair() catch unreachable;
    const bob_keypair = ferret.asymmetric.X25519.generateKeyPair() catch unreachable;
    const shared_secret = try alice_keypair.private_key.exchange(bob_keypair.public_key);

    const context = "benchmark-context";
    const key_length = 32;

    // Warmup
    for (0..WARMUP_ITERATIONS) |_| {
        const derived_key = shared_secret.deriveKey(allocator, context, key_length) catch unreachable;
        allocator.free(derived_key);
    }

    // Benchmark
    const start_time = std.time.nanoTimestamp();
    for (0..ITERATIONS) |_| {
        const derived_key = shared_secret.deriveKey(allocator, context, key_length) catch unreachable;
        allocator.free(derived_key);
    }
    const end_time = std.time.nanoTimestamp();

    const duration = end_time - start_time;
    const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

    print("   Key derivation (32 bytes): {d:.2} ops/sec\n", .{ops_per_sec});
    print("   Average time per derivation: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
}

fn benchmarkKeyManagement(allocator: std.mem.Allocator) !void {
    print("5. Key Management Performance\n", .{});
    print("   ===========================\n", .{});

    // Key Exchange Workflow
    {
        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            var keypair = ferret.asymmetric.KeyManager.KeyExchangeKeyPair.generate(allocator, .x25519) catch unreachable;
            keypair.deinit();
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            var keypair = ferret.asymmetric.KeyManager.KeyExchangeKeyPair.generate(allocator, .x25519) catch unreachable;
            keypair.deinit();
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   KeyManager X25519 generation: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time: {d:.2} μs\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
    }

    // Signature Workflow
    {
        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            var keypair = ferret.asymmetric.KeyManager.SignatureKeyPair.generate(allocator, .ed25519) catch unreachable;
            keypair.deinit();
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            var keypair = ferret.asymmetric.KeyManager.SignatureKeyPair.generate(allocator, .ed25519) catch unreachable;
            keypair.deinit();
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   KeyManager Ed25519 generation: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
    }
}

fn benchmarkSerialization(allocator: std.mem.Allocator) !void {
    print("6. Key Serialization Performance\n", .{});
    print("   ==============================\n", .{});

    const keypair = ferret.asymmetric.X25519.generateKeyPair() catch unreachable;

    // Hex Encoding
    {
        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            const hex_key = keypair.public_key.hex(allocator) catch unreachable;
            allocator.free(hex_key);
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            const hex_key = keypair.public_key.hex(allocator) catch unreachable;
            allocator.free(hex_key);
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Hex encoding: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time: {d:.2} μs\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
    }

    // Hex Decoding
    {
        const hex_key = try keypair.public_key.hex(allocator);
        defer allocator.free(hex_key);

        // Warmup
        for (0..WARMUP_ITERATIONS) |_| {
            _ = ferret.asymmetric.X25519.PublicKey.fromHex(hex_key) catch unreachable;
        }

        // Benchmark
        const start_time = std.time.nanoTimestamp();
        for (0..ITERATIONS) |_| {
            _ = ferret.asymmetric.X25519.PublicKey.fromHex(hex_key) catch unreachable;
        }
        const end_time = std.time.nanoTimestamp();

        const duration = end_time - start_time;
        const ops_per_sec = (@as(f64, ITERATIONS) * 1_000_000_000.0) / @as(f64, @floatFromInt(duration));

        print("   Hex decoding: {d:.2} ops/sec\n", .{ops_per_sec});
        print("   Average time: {d:.2} μs\n\n", .{@as(f64, @floatFromInt(duration)) / (ITERATIONS * 1000.0)});
    }
}
