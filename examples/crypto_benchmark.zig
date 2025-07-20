//! Cryptographic operations benchmark
//! 
//! Tests the performance of Ferret's cryptographic modules including
//! hashing, encryption, and random number generation.

const std = @import("std");
const ferret = @import("ferret");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Crypto Benchmark ===", .{});

    // Test hash performance
    try benchmarkHashing();
    
    // Test encryption performance
    try benchmarkEncryption(allocator);
    
    // Test random generation performance
    try benchmarkRandom(allocator);

    std.log.info("=== Benchmark completed ===", .{});
}

fn benchmarkHashing() !void {
    std.log.info("\n--- Hash Performance ---", .{});
    
    const data_sizes = [_]usize{ 100, 1024, 10240, 102400 }; // 100B, 1KB, 10KB, 100KB
    const iterations = 1000;
    
    for (data_sizes) |size| {
        const data = try std.heap.page_allocator.alloc(u8, size);
        defer std.heap.page_allocator.free(data);
        @memset(data, 0x42); // Fill with test pattern
        
        // SHA-256 benchmark
        const start = std.time.nanoTimestamp();
        for (0..iterations) |_| {
            _ = ferret.hash.Hash.sha256(data);
        }
        const end = std.time.nanoTimestamp();
        
        const duration_ns = end - start;
        const ns_per_op = @as(f64, @floatFromInt(duration_ns)) / @as(f64, @floatFromInt(iterations));
        const mb_per_sec = (@as(f64, @floatFromInt(size)) * @as(f64, @floatFromInt(iterations))) / 
                          (@as(f64, @floatFromInt(duration_ns)) / 1_000_000_000.0) / 1_048_576.0;
        
        std.log.info("SHA-256 {}B: {d:.2} ns/op, {d:.2} MB/s", .{ size, ns_per_op, mb_per_sec });
    }
    
    // BLAKE3 benchmark
    std.log.info("BLAKE3 comparison:", .{});
    const test_data = "The quick brown fox jumps over the lazy dog";
    
    const blake3_start = std.time.nanoTimestamp();
    for (0..10000) |_| {
        _ = ferret.hash.Hash.blake3(test_data);
    }
    const blake3_end = std.time.nanoTimestamp();
    
    const blake3_ns_per_op = @as(f64, @floatFromInt(blake3_end - blake3_start)) / 10000.0;
    std.log.info("BLAKE3 43B: {d:.2} ns/op", .{blake3_ns_per_op});
}

fn benchmarkEncryption(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Encryption Performance ---", .{});
    
    const plaintext = "The quick brown fox jumps over the lazy dog. This is a test message for encryption benchmarking.";
    const iterations = 1000;
    
    // AES-256-GCM benchmark
    const aes_key = ferret.cipher.Aes256GcmKey.random();
    
    const aes_start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        const encrypted = try ferret.cipher.Cipher.encryptAes256Gcm(
            allocator,
            plaintext,
            null,
            aes_key,
        );
        allocator.free(encrypted.ciphertext);
    }
    const aes_end = std.time.nanoTimestamp();
    
    const aes_ns_per_op = @as(f64, @floatFromInt(aes_end - aes_start)) / @as(f64, @floatFromInt(iterations));
    const aes_mb_per_sec = (@as(f64, @floatFromInt(plaintext.len)) * @as(f64, @floatFromInt(iterations))) / 
                          (@as(f64, @floatFromInt(aes_end - aes_start)) / 1_000_000_000.0) / 1_048_576.0;
    
    std.log.info("AES-256-GCM {}B: {d:.2} ns/op, {d:.2} MB/s", .{ plaintext.len, aes_ns_per_op, aes_mb_per_sec });
    
    // ChaCha20-Poly1305 benchmark
    const chacha_key = ferret.cipher.ChaCha20Poly1305Key.random();
    
    const chacha_start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        const encrypted = try ferret.cipher.Cipher.encryptChaCha20Poly1305(
            allocator,
            plaintext,
            null,
            chacha_key,
        );
        allocator.free(encrypted.ciphertext);
    }
    const chacha_end = std.time.nanoTimestamp();
    
    const chacha_ns_per_op = @as(f64, @floatFromInt(chacha_end - chacha_start)) / @as(f64, @floatFromInt(iterations));
    const chacha_mb_per_sec = (@as(f64, @floatFromInt(plaintext.len)) * @as(f64, @floatFromInt(iterations))) / 
                             (@as(f64, @floatFromInt(chacha_end - chacha_start)) / 1_000_000_000.0) / 1_048_576.0;
    
    std.log.info("ChaCha20-Poly1305 {}B: {d:.2} ns/op, {d:.2} MB/s", .{ plaintext.len, chacha_ns_per_op, chacha_mb_per_sec });
}

fn benchmarkRandom(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Random Generation Performance ---", .{});
    
    const iterations = 100000;
    
    // UUID generation
    const uuid_start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        _ = ferret.rand.Uuid.v4();
    }
    const uuid_end = std.time.nanoTimestamp();
    
    const uuid_ns_per_op = @as(f64, @floatFromInt(uuid_end - uuid_start)) / @as(f64, @floatFromInt(iterations));
    std.log.info("UUID v4 generation: {d:.2} ns/op", .{uuid_ns_per_op});
    
    // Random string generation
    const string_start = std.time.nanoTimestamp();
    for (0..1000) |_| {
        const random_string = try ferret.rand.RandomString.alphanumeric(allocator, 32);
        allocator.free(random_string);
    }
    const string_end = std.time.nanoTimestamp();
    
    const string_ns_per_op = @as(f64, @floatFromInt(string_end - string_start)) / 1000.0;
    std.log.info("Random string (32 chars): {d:.2} ns/op", .{string_ns_per_op});
    
    // Random number generation
    const u32_start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        _ = ferret.rand.SecureRandom.randomU32();
    }
    const u32_end = std.time.nanoTimestamp();
    
    const u32_ns_per_op = @as(f64, @floatFromInt(u32_end - u32_start)) / @as(f64, @floatFromInt(iterations));
    std.log.info("Random u32: {d:.2} ns/op", .{u32_ns_per_op});
    
    // UUID formatting
    const uuid = ferret.rand.Uuid.v4();
    const format_start = std.time.nanoTimestamp();
    for (0..10000) |_| {
        const uuid_str = try uuid.toString(allocator);
        allocator.free(uuid_str);
    }
    const format_end = std.time.nanoTimestamp();
    
    const format_ns_per_op = @as(f64, @floatFromInt(format_end - format_start)) / 10000.0;
    std.log.info("UUID toString(): {d:.2} ns/op", .{format_ns_per_op});
}