//! Unicode escape handling validation test
const std = @import("std");
const ferret = @import("ferret");
const json = ferret.Json;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== JSON Unicode Validation Test ===", .{});

    // Test various Unicode scenarios
    const test_cases = [_]struct { input: []const u8, expected_bytes: []const u8 }{
        .{ .input = "\"\\u0041\"", .expected_bytes = "A" }, // ASCII
        .{ .input = "\"\\u00E9\"", .expected_bytes = "é" }, // Latin-1 supplement
        .{ .input = "\"\\u20AC\"", .expected_bytes = "€" }, // Euro sign (BMP)
        .{ .input = "\"\\u4E2D\\u6587\"", .expected_bytes = "中文" }, // Chinese characters
        .{ .input = "\"\\uD83D\\uDE00\"", .expected_bytes = &[_]u8{ 0xF0, 0x9F, 0x98, 0x80 } }, // U+1F600 grinning face
        .{ .input = "\"\\uD83C\\uDF89\"", .expected_bytes = &[_]u8{ 0xF0, 0x9F, 0x8E, 0x89 } }, // U+1F389 party popper
        .{ .input = "\"\\u4E16\\u754C\"", .expected_bytes = "世界" }, // World in Chinese
    };

    std.log.info("Running {} Unicode test cases...", .{test_cases.len});

    for (test_cases, 0..) |test_case, i| {
        var value = json.parseFromString(allocator, test_case.input) catch |err| {
            std.log.err("Test {} failed to parse: {}", .{ i + 1, err });
            continue;
        };
        defer value.deinit(allocator);

        const str = value.getString() catch |err| {
            std.log.err("Test {} failed to get string: {}", .{ i + 1, err });
            continue;
        };

        if (std.mem.eql(u8, str, test_case.expected_bytes)) {
            std.log.info("[OK] Test {}: '{s}' -> UTF-8 bytes match", .{ i + 1, test_case.input });
        } else {
            std.log.err("[FAIL] Test {}: UTF-8 bytes mismatch", .{i + 1});
        }
    }

    // Run micro-benchmark
    std.log.info("\n--- Unicode Performance Benchmark ---", .{});
    const count = 10000;
    const unicode_json = "\"\\u4E2D\\u6587\\uD83C\\uDF89\""; // Chinese + Unicode surrogate pair

    const start = std.time.nanoTimestamp();
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var value = json.parseFromString(allocator, unicode_json) catch unreachable;
        defer value.deinit(allocator);
    }
    const end = std.time.nanoTimestamp();

    const duration_ns = end - start;
    const ns_per_op = @as(f64, @floatFromInt(duration_ns)) / @as(f64, @floatFromInt(count));
    const duration_ms = @as(f64, @floatFromInt(duration_ns)) / 1_000_000.0;

    std.log.info("Parsed {} Unicode strings in {d:.2} ms", .{ count, duration_ms });
    std.log.info("Performance: {d:.0} ns/op", .{ns_per_op});

    // Validate UTF-8 output
    std.log.info("\n--- UTF-8 Validation ---", .{});
    var test_value = try json.parseFromString(allocator, "\"\\uD83D\\uDE00\"");
    defer test_value.deinit(allocator);
    const unicode_str = try test_value.getString();

    // Check that the result is valid UTF-8
    if (std.unicode.utf8ValidateSlice(unicode_str)) {
        std.log.info("[OK] Generated UTF-8 is valid", .{});
        std.log.info("Unicode bytes: {any}", .{unicode_str});
    } else {
        std.log.err("[FAIL] Generated UTF-8 is invalid", .{});
    }

    std.log.info("\n=== Unicode Test Complete ===", .{});
}
