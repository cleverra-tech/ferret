//! JSON parser and generator benchmark
//! 
//! Tests performance of Ferret's JSON implementation with various data sizes

const std = @import("std");
const ferret = @import("ferret");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== JSON Benchmark ===", .{});

    // Small JSON test
    try benchmarkParseAndGenerate(allocator, "Small JSON", small_json);
    
    // Medium JSON test  
    try benchmarkParseAndGenerate(allocator, "Medium JSON", medium_json);
    
    // Large array test
    try benchmarkParseAndGenerate(allocator, "Large Array", large_array_json);

    std.log.info("=== Benchmark completed ===", .{});
}

fn benchmarkParseAndGenerate(allocator: std.mem.Allocator, name: []const u8, json_str: []const u8) !void {
    const iterations = 1000;
    
    std.log.info("\n--- {s} ({} bytes) ---", .{ name, json_str.len });
    
    // Parse benchmark
    const parse_start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        var value = try ferret.Json.parseFromString(allocator, json_str);
        defer value.deinit(allocator);
    }
    const parse_end = std.time.nanoTimestamp();
    const parse_time = @as(f64, @floatFromInt(parse_end - parse_start)) / @as(f64, @floatFromInt(iterations));
    
    // Generate benchmark
    var value = try ferret.Json.parseFromString(allocator, json_str);
    defer value.deinit(allocator);
    
    const gen_start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        const generated = try ferret.Json.stringify(allocator, value, false);
        defer allocator.free(generated);
    }
    const gen_end = std.time.nanoTimestamp();
    const gen_time = @as(f64, @floatFromInt(gen_end - gen_start)) / @as(f64, @floatFromInt(iterations));
    
    const throughput_parse = (@as(f64, @floatFromInt(json_str.len)) / parse_time) * 1_000_000_000.0 / (1024.0 * 1024.0);
    const throughput_gen = (@as(f64, @floatFromInt(json_str.len)) / gen_time) * 1_000_000_000.0 / (1024.0 * 1024.0);
    
    std.log.info("Parse: {d:.2} ns/op, {d:.2} MB/s", .{ parse_time, throughput_parse });
    std.log.info("Generate: {d:.2} ns/op, {d:.2} MB/s", .{ gen_time, throughput_gen });
}

const small_json = 
    \\{"name":"John","age":30,"active":true}
;

const medium_json = 
    \\{
    \\  "users": [
    \\    {"id": 1, "name": "Alice", "email": "alice@example.com", "age": 25, "active": true},
    \\    {"id": 2, "name": "Bob", "email": "bob@example.com", "age": 30, "active": false},
    \\    {"id": 3, "name": "Charlie", "email": "charlie@example.com", "age": 35, "active": true}
    \\  ],
    \\  "metadata": {
    \\    "total": 3,
    \\    "timestamp": "2024-01-01T00:00:00Z",
    \\    "version": "1.0.0"
    \\  }
    \\}
;

const large_array_json = 
    \\{"data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100]}
;