//! Buffer performance benchmark and demonstration

const std = @import("std");
const ferret = @import("ferret");
const Buffer = ferret.Buffer;
const BufferPool = ferret.io.buffer.BufferPool;
const RingBuffer = ferret.io.buffer.RingBuffer;
const FixedBuffer = ferret.io.buffer.FixedBuffer;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Buffer Performance Benchmark ===\n", .{});

    const iterations = 50_000;
    
    // Benchmark Dynamic Buffer
    std.log.info("--- Dynamic Buffer Performance ---", .{});
    try benchmarkDynamicBuffer(allocator, iterations);
    
    std.log.info("\n--- RingBuffer Performance ---", .{});
    try benchmarkRingBuffer(iterations);
    
    std.log.info("\n--- BufferPool Performance ---", .{});
    try benchmarkBufferPool(allocator, iterations);
    
    std.log.info("\n--- Buffer API Demonstration ---", .{});
    try demonstrateBufferAPI(allocator);
    
    std.log.info("\n=== Benchmark Complete ===", .{});
}

fn benchmarkDynamicBuffer(allocator: std.mem.Allocator, iterations: usize) !void {
    var buffer = try Buffer.init(allocator);
    defer buffer.deinit();
    
    // Write benchmark
    const write_start = std.time.nanoTimestamp();
    for (0..iterations) |i| {
        var temp_buf: [16]u8 = undefined;
        const data = try std.fmt.bufPrint(&temp_buf, "msg_{}", .{i});
        _ = try buffer.write(data);
    }
    const write_time = std.time.nanoTimestamp() - write_start;
    
    // Read benchmark
    const read_start = std.time.nanoTimestamp();
    var read_buf: [1024]u8 = undefined;
    var total_read: usize = 0;
    while (!buffer.isEmpty()) {
        total_read += buffer.read(&read_buf);
    }
    const read_time = std.time.nanoTimestamp() - read_start;
    
    const write_ns_per_op = @as(f64, @floatFromInt(write_time)) / @as(f64, @floatFromInt(iterations));
    const read_throughput = @as(f64, @floatFromInt(total_read)) / (@as(f64, @floatFromInt(read_time)) / 1_000_000_000.0);
    
    std.log.info("Dynamic Buffer ({} operations):", .{iterations});
    std.log.info("  Write: {d:.2} ns/op ({d:.2} ops/sec)", .{ write_ns_per_op, 1_000_000_000.0 / write_ns_per_op });
    std.log.info("  Read throughput: {d:.2} MB/s", .{read_throughput / 1_048_576.0});
    std.log.info("  Total data: {} bytes", .{total_read});
}

fn benchmarkRingBuffer(iterations: usize) !void {
    var ring = RingBuffer(8192).init();
    
    // Write benchmark
    const write_start = std.time.nanoTimestamp();
    var written: usize = 0;
    for (0..iterations) |i| {
        var temp_buf: [16]u8 = undefined;
        const data = std.fmt.bufPrint(&temp_buf, "msg_{}", .{i}) catch unreachable;
        written += ring.write(data);
        
        // Occasionally read to prevent buffer from filling
        if (i % 100 == 0) {
            var read_buf: [1000]u8 = undefined;
            _ = ring.read(&read_buf);
        }
    }
    const write_time = std.time.nanoTimestamp() - write_start;
    
    // Read remaining data
    var read_buf: [8192]u8 = undefined;
    const final_read = ring.read(&read_buf);
    
    const write_ns_per_op = @as(f64, @floatFromInt(write_time)) / @as(f64, @floatFromInt(iterations));
    
    std.log.info("RingBuffer ({} operations):", .{iterations});
    std.log.info("  Write: {d:.2} ns/op ({d:.2} ops/sec)", .{ write_ns_per_op, 1_000_000_000.0 / write_ns_per_op });
    std.log.info("  Capacity: {} bytes", .{RingBuffer(8192).getCapacity()});
    std.log.info("  Final read: {} bytes", .{final_read});
}

fn benchmarkBufferPool(allocator: std.mem.Allocator, iterations: usize) !void {
    var pool = BufferPool.init(allocator, 4096);
    defer pool.deinit();
    
    // Benchmark buffer allocation/release cycles
    const start = std.time.nanoTimestamp();
    
    for (0..iterations) |i| {
        var buffer = try pool.acquire();
        
        var temp_buf: [16]u8 = undefined;
        const data = try std.fmt.bufPrint(&temp_buf, "data_{}", .{i});
        _ = try buffer.write(data);
        
        // Simulate some work
        _ = buffer.available();
        
        pool.release(buffer);
    }
    
    const end = std.time.nanoTimestamp();
    const ns_per_cycle = @as(f64, @floatFromInt(end - start)) / @as(f64, @floatFromInt(iterations));
    
    const stats = pool.stats();
    
    std.log.info("BufferPool ({} cycles):", .{iterations});
    std.log.info("  Acquire/Release: {d:.2} ns/cycle ({d:.2} cycles/sec)", .{ ns_per_cycle, 1_000_000_000.0 / ns_per_cycle });
    std.log.info("  Pool stats: {} total, {} in use, {} free", .{ stats.total, stats.in_use, stats.free });
}

fn demonstrateBufferAPI(allocator: std.mem.Allocator) !void {
    // Demonstrate Dynamic Buffer features
    std.log.info("Creating dynamic buffer...", .{});
    var buffer = try Buffer.init(allocator);
    defer buffer.deinit();
    
    // Basic operations
    _ = try buffer.write("Hello, ");
    _ = try buffer.write("Buffer ");
    _ = try buffer.write("World!");
    
    std.log.info("Buffer state after writes:", .{});
    std.log.info("  Available bytes: {}", .{buffer.available()});
    std.log.info("  Capacity: {}", .{buffer.getCapacity()});
    std.log.info("  Content: '{s}'", .{buffer.readable()});
    
    // Demonstrate peeking
    var peek_buf: [5]u8 = undefined;
    const peeked = buffer.peek(&peek_buf);
    std.log.info("  Peeked {} bytes: '{s}'", .{ peeked, peek_buf[0..peeked] });
    
    // Read some data
    var read_buf: [7]u8 = undefined;
    const read_count = buffer.read(&read_buf);
    std.log.info("  Read {} bytes: '{s}'", .{ read_count, read_buf[0..read_count] });
    std.log.info("  Remaining: '{s}'", .{buffer.readable()});
    
    // Demonstrate FixedBuffer
    std.log.info("\nCreating fixed buffer (32 bytes)...", .{});
    var fixed = FixedBuffer(32).init();
    
    _ = try fixed.write("Fixed buffer test");
    try fixed.writeByte('!');
    
    std.log.info("FixedBuffer state:", .{});
    std.log.info("  Length: {}", .{fixed.getLen()});
    std.log.info("  Capacity: {}", .{FixedBuffer(32).getCapacity()});
    std.log.info("  Content: '{s}'", .{fixed.readable()});
    std.log.info("  Is full: {}", .{fixed.isFull()});
    
    // Demonstrate RingBuffer
    std.log.info("\nCreating ring buffer (16 bytes)...", .{});
    var ring = RingBuffer(16).init();
    
    // Fill the ring buffer
    const written = ring.write("0123456789ABCDEF");
    std.log.info("RingBuffer written {} bytes", .{written});
    std.log.info("  Available: {}", .{ring.available()});
    std.log.info("  Is full: {}", .{ring.isFull()});
    
    // Read and write to demonstrate circular nature
    var ring_read: [8]u8 = undefined;
    const ring_read_count = ring.read(&ring_read);
    std.log.info("  Read {} bytes: '{s}'", .{ ring_read_count, ring_read[0..ring_read_count] });
    
    _ = ring.write("XYZ12345");
    std.log.info("  After writing more data, available: {}", .{ring.available()});
    
    // Show buffer pool usage
    std.log.info("\nDemonstrating buffer pool...", .{});
    var pool = BufferPool.init(allocator, 1024);
    defer pool.deinit();
    
    var buf1 = try pool.acquire();
    var buf2 = try pool.acquire();
    var buf3 = try pool.acquire();
    
    _ = try buf1.write("Pool buffer 1");
    _ = try buf2.write("Pool buffer 2");  
    _ = try buf3.write("Pool buffer 3");
    
    var pool_stats = pool.stats();
    std.log.info("  Pool stats: {} total, {} in use", .{ pool_stats.total, pool_stats.in_use });
    
    pool.release(buf2);
    pool_stats = pool.stats();
    std.log.info("  After releasing one: {} in use, {} free", .{ pool_stats.in_use, pool_stats.free });
    
    // Reuse released buffer
    var buf4 = try pool.acquire();
    std.log.info("  Reused buffer is empty: {}", .{buf4.isEmpty()});
}