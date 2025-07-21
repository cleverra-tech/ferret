//! Queue performance benchmark demonstration

const std = @import("std");
const ferret = @import("ferret");
const Queue = ferret.Queue;
const ArrayQueue = ferret.collections.queue.ArrayQueue;
const LinkedQueue = ferret.collections.queue.LinkedQueue;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Queue Performance Benchmark ===\n", .{});

    const iterations = 100_000;

    // Benchmark ArrayQueue
    std.log.info("--- ArrayQueue Performance ---", .{});
    try benchmarkArrayQueue(allocator, iterations);

    std.log.info("\n--- LinkedQueue Performance ---", .{});
    try benchmarkLinkedQueue(allocator, iterations);

    std.log.info("\n--- Queue API Demonstration ---", .{});
    try demonstrateQueueAPI(allocator);

    std.log.info("\n=== Benchmark Complete ===", .{});
}

fn benchmarkArrayQueue(allocator: std.mem.Allocator, iterations: usize) !void {
    var queue = try ArrayQueue(usize).init(allocator, iterations);
    defer queue.deinit();

    // Enqueue benchmark
    const enqueue_start = std.time.nanoTimestamp();
    for (0..iterations) |i| {
        try queue.enqueue(i);
    }
    const enqueue_time = std.time.nanoTimestamp() - enqueue_start;

    // Dequeue benchmark
    const dequeue_start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        _ = queue.dequeue().?;
    }
    const dequeue_time = std.time.nanoTimestamp() - dequeue_start;

    const enqueue_ns_per_op = @as(f64, @floatFromInt(enqueue_time)) / @as(f64, @floatFromInt(iterations));
    const dequeue_ns_per_op = @as(f64, @floatFromInt(dequeue_time)) / @as(f64, @floatFromInt(iterations));

    std.log.info("ArrayQueue ({} items):", .{iterations});
    std.log.info("  Enqueue: {d:.2} ns/op ({d:.2} ops/sec)", .{ enqueue_ns_per_op, 1_000_000_000.0 / enqueue_ns_per_op });
    std.log.info("  Dequeue: {d:.2} ns/op ({d:.2} ops/sec)", .{ dequeue_ns_per_op, 1_000_000_000.0 / dequeue_ns_per_op });
    std.log.info("  Memory: {} bytes (fixed allocation)", .{iterations * @sizeOf(usize)});
}

fn benchmarkLinkedQueue(allocator: std.mem.Allocator, iterations: usize) !void {
    var queue = LinkedQueue(usize).init(allocator);
    defer queue.deinit();

    // Enqueue benchmark
    const enqueue_start = std.time.nanoTimestamp();
    for (0..iterations) |i| {
        try queue.enqueue(i);
    }
    const enqueue_time = std.time.nanoTimestamp() - enqueue_start;

    // Dequeue benchmark
    const dequeue_start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        _ = queue.dequeue().?;
    }
    const dequeue_time = std.time.nanoTimestamp() - dequeue_start;

    const enqueue_ns_per_op = @as(f64, @floatFromInt(enqueue_time)) / @as(f64, @floatFromInt(iterations));
    const dequeue_ns_per_op = @as(f64, @floatFromInt(dequeue_time)) / @as(f64, @floatFromInt(iterations));

    std.log.info("LinkedQueue ({} items):", .{iterations});
    std.log.info("  Enqueue: {d:.2} ns/op ({d:.2} ops/sec)", .{ enqueue_ns_per_op, 1_000_000_000.0 / enqueue_ns_per_op });
    std.log.info("  Dequeue: {d:.2} ns/op ({d:.2} ops/sec)", .{ dequeue_ns_per_op, 1_000_000_000.0 / dequeue_ns_per_op });
    std.log.info("  Memory: Dynamic allocation per node", .{});
}

fn demonstrateQueueAPI(allocator: std.mem.Allocator) !void {
    // Demonstrate ArrayQueue features
    std.log.info("Creating ArrayQueue with capacity 5...", .{});
    var array_queue = try ArrayQueue([]const u8).init(allocator, 5);
    defer array_queue.deinit();

    // Basic operations
    try array_queue.enqueue("first");
    try array_queue.enqueue("second");
    try array_queue.enqueue("third");

    std.log.info("ArrayQueue state:", .{});
    std.log.info("  Length: {}", .{array_queue.len()});
    std.log.info("  Front: {s}", .{array_queue.peek().?});
    std.log.info("  Back: {s}", .{array_queue.peekLast().?});
    std.log.info("  Is full: {}", .{array_queue.isFull()});

    // Iterator demonstration
    std.log.info("  Contents (via iterator):", .{});
    var iter = array_queue.iterator();
    var index: usize = 0;
    while (iter.next()) |item| {
        std.log.info("    [{}]: {s}", .{ index, item });
        index += 1;
    }

    // Demonstrate LinkedQueue features
    std.log.info("\nCreating LinkedQueue...", .{});
    var linked_queue = Queue(i32).init(allocator);
    defer linked_queue.deinit();

    // Add many items to show dynamic nature
    for (1..11) |i| {
        try linked_queue.enqueue(@intCast(i * 10));
    }

    std.log.info("LinkedQueue state:", .{});
    std.log.info("  Length: {}", .{linked_queue.len()});
    std.log.info("  Front: {}", .{linked_queue.peek().?});
    std.log.info("  Back: {}", .{linked_queue.peekLast().?});

    // Dequeue a few items
    std.log.info("  Dequeuing 3 items:", .{});
    for (0..3) |_| {
        const item = linked_queue.dequeue().?;
        std.log.info("    Dequeued: {}", .{item});
    }

    std.log.info("  New front: {}", .{linked_queue.peek().?});
    std.log.info("  New length: {}", .{linked_queue.len()});
}
