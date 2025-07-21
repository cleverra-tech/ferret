//! Atomic operations benchmark and lock-free queue performance test

const std = @import("std");
const ferret = @import("ferret");
const AtomicCounter = ferret.AtomicCounter;
const LockFreeQueue = ferret.LockFreeQueue;
const SpinLock = ferret.SpinLock;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Atomic Operations Benchmark ===\n", .{});

    try benchmarkAtomicCounter();
    std.log.info("", .{});

    try benchmarkLockFreeQueue(allocator);
    std.log.info("", .{});

    try benchmarkSpinLock();

    std.log.info("\n=== Benchmark Complete ===", .{});
}

fn benchmarkAtomicCounter() !void {
    const iterations = 1_000_000;

    var counter = AtomicCounter.init(0);

    const start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        _ = counter.increment();
    }
    const increment_time = std.time.nanoTimestamp() - start;

    const decrement_start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        _ = counter.decrement();
    }
    const decrement_time = std.time.nanoTimestamp() - decrement_start;

    const cas_start = std.time.nanoTimestamp();
    var cas_successes: u32 = 0;
    for (0..iterations) |i| {
        if (counter.compareAndSwap(@intCast(i), @intCast(i + 1))) {
            cas_successes += 1;
        }
    }
    const cas_time = std.time.nanoTimestamp() - cas_start;

    const increment_ns_per_op = @as(f64, @floatFromInt(increment_time)) / @as(f64, @floatFromInt(iterations));
    const decrement_ns_per_op = @as(f64, @floatFromInt(decrement_time)) / @as(f64, @floatFromInt(iterations));
    const cas_ns_per_op = @as(f64, @floatFromInt(cas_time)) / @as(f64, @floatFromInt(iterations));

    std.log.info("AtomicCounter Performance ({} operations):", .{iterations});
    std.log.info("  Increment: {d:.2} ns/op ({d:.2} ops/sec)", .{ increment_ns_per_op, 1_000_000_000.0 / increment_ns_per_op });
    std.log.info("  Decrement: {d:.2} ns/op ({d:.2} ops/sec)", .{ decrement_ns_per_op, 1_000_000_000.0 / decrement_ns_per_op });
    std.log.info("  CAS: {d:.2} ns/op ({d:.2} ops/sec) - {}/{} successes", .{ cas_ns_per_op, 1_000_000_000.0 / cas_ns_per_op, cas_successes, iterations });
    std.log.info("  Final counter value: {}", .{counter.load()});
}

fn benchmarkLockFreeQueue(allocator: std.mem.Allocator) !void {
    const iterations = 100_000;

    // Test basic enqueue/dequeue performance
    var queue = try LockFreeQueue(usize).init(allocator);
    defer queue.deinit();

    // Enqueue benchmark
    const enqueue_start = std.time.nanoTimestamp();
    for (0..iterations) |i| {
        try queue.enqueue(i);
    }
    const enqueue_time = std.time.nanoTimestamp() - enqueue_start;

    // Dequeue benchmark
    const dequeue_start = std.time.nanoTimestamp();
    var dequeue_count: usize = 0;
    while (queue.dequeue()) |value| {
        std.debug.assert(value == dequeue_count);
        dequeue_count += 1;
    }
    const dequeue_time = std.time.nanoTimestamp() - dequeue_start;

    // Mixed operations benchmark
    var mixed_queue = try LockFreeQueue(usize).init(allocator);
    defer mixed_queue.deinit();

    const mixed_start = std.time.nanoTimestamp();
    for (0..iterations / 2) |i| {
        try mixed_queue.enqueue(i);
        try mixed_queue.enqueue(i + iterations / 2);
        _ = mixed_queue.dequeue();
        _ = mixed_queue.dequeue();
    }
    const mixed_time = std.time.nanoTimestamp() - mixed_start;

    const enqueue_ns_per_op = @as(f64, @floatFromInt(enqueue_time)) / @as(f64, @floatFromInt(iterations));
    const dequeue_ns_per_op = @as(f64, @floatFromInt(dequeue_time)) / @as(f64, @floatFromInt(iterations));
    const mixed_ns_per_op = @as(f64, @floatFromInt(mixed_time)) / @as(f64, @floatFromInt(iterations));

    std.log.info("LockFreeQueue Performance ({} operations):", .{iterations});
    std.log.info("  Enqueue: {d:.2} ns/op ({d:.2} ops/sec)", .{ enqueue_ns_per_op, 1_000_000_000.0 / enqueue_ns_per_op });
    std.log.info("  Dequeue: {d:.2} ns/op ({d:.2} ops/sec)", .{ dequeue_ns_per_op, 1_000_000_000.0 / dequeue_ns_per_op });
    std.log.info("  Mixed: {d:.2} ns/op ({d:.2} ops/sec)", .{ mixed_ns_per_op, 1_000_000_000.0 / mixed_ns_per_op });
    std.log.info("  Items dequeued: {}/{}", .{ dequeue_count, iterations });
    std.log.info("  Queue empty after test: {}", .{queue.isEmpty()});
    std.log.info("  Mixed queue empty: {}", .{mixed_queue.isEmpty()});
}

fn benchmarkSpinLock() !void {
    const iterations = 1_000_000;

    var lock = SpinLock.init();
    var counter: u64 = 0;

    const start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        lock.lock();
        counter += 1;
        lock.unlock();
    }
    const lock_time = std.time.nanoTimestamp() - start;

    const trylock_start = std.time.nanoTimestamp();
    var trylock_successes: u32 = 0;
    for (0..iterations) |_| {
        if (lock.tryLock()) {
            trylock_successes += 1;
            counter += 1;
            lock.unlock();
        }
    }
    const trylock_time = std.time.nanoTimestamp() - trylock_start;

    const lock_ns_per_op = @as(f64, @floatFromInt(lock_time)) / @as(f64, @floatFromInt(iterations));
    const trylock_ns_per_op = @as(f64, @floatFromInt(trylock_time)) / @as(f64, @floatFromInt(iterations));

    std.log.info("SpinLock Performance ({} operations):", .{iterations});
    std.log.info("  Lock/Unlock: {d:.2} ns/op ({d:.2} ops/sec)", .{ lock_ns_per_op, 1_000_000_000.0 / lock_ns_per_op });
    std.log.info("  TryLock: {d:.2} ns/op ({d:.2} ops/sec) - {}/{} successes", .{ trylock_ns_per_op, 1_000_000_000.0 / trylock_ns_per_op, trylock_successes, iterations });
    std.log.info("  Final counter value: {}", .{counter});
}
