//! I/O reactor performance benchmark
//! 
//! Tests the performance of Ferret's reactor with multiple file descriptors
//! and timers to verify scalability and low latency.

const std = @import("std");
const ferret = @import("ferret");
const posix = std.posix;

var events_processed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var benchmark_running = true;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Reactor Benchmark ===", .{});

    // Test 1: Many file descriptors
    try benchmarkManyFds(allocator);
    
    // Test 2: Timer performance
    try benchmarkTimers(allocator);
    
    // Test 3: Mixed workload
    try benchmarkMixedWorkload(allocator);

    std.log.info("=== Benchmark completed ===", .{});
}

fn benchmarkManyFds(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Many File Descriptors Test ---", .{});
    
    var reactor = try ferret.Reactor.init(allocator);
    defer reactor.deinit();
    
    const num_pipes = 100;
    const pipes = try allocator.alloc([2]posix.fd_t, num_pipes);
    defer allocator.free(pipes);
    
    // Create pipes and register them
    for (pipes) |*pipe_fds| {
        pipe_fds.* = try posix.pipe();
        try reactor.register(pipe_fds[0], ferret.EventType{ .read = true }, handleEvent, null);
    }
    defer {
        for (pipes) |pipe_fds| {
            posix.close(pipe_fds[0]);
            posix.close(pipe_fds[1]);
        }
    }
    
    std.log.info("Registered {} file descriptors", .{reactor.getRegistrationCount()});
    
    const start = std.time.nanoTimestamp();
    
    // Trigger events on all pipes
    for (pipes) |pipe_fds| {
        _ = try posix.write(pipe_fds[1], "test");
    }
    
    // Process events
    try reactor.poll();
    
    const end = std.time.nanoTimestamp();
    const duration_ms = @as(f64, @floatFromInt(end - start)) / 1_000_000.0;
    
    std.log.info("Processed {} events in {d:.2} ms", .{ reactor.getRegistrationCount(), duration_ms });
    std.log.info("Average: {d:.2} μs per event", .{ duration_ms * 1000.0 / @as(f64, @floatFromInt(reactor.getRegistrationCount())) });
}

fn benchmarkTimers(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Timer Performance Test ---", .{});
    
    var reactor = try ferret.Reactor.init(allocator);
    defer reactor.deinit();
    
    const num_timers = 1000;
    const timer_ids = try allocator.alloc(u64, num_timers);
    defer allocator.free(timer_ids);
    
    const start = std.time.nanoTimestamp();
    
    // Add many timers
    for (timer_ids, 0..) |*timer_id, i| {
        const delay = @as(u64, @intCast(i)) * 1_000_000; // Staggered delays
        timer_id.* = try reactor.addTimer(delay, handleTimer, null);
    }
    
    const add_end = std.time.nanoTimestamp();
    
    // Process timers by polling with zero timeout repeatedly
    var processed: u32 = 0;
    const max_iterations = 100;
    for (0..max_iterations) |_| {
        try reactor.poll();
        const current_count = reactor.getTimerCount();
        if (current_count == 0) break;
        processed += 1;
    }
    
    const process_end = std.time.nanoTimestamp();
    
    const add_duration_ms = @as(f64, @floatFromInt(add_end - start)) / 1_000_000.0;
    const process_duration_ms = @as(f64, @floatFromInt(process_end - add_end)) / 1_000_000.0;
    
    std.log.info("Added {} timers in {d:.2} ms", .{ num_timers, add_duration_ms });
    std.log.info("Processed timers in {d:.2} ms ({} poll iterations)", .{ process_duration_ms, processed });
    std.log.info("Remaining timers: {}", .{reactor.getTimerCount()});
}

fn benchmarkMixedWorkload(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Mixed Workload Test ---", .{});
    
    var reactor = try ferret.Reactor.init(allocator);
    defer reactor.deinit();
    
    // Create some pipes
    const num_pipes = 50;
    const pipes = try allocator.alloc([2]posix.fd_t, num_pipes);
    defer allocator.free(pipes);
    
    for (pipes) |*pipe_fds| {
        pipe_fds.* = try posix.pipe();
        try reactor.register(pipe_fds[0], ferret.EventType{ .read = true }, handleEvent, null);
    }
    defer {
        for (pipes) |pipe_fds| {
            posix.close(pipe_fds[0]);
            posix.close(pipe_fds[1]);
        }
    }
    
    // Add some timers
    const num_timers = 50;
    for (0..num_timers) |i| {
        const delay = @as(u64, @intCast(i)) * 500_000; // 0.5ms intervals
        _ = try reactor.addTimer(delay, handleTimer, null);
    }
    
    const start = std.time.nanoTimestamp();
    
    // Trigger some I/O events
    for (pipes[0..25]) |pipe_fds| {
        _ = try posix.write(pipe_fds[1], "mixed");
    }
    
    // Poll multiple times to process both I/O and timers
    for (0..10) |_| {
        try reactor.poll();
    }
    
    const end = std.time.nanoTimestamp();
    const duration_ms = @as(f64, @floatFromInt(end - start)) / 1_000_000.0;
    
    std.log.info("Mixed workload processed in {d:.2} ms", .{duration_ms});
    std.log.info("Remaining FDs: {}, Remaining timers: {}", .{ reactor.getRegistrationCount(), reactor.getTimerCount() });
}

fn handleEvent(event: ferret.Event) void {
    _ = event;
    _ = events_processed.fetchAdd(1, .monotonic);
}

fn handleTimer(data: ?*anyopaque) void {
    _ = data;
    _ = events_processed.fetchAdd(1, .monotonic);
}