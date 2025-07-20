//! High-precision timing utilities for Ferret

const std = @import("std");

/// High-precision timestamp
pub const Timestamp = struct {
    const Self = @This();

    nanos: u64,

    pub fn now() Self {
        return Self{
            .nanos = @intCast(std.time.nanoTimestamp()),
        };
    }

    pub fn fromMillis(millis: u64) Self {
        return Self{
            .nanos = millis * std.time.ns_per_ms,
        };
    }

    pub fn fromSeconds(seconds: u64) Self {
        return Self{
            .nanos = seconds * std.time.ns_per_s,
        };
    }

    pub fn toMillis(self: Self) u64 {
        return self.nanos / std.time.ns_per_ms;
    }

    pub fn toSeconds(self: Self) u64 {
        return self.nanos / std.time.ns_per_s;
    }

    pub fn toNanos(self: Self) u64 {
        return self.nanos;
    }

    pub fn add(self: Self, other: Self) Self {
        return Self{
            .nanos = self.nanos + other.nanos,
        };
    }

    pub fn sub(self: Self, other: Self) Self {
        return Self{
            .nanos = self.nanos - other.nanos,
        };
    }

    pub fn diff(self: Self, other: Self) Self {
        return if (self.nanos >= other.nanos)
            Self{ .nanos = self.nanos - other.nanos }
        else
            Self{ .nanos = other.nanos - self.nanos };
    }

    pub fn isAfter(self: Self, other: Self) bool {
        return self.nanos > other.nanos;
    }

    pub fn isBefore(self: Self, other: Self) bool {
        return self.nanos < other.nanos;
    }

    pub fn equals(self: Self, other: Self) bool {
        return self.nanos == other.nanos;
    }
};

/// Duration type for time intervals
pub const Duration = struct {
    const Self = @This();

    nanos: u64,

    pub fn fromNanos(nanos: u64) Self {
        return Self{ .nanos = nanos };
    }

    pub fn fromMicros(micros: u64) Self {
        return Self{ .nanos = micros * std.time.ns_per_us };
    }

    pub fn fromMillis(millis: u64) Self {
        return Self{ .nanos = millis * std.time.ns_per_ms };
    }

    pub fn fromSeconds(seconds: u64) Self {
        return Self{ .nanos = seconds * std.time.ns_per_s };
    }

    pub fn fromMinutes(minutes: u64) Self {
        return Self{ .nanos = minutes * std.time.ns_per_min };
    }

    pub fn fromHours(hours: u64) Self {
        return Self{ .nanos = hours * std.time.ns_per_hour };
    }

    pub fn toNanos(self: Self) u64 {
        return self.nanos;
    }

    pub fn toMicros(self: Self) u64 {
        return self.nanos / std.time.ns_per_us;
    }

    pub fn toMillis(self: Self) u64 {
        return self.nanos / std.time.ns_per_ms;
    }

    pub fn toSeconds(self: Self) u64 {
        return self.nanos / std.time.ns_per_s;
    }

    pub fn toSecondsF(self: Self) f64 {
        return @as(f64, @floatFromInt(self.nanos)) / @as(f64, @floatFromInt(std.time.ns_per_s));
    }

    pub fn add(self: Self, other: Self) Self {
        return Self{ .nanos = self.nanos + other.nanos };
    }

    pub fn sub(self: Self, other: Self) Self {
        return Self{ .nanos = self.nanos - other.nanos };
    }

    pub fn mul(self: Self, factor: u64) Self {
        return Self{ .nanos = self.nanos * factor };
    }

    pub fn div(self: Self, divisor: u64) Self {
        return Self{ .nanos = self.nanos / divisor };
    }

    pub fn isZero(self: Self) bool {
        return self.nanos == 0;
    }

    pub fn compare(self: Self, other: Self) std.math.Order {
        return std.math.order(self.nanos, other.nanos);
    }
};

/// Timer for measuring elapsed time
pub const Timer = struct {
    const Self = @This();

    start_time: Timestamp,

    pub fn start() Self {
        return Self{
            .start_time = Timestamp.now(),
        };
    }

    pub fn elapsed(self: Self) Duration {
        const now = Timestamp.now();
        return Duration.fromNanos(now.nanos - self.start_time.nanos);
    }

    pub fn reset(self: *Self) void {
        self.start_time = Timestamp.now();
    }

    pub fn lap(self: *Self) Duration {
        const elapsed_time = self.elapsed();
        self.reset();
        return elapsed_time;
    }
};

/// Timeout checker for non-blocking operations
pub const Timeout = struct {
    const Self = @This();

    deadline: Timestamp,

    pub fn init(duration: Duration) Self {
        const now = Timestamp.now();
        return Self{
            .deadline = Timestamp{
                .nanos = now.nanos + duration.nanos,
            },
        };
    }

    pub fn isExpired(self: Self) bool {
        const now = Timestamp.now();
        return now.isAfter(self.deadline);
    }

    pub fn remaining(self: Self) Duration {
        const now = Timestamp.now();
        if (now.isAfter(self.deadline)) {
            return Duration.fromNanos(0);
        }
        return Duration.fromNanos(self.deadline.nanos - now.nanos);
    }

    pub fn extend(self: *Self, additional: Duration) void {
        self.deadline = Timestamp{
            .nanos = self.deadline.nanos + additional.nanos,
        };
    }
};

/// Rate limiter using token bucket algorithm
pub const RateLimiter = struct {
    const Self = @This();

    capacity: u64,
    tokens: f64,
    fill_rate: f64, // tokens per second
    last_refill: Timestamp,

    pub fn init(capacity: u64, fill_rate: f64) Self {
        return Self{
            .capacity = capacity,
            .tokens = @floatFromInt(capacity),
            .fill_rate = fill_rate,
            .last_refill = Timestamp.now(),
        };
    }

    pub fn tryAcquire(self: *Self, tokens: u64) bool {
        self.refill();

        const tokens_f = @as(f64, @floatFromInt(tokens));
        if (self.tokens >= tokens_f) {
            self.tokens -= tokens_f;
            return true;
        }
        return false;
    }

    pub fn acquire(self: *Self, tokens: u64) void {
        while (!self.tryAcquire(tokens)) {
            std.Thread.sleep(std.time.ns_per_ms); // Sleep 1ms
        }
    }

    fn refill(self: *Self) void {
        const now = Timestamp.now();
        const elapsed = Duration.fromNanos(now.nanos - self.last_refill.nanos);
        const elapsed_seconds = elapsed.toSecondsF();

        const tokens_to_add = self.fill_rate * elapsed_seconds;
        self.tokens = @min(self.tokens + tokens_to_add, @as(f64, @floatFromInt(self.capacity)));
        self.last_refill = now;
    }

    pub fn availableTokens(self: *Self) u64 {
        self.refill();
        return @intFromFloat(@floor(self.tokens));
    }
};

/// Sleep utilities
pub fn sleep(duration: Duration) void {
    std.Thread.sleep(duration.nanos);
}

pub fn sleepMillis(millis: u64) void {
    std.Thread.sleep(millis * std.time.ns_per_ms);
}

pub fn sleepSeconds(seconds: u64) void {
    std.Thread.sleep(seconds * std.time.ns_per_s);
}

test "Timestamp operations" {
    const t1 = Timestamp.now();
    std.Thread.sleep(std.time.ns_per_ms); // Sleep 1ms
    const t2 = Timestamp.now();

    try std.testing.expect(t2.isAfter(t1));
    try std.testing.expect(t1.isBefore(t2));
    try std.testing.expect(!t1.equals(t2));

    const diff = t2.diff(t1);
    try std.testing.expect(diff.toNanos() >= std.time.ns_per_ms);
}

test "Duration operations" {
    const d1 = Duration.fromMillis(1000);
    const d2 = Duration.fromSeconds(1);

    try std.testing.expectEqual(d1.toNanos(), d2.toNanos());
    try std.testing.expectEqual(@as(u64, 1000), d1.toMillis());
    try std.testing.expectEqual(@as(u64, 1), d1.toSeconds());
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), d1.toSecondsF(), 0.001);

    const d3 = d1.add(d2);
    try std.testing.expectEqual(@as(u64, 2), d3.toSeconds());

    const d4 = d3.sub(d1);
    try std.testing.expectEqual(d2.toNanos(), d4.toNanos());
}

test "Timer functionality" {
    var timer = Timer.start();

    std.Thread.sleep(std.time.ns_per_ms * 10); // Sleep 10ms

    const elapsed = timer.elapsed();
    try std.testing.expect(elapsed.toMillis() >= 10);

    timer.reset();
    const elapsed2 = timer.elapsed();
    try std.testing.expect(elapsed2.toMillis() < elapsed.toMillis());
}

test "Timeout functionality" {
    const timeout = Timeout.init(Duration.fromMillis(10));

    try std.testing.expect(!timeout.isExpired());

    std.Thread.sleep(std.time.ns_per_ms * 15); // Sleep 15ms

    try std.testing.expect(timeout.isExpired());
    try std.testing.expect(timeout.remaining().isZero());
}

test "RateLimiter basic functionality" {
    var limiter = RateLimiter.init(10, 10.0); // 10 tokens capacity, 10 tokens/second

    // Should be able to acquire initial tokens
    try std.testing.expect(limiter.tryAcquire(5));
    try std.testing.expect(limiter.tryAcquire(5));

    // Should be out of tokens now
    try std.testing.expect(!limiter.tryAcquire(1));

    // After some time, should have more tokens
    std.Thread.sleep(std.time.ns_per_ms * 200); // Sleep 200ms
    try std.testing.expect(limiter.tryAcquire(1));
}
