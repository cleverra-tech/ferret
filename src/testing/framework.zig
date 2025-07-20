//! Comprehensive testing framework for Ferret
//!
//! This module provides:
//! - Test categories and organization
//! - Performance benchmarking utilities
//! - Test result reporting and analysis
//! - Integration test helpers
//! - Mock and stub utilities
//! - Memory leak detection
//! - Test timing and profiling

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;

/// Test categories for organization
pub const TestCategory = enum {
    unit,
    integration,
    performance,
    stress,
    memory,
    security,
    compatibility,

    pub fn toString(self: TestCategory) []const u8 {
        return switch (self) {
            .unit => "Unit",
            .integration => "Integration",
            .performance => "Performance",
            .stress => "Stress",
            .memory => "Memory",
            .security => "Security",
            .compatibility => "Compatibility",
        };
    }
};

/// Test priority levels
pub const TestPriority = enum {
    critical,
    high,
    medium,
    low,

    pub fn toString(self: TestPriority) []const u8 {
        return switch (self) {
            .critical => "Critical",
            .high => "High",
            .medium => "Medium",
            .low => "Low",
        };
    }
};

/// Test result status
pub const TestResult = enum {
    pass,
    fail,
    skip,
    timeout,
    @"error",

    pub fn toString(self: TestResult) []const u8 {
        return switch (self) {
            .pass => "PASS",
            .fail => "FAIL",
            .skip => "SKIP",
            .timeout => "TIMEOUT",
            .@"error" => "ERROR",
        };
    }

    pub fn color(self: TestResult) []const u8 {
        return switch (self) {
            .pass => "\x1b[32m", // Green
            .fail => "\x1b[31m", // Red
            .skip => "\x1b[33m", // Yellow
            .timeout => "\x1b[35m", // Magenta
            .@"error" => "\x1b[91m", // Bright red
        };
    }
};

/// Performance measurement data
pub const PerformanceMetrics = struct {
    duration_ns: u64,
    memory_used: usize,
    allocations: u32,
    deallocations: u32,
    peak_memory: usize,
    iterations: u32,

    pub fn opsPerSecond(self: PerformanceMetrics) f64 {
        if (self.duration_ns == 0) return 0;
        return @as(f64, @floatFromInt(self.iterations)) / (@as(f64, @floatFromInt(self.duration_ns)) / 1_000_000_000.0);
    }

    pub fn nsPerOp(self: PerformanceMetrics) f64 {
        if (self.iterations == 0) return 0;
        return @as(f64, @floatFromInt(self.duration_ns)) / @as(f64, @floatFromInt(self.iterations));
    }

    pub fn memoryLeaked(self: PerformanceMetrics) bool {
        return self.allocations != self.deallocations;
    }
};

/// Test case metadata
pub const TestCase = struct {
    name: []const u8,
    category: TestCategory,
    priority: TestPriority,
    description: []const u8,
    timeout_ms: u32 = 5000,
    enabled: bool = true,

    // Result data
    result: TestResult = .skip,
    metrics: ?PerformanceMetrics = null,
    error_message: ?[]const u8 = null,
    start_time: i128 = 0,
    end_time: i128 = 0,

    pub fn duration_ms(self: TestCase) f64 {
        if (self.start_time == 0 or self.end_time == 0) return 0;
        return @as(f64, @floatFromInt(self.end_time - self.start_time)) / 1_000_000.0;
    }
};

/// Test suite for organizing related tests
pub const TestSuite = struct {
    name: []const u8,
    description: []const u8,
    tests: ArrayList(TestCase),
    allocator: Allocator,
    setup_fn: ?*const fn () anyerror!void = null,
    teardown_fn: ?*const fn () anyerror!void = null,

    pub fn init(allocator: Allocator, name: []const u8, description: []const u8) TestSuite {
        return TestSuite{
            .name = name,
            .description = description,
            .tests = ArrayList(TestCase).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TestSuite) void {
        self.tests.deinit();
    }

    pub fn addTest(self: *TestSuite, test_case: TestCase) !void {
        try self.tests.append(test_case);
    }

    pub fn runAll(self: *TestSuite) !TestSummary {
        var summary = TestSummary.init(self.allocator);

        if (self.setup_fn) |setup| {
            try setup();
        }
        defer {
            if (self.teardown_fn) |teardown| {
                teardown() catch |err| {
                    std.log.err("Teardown failed: {}", .{err});
                };
            }
        }

        for (self.tests.items) |*test_case| {
            if (!test_case.enabled) {
                test_case.result = .skip;
                continue;
            }

            test_case.start_time = std.time.nanoTimestamp();
            // Note: Actual test execution would be implemented by the user
            // This framework provides the infrastructure
            test_case.end_time = std.time.nanoTimestamp();
        }

        try summary.addSuite(self);
        return summary;
    }
};

/// Test summary and reporting
pub const TestSummary = struct {
    allocator: Allocator,
    suites: ArrayList(*TestSuite),
    total_tests: u32 = 0,
    passed: u32 = 0,
    failed: u32 = 0,
    skipped: u32 = 0,
    errors: u32 = 0,
    timeouts: u32 = 0,
    total_duration_ms: f64 = 0,

    pub fn init(allocator: Allocator) TestSummary {
        return TestSummary{
            .allocator = allocator,
            .suites = ArrayList(*TestSuite).init(allocator),
        };
    }

    pub fn deinit(self: *TestSummary) void {
        self.suites.deinit();
    }

    pub fn addSuite(self: *TestSummary, suite: *TestSuite) !void {
        try self.suites.append(suite);

        for (suite.tests.items) |test_case| {
            self.total_tests += 1;
            self.total_duration_ms += test_case.duration_ms();

            switch (test_case.result) {
                .pass => self.passed += 1,
                .fail => self.failed += 1,
                .skip => self.skipped += 1,
                .timeout => self.timeouts += 1,
                .@"error" => self.errors += 1,
            }
        }
    }

    pub fn successRate(self: TestSummary) f64 {
        if (self.total_tests == 0) return 0;
        return @as(f64, @floatFromInt(self.passed)) / @as(f64, @floatFromInt(self.total_tests)) * 100.0;
    }

    pub fn print(self: TestSummary) void {
        std.debug.print("\n=== Test Summary ===\n", .{});
        std.debug.print("Total Tests: {}\n", .{self.total_tests});
        std.debug.print("{}Passed: {}\x1b[0m\n", .{ TestResult.pass.color(), self.passed });
        std.debug.print("{}Failed: {}\x1b[0m\n", .{ TestResult.fail.color(), self.failed });
        std.debug.print("{}Skipped: {}\x1b[0m\n", .{ TestResult.skip.color(), self.skipped });
        std.debug.print("{}Errors: {}\x1b[0m\n", .{ TestResult.@"error".color(), self.errors });
        std.debug.print("{}Timeouts: {}\x1b[0m\n", .{ TestResult.timeout.color(), self.timeouts });
        std.debug.print("Success Rate: {d:.2}%\n", .{self.successRate()});
        std.debug.print("Total Duration: {d:.2} ms\n", .{self.total_duration_ms});

        // Detailed suite breakdown
        for (self.suites.items) |suite| {
            std.debug.print("\n--- {} Suite ---\n", .{suite.name});
            for (suite.tests.items) |test_case| {
                std.debug.print("  {}{s}\x1b[0m: {} ({d:.2} ms)\n", .{
                    test_case.result.color(),
                    test_case.result.toString(),
                    test_case.name,
                    test_case.duration_ms(),
                });

                if (test_case.error_message) |msg| {
                    std.debug.print("    Error: {s}\n", .{msg});
                }

                if (test_case.metrics) |metrics| {
                    std.debug.print("    Metrics: {d:.2} ops/sec, {} memory\n", .{
                        metrics.opsPerSecond(),
                        metrics.memory_used,
                    });
                }
            }
        }
    }

    pub fn printJUnit(self: TestSummary) !void {
        // TODO: Implement JUnit XML output for CI integration
        _ = self;
    }
};

/// Performance benchmark utilities
pub const Benchmark = struct {
    allocator: Allocator,
    iterations: u32,
    warmup_iterations: u32 = 1000,

    pub fn init(allocator: Allocator, iterations: u32) Benchmark {
        return Benchmark{
            .allocator = allocator,
            .iterations = iterations,
        };
    }

    pub fn run(self: Benchmark, comptime func: anytype, args: anytype) !PerformanceMetrics {
        var tracking_allocator = std.heap.GeneralPurposeAllocator(.{
            .enable_memory_limit = false,
            .thread_safe = true,
        }){};
        defer _ = tracking_allocator.deinit();
        const tracked_alloc = tracking_allocator.allocator();

        // Warmup
        for (0..self.warmup_iterations) |_| {
            _ = try func(tracked_alloc, args);
        }

        // Reset tracking
        _ = tracking_allocator.deinit();
        tracking_allocator = std.heap.GeneralPurposeAllocator(.{
            .enable_memory_limit = false,
            .thread_safe = true,
        }){};
        const fresh_alloc = tracking_allocator.allocator();

        const start_time = std.time.nanoTimestamp();

        for (0..self.iterations) |_| {
            _ = try func(fresh_alloc, args);
        }

        const end_time = std.time.nanoTimestamp();

        return PerformanceMetrics{
            .duration_ns = @intCast(end_time - start_time),
            .memory_used = 0, // TODO: Implement proper memory tracking
            .allocations = 0, // TODO: Track allocations count
            .deallocations = 0, // TODO: Track deallocations count
            .peak_memory = 0, // TODO: Implement peak memory tracking
            .iterations = self.iterations,
        };
    }
};

/// Memory leak detector
pub const MemoryTracker = struct {
    allocator: Allocator,
    allocations: std.AutoHashMap(usize, AllocationInfo),
    total_allocated: usize = 0,
    total_freed: usize = 0,

    const AllocationInfo = struct {
        size: usize,
        timestamp: i128,
        stack_trace: ?[]const usize = null,
    };

    pub fn init(allocator: Allocator) MemoryTracker {
        return MemoryTracker{
            .allocator = allocator,
            .allocations = std.AutoHashMap(usize, AllocationInfo).init(allocator),
        };
    }

    pub fn deinit(self: *MemoryTracker) void {
        self.allocations.deinit();
    }

    pub fn trackAllocation(self: *MemoryTracker, ptr: usize, size: usize) !void {
        const info = AllocationInfo{
            .size = size,
            .timestamp = std.time.nanoTimestamp(),
        };
        try self.allocations.put(ptr, info);
        self.total_allocated += size;
    }

    pub fn trackFree(self: *MemoryTracker, ptr: usize) void {
        if (self.allocations.fetchRemove(ptr)) |entry| {
            self.total_freed += entry.value.size;
        }
    }

    pub fn checkLeaks(self: MemoryTracker) !void {
        if (self.allocations.count() > 0) {
            std.log.err("Memory leaks detected: {} allocations not freed", .{self.allocations.count()});
            var iter = self.allocations.iterator();
            while (iter.next()) |entry| {
                std.log.err("  Leaked: {} bytes at 0x{X}", .{ entry.value_ptr.size, entry.key_ptr.* });
            }
            return error.MemoryLeak;
        }
    }

    pub fn getStats(self: MemoryTracker) struct { allocated: usize, freed: usize, leaked: usize } {
        return .{
            .allocated = self.total_allocated,
            .freed = self.total_freed,
            .leaked = self.total_allocated - self.total_freed,
        };
    }
};

/// Test assertion utilities
pub const Assert = struct {
    pub fn equals(comptime T: type, expected: T, actual: T) !void {
        if (expected != actual) {
            std.debug.print("Assertion failed: expected {} but got {}\n", .{ expected, actual });
            return error.AssertionFailed;
        }
    }

    pub fn notEquals(comptime T: type, not_expected: T, actual: T) !void {
        if (not_expected == actual) {
            std.debug.print("Assertion failed: expected not {} but got {}\n", .{ not_expected, actual });
            return error.AssertionFailed;
        }
    }

    pub fn isTrue(condition: bool) !void {
        if (!condition) {
            std.debug.print("Assertion failed: expected true but got false\n", .{});
            return error.AssertionFailed;
        }
    }

    pub fn isFalse(condition: bool) !void {
        if (condition) {
            std.debug.print("Assertion failed: expected false but got true\n", .{});
            return error.AssertionFailed;
        }
    }

    pub fn isNull(comptime T: type, value: ?T) !void {
        if (value != null) {
            std.debug.print("Assertion failed: expected null but got non-null value\n", .{});
            return error.AssertionFailed;
        }
    }

    pub fn isNotNull(comptime T: type, value: ?T) !void {
        if (value == null) {
            std.debug.print("Assertion failed: expected non-null but got null\n", .{});
            return error.AssertionFailed;
        }
    }

    pub fn approximatelyEquals(expected: f64, actual: f64, tolerance: f64) !void {
        const diff = @abs(expected - actual);
        if (diff > tolerance) {
            std.debug.print("Assertion failed: expected {d} ± {d} but got {d} (diff: {d})\n", .{ expected, tolerance, actual, diff });
            return error.AssertionFailed;
        }
    }

    pub fn stringEquals(expected: []const u8, actual: []const u8) !void {
        if (!std.mem.eql(u8, expected, actual)) {
            std.debug.print("Assertion failed: expected '{s}' but got '{s}'\n", .{ expected, actual });
            return error.AssertionFailed;
        }
    }

    pub fn stringContains(haystack: []const u8, needle: []const u8) !void {
        if (std.mem.indexOf(u8, haystack, needle) == null) {
            std.debug.print("Assertion failed: '{s}' does not contain '{s}'\n", .{ haystack, needle });
            return error.AssertionFailed;
        }
    }

    pub fn expectError(comptime ErrorType: type, result: ErrorType!void) !void {
        if (result) {
            std.debug.print("Assertion failed: expected error but operation succeeded\n", .{});
            return error.AssertionFailed;
        } else |_| {
            // Expected error occurred
        }
    }

    pub fn performsWithin(time_limit_ns: u64, comptime func: anytype, args: anytype) !void {
        const start = std.time.nanoTimestamp();
        _ = try func(args);
        const duration = @as(u64, @intCast(std.time.nanoTimestamp() - start));

        if (duration > time_limit_ns) {
            std.debug.print("Assertion failed: operation took {}ns but limit was {}ns\n", .{ duration, time_limit_ns });
            return error.AssertionFailed;
        }
    }
};

/// Mock object utilities
pub fn Mock(comptime T: type) type {
    return struct {
        const Self = @This();

        call_count: u32 = 0,
        last_args: ?T = null,
        return_value: ?T = null,
        should_error: bool = false,
        error_to_return: anyerror = error.MockError,

        pub fn init() Self {
            return Self{};
        }

        pub fn setReturnValue(self: *Self, value: T) void {
            self.return_value = value;
        }

        pub fn setError(self: *Self, err: anyerror) void {
            self.should_error = true;
            self.error_to_return = err;
        }

        pub fn call(self: *Self, args: T) !T {
            self.call_count += 1;
            self.last_args = args;

            if (self.should_error) {
                return self.error_to_return;
            }

            if (self.return_value) |value| {
                return value;
            }

            return args; // Default: echo input
        }

        pub fn wasCalled(self: Self) bool {
            return self.call_count > 0;
        }

        pub fn wasCalledWith(self: Self, expected_args: T) bool {
            if (self.last_args) |args| {
                return std.meta.eql(args, expected_args);
            }
            return false;
        }

        pub fn reset(self: *Self) void {
            self.call_count = 0;
            self.last_args = null;
            self.return_value = null;
            self.should_error = false;
        }
    };
}

// Tests for the testing framework itself
test "TestCase basic functionality" {
    const test_case = TestCase{
        .name = "example test",
        .category = .unit,
        .priority = .high,
        .description = "Test description",
    };

    try std.testing.expect(std.mem.eql(u8, test_case.name, "example test"));
    try std.testing.expect(test_case.category == .unit);
    try std.testing.expect(test_case.priority == .high);
}

test "TestSuite management" {
    var suite = TestSuite.init(std.testing.allocator, "Core Tests", "Tests for core functionality");
    defer suite.deinit();

    const test_case = TestCase{
        .name = "test1",
        .category = .unit,
        .priority = .medium,
        .description = "First test",
    };

    try suite.addTest(test_case);
    try std.testing.expect(suite.tests.items.len == 1);
}

test "Assert utilities" {
    try Assert.equals(i32, 42, 42);
    try Assert.notEquals(i32, 42, 24);
    try Assert.isTrue(true);
    try Assert.isFalse(false);
    try Assert.isNull(?i32, null);
    try Assert.isNotNull(?i32, @as(?i32, 42));
    try Assert.approximatelyEquals(3.14159, 3.14160, 0.001);
    try Assert.stringEquals("hello", "hello");
    try Assert.stringContains("hello world", "world");
}

test "Mock functionality" {
    var mock = Mock(i32).init();

    mock.setReturnValue(42);
    const result = try mock.call(10);

    try std.testing.expect(result == 42);
    try std.testing.expect(mock.wasCalled());
    try std.testing.expect(mock.wasCalledWith(10));
    try std.testing.expect(mock.call_count == 1);
}

test "PerformanceMetrics calculations" {
    const metrics = PerformanceMetrics{
        .duration_ns = 1_000_000_000, // 1 second
        .memory_used = 1024,
        .allocations = 10,
        .deallocations = 10,
        .peak_memory = 2048,
        .iterations = 1000,
    };

    try Assert.approximatelyEquals(1000.0, metrics.opsPerSecond(), 0.1);
    try Assert.approximatelyEquals(1_000_000.0, metrics.nsPerOp(), 0.1);
    try Assert.isFalse(metrics.memoryLeaked());
}
