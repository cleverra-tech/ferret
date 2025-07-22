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
    test_fn: ?*const fn (std.mem.Allocator) anyerror!void = null,

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

    /// Helper function to create a test case with a test function
    pub fn withFunction(
        name: []const u8,
        category: TestCategory,
        priority: TestPriority,
        description: []const u8,
        test_fn: *const fn (std.mem.Allocator) anyerror!void,
    ) TestCase {
        return TestCase{
            .name = name,
            .category = category,
            .priority = priority,
            .description = description,
            .test_fn = test_fn,
        };
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

    /// Add multiple tests at once for batch registration
    pub fn addTests(self: *TestSuite, test_cases: []const TestCase) !void {
        for (test_cases) |test_case| {
            try self.addTest(test_case);
        }
    }

    /// Filter tests by category for selective execution
    pub fn filterByCategory(self: *TestSuite, category: TestCategory) !TestSuite {
        var filtered = TestSuite.init(self.allocator, self.name, self.description);
        for (self.tests.items) |test_case| {
            if (test_case.category == category) {
                try filtered.addTest(test_case);
            }
        }
        return filtered;
    }

    /// Filter tests by priority for selective execution
    pub fn filterByPriority(self: *TestSuite, min_priority: TestPriority) !TestSuite {
        var filtered = TestSuite.init(self.allocator, self.name, self.description);

        const priority_values = std.enums.values(TestPriority);
        const min_index = for (priority_values, 0..) |p, i| {
            if (p == min_priority) break i;
        } else priority_values.len;

        for (self.tests.items) |test_case| {
            const test_index = for (priority_values, 0..) |p, i| {
                if (p == test_case.priority) break i;
            } else continue;

            if (test_index <= min_index) {
                try filtered.addTest(test_case);
            }
        }
        return filtered;
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

            // Skip tests without test functions
            if (test_case.test_fn == null) {
                test_case.result = .skip;
                test_case.error_message = "No test function provided";
                continue;
            }

            test_case.start_time = std.time.nanoTimestamp();

            // Create a tracking allocator for memory leak detection
            var tracking_allocator = TrackingAllocator.init(self.allocator);
            defer _ = tracking_allocator.deinit();

            // Execute the test function with timeout support
            const test_fn = test_case.test_fn.?;

            // Simple timeout implementation using wall clock time
            const timeout_start = std.time.nanoTimestamp();
            const timeout_ns = @as(i128, test_case.timeout_ms) * 1_000_000;

            var test_completed = false;
            var test_error: ?anyerror = null;

            // Create a test execution wrapper
            test_fn(tracking_allocator.allocator()) catch |err| {
                test_error = err;
            };
            test_completed = true;

            // Check if we exceeded timeout
            const elapsed = std.time.nanoTimestamp() - timeout_start;
            if (!test_completed or elapsed > timeout_ns) {
                test_case.result = .timeout;
                test_case.error_message = "Test execution exceeded timeout limit";
            } else if (test_error) |err| {
                // Set test result based on error type
                test_case.result = switch (err) {
                    error.TestExpectedEqual, error.TestExpectedError, error.TestUnexpectedResult, error.TestExpected, error.TestSkipped, error.AssertionFailed => .fail,
                    error.OutOfMemory => .@"error",
                    else => .@"error",
                };

                // Capture error message (simplified for now)
                test_case.error_message = switch (err) {
                    error.TestExpectedEqual => "Expected values to be equal",
                    error.TestExpectedError => "Expected error was not thrown",
                    error.TestUnexpectedResult => "Unexpected test result",
                    error.TestExpected => "Test assertion failed",
                    error.TestSkipped => "Test was skipped",
                    error.AssertionFailed => "Assertion failed",
                    error.OutOfMemory => "Out of memory during test execution",
                    else => "Test execution failed with error",
                };

                test_case.end_time = std.time.nanoTimestamp();

                // Still collect metrics even for failed tests
                const allocations = tracking_allocator.allocation_count;
                const deallocations = tracking_allocator.deallocation_count;
                const peak_memory = tracking_allocator.peak_memory;

                test_case.metrics = PerformanceMetrics{
                    .duration_ns = @intCast(test_case.end_time - test_case.start_time),
                    .iterations = 1,
                    .allocations = allocations,
                    .deallocations = deallocations,
                    .peak_memory = peak_memory,
                    .memory_used = tracking_allocator.total_allocated - tracking_allocator.total_deallocated,
                };
                continue;
            }

            // Test completed successfully
            test_case.result = .pass;
            test_case.end_time = std.time.nanoTimestamp();

            // Collect performance metrics for successful tests
            const allocations = tracking_allocator.allocation_count;
            const deallocations = tracking_allocator.deallocation_count;
            const peak_memory = tracking_allocator.peak_memory;

            test_case.metrics = PerformanceMetrics{
                .duration_ns = @intCast(test_case.end_time - test_case.start_time),
                .iterations = 1,
                .allocations = allocations,
                .deallocations = deallocations,
                .peak_memory = peak_memory,
                .memory_used = tracking_allocator.total_allocated - tracking_allocator.total_deallocated,
            };
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

    /// Generate JUnit XML output for CI/CD integration
    /// Follows the JUnit XML format specification for maximum compatibility
    pub fn printJUnit(self: TestSummary) !void {
        const stdout = std.io.getStdOut().writer();
        try self.writeJUnitToWriter(stdout);
    }

    /// Write JUnit XML to a specific file
    pub fn writeJUnitToFile(self: TestSummary, file_path: []const u8) !void {
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        // Generate XML content in memory first
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        try self.writeJUnitToWriter(buffer.writer());
        try file.writeAll(buffer.items);
    }

    /// Write JUnit XML to any writer (core implementation)
    pub fn writeJUnitToWriter(self: TestSummary, writer: anytype) !void {
        // XML header
        try writer.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

        // Root testsuites element with summary statistics
        try writer.print("<testsuites tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\" time=\"{d:.3}\">\n", .{
            self.total_tests,
            self.failed,
            self.errors + self.timeouts, // Timeouts are treated as errors in JUnit
            self.skipped,
            self.total_duration_ms / 1000.0, // Convert to seconds
        });

        // Generate testsuite for each suite
        for (self.suites.items) |suite| {
            try self.writeTestSuite(writer, suite);
        }

        // Close root element
        try writer.writeAll("</testsuites>\n");
    }

    /// Write a single test suite to XML
    fn writeTestSuite(self: TestSummary, writer: anytype, suite: *TestSuite) !void {
        // Calculate suite-specific statistics
        var suite_passed: u32 = 0;
        var suite_failed: u32 = 0;
        var suite_errors: u32 = 0;
        var suite_skipped: u32 = 0;
        var suite_duration: f64 = 0;

        for (suite.tests.items) |test_case| {
            suite_duration += test_case.duration_ms();
            switch (test_case.result) {
                .pass => suite_passed += 1,
                .fail => suite_failed += 1,
                .skip => suite_skipped += 1,
                .timeout, .@"error" => suite_errors += 1,
            }
        }

        const suite_total = suite.tests.items.len;

        // Write testsuite element with attributes
        try writer.print("  <testsuite name=\"{s}\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\" time=\"{d:.3}\"", .{
            suite.name,
            suite_total,
            suite_failed,
            suite_errors,
            suite_skipped,
            suite_duration / 1000.0, // Convert to seconds
        });

        // Add timestamp (ISO 8601 format)
        const timestamp = std.time.timestamp();
        try writer.print(" timestamp=\"{d}\"", .{timestamp});

        try writer.writeAll(">\n");

        // Write properties section if needed
        try writer.writeAll("    <properties>\n");
        try writer.print("      <property name=\"test.framework\" value=\"Ferret Testing Framework\"/>\n", .{});
        try writer.print("      <property name=\"test.suite.category\" value=\"{s}\"/>\n", .{if (suite.tests.items.len > 0) suite.tests.items[0].category.toString() else "unknown"});
        try writer.writeAll("    </properties>\n");

        // Write individual test cases
        for (suite.tests.items) |test_case| {
            try self.writeTestCase(writer, test_case);
        }

        try writer.writeAll("  </testsuite>\n");
    }

    /// Write a single test case to XML
    fn writeTestCase(self: TestSummary, writer: anytype, test_case: TestCase) !void {

        // Basic testcase element
        try writer.print("    <testcase name=\"{s}\" classname=\"{s}.{s}\" time=\"{d:.3}\"", .{
            test_case.name,
            test_case.category.toString(),
            test_case.priority.toString(),
            test_case.duration_ms() / 1000.0, // Convert to seconds
        });

        // Handle different test results
        switch (test_case.result) {
            .pass => {
                // Successful test - just close the element
                try writer.writeAll("/>\n");
            },
            .fail => {
                try writer.writeAll(">\n");
                try writer.writeAll("      <failure");
                if (test_case.error_message) |msg| {
                    try writer.writeAll(" message=\"");
                    try self.writeEscapedXML(writer, msg);
                    try writer.writeAll("\"");
                }
                try writer.writeAll(" type=\"AssertionFailure\">");
                if (test_case.error_message) |msg| {
                    try self.writeEscapedXML(writer, msg);
                }
                try writer.writeAll("</failure>\n");
                try writer.writeAll("    </testcase>\n");
            },
            .@"error" => {
                try writer.writeAll(">\n");
                try writer.writeAll("      <error");
                if (test_case.error_message) |msg| {
                    try writer.writeAll(" message=\"");
                    try self.writeEscapedXML(writer, msg);
                    try writer.writeAll("\"");
                }
                try writer.writeAll(" type=\"TestError\">");
                if (test_case.error_message) |msg| {
                    try self.writeEscapedXML(writer, msg);
                }
                try writer.writeAll("</error>\n");
                try writer.writeAll("    </testcase>\n");
            },
            .timeout => {
                try writer.writeAll(">\n");
                try writer.print("      <error message=\"Test timed out after {}ms\" type=\"TimeoutError\">", .{test_case.timeout_ms});
                try writer.print("Test case '{s}' exceeded the timeout limit of {}ms", .{ test_case.name, test_case.timeout_ms });
                try writer.writeAll("</error>\n");
                try writer.writeAll("    </testcase>\n");
            },
            .skip => {
                try writer.writeAll(">\n");
                try writer.writeAll("      <skipped");
                if (test_case.error_message) |msg| {
                    try writer.writeAll(" message=\"");
                    try self.writeEscapedXML(writer, msg);
                    try writer.writeAll("\"");
                } else {
                    try writer.writeAll(" message=\"Test skipped\"");
                }
                try writer.writeAll("/>\n");
                try writer.writeAll("    </testcase>\n");
            },
        }
    }

    /// Escape XML special characters to prevent XML injection and ensure validity
    fn writeEscapedXML(self: TestSummary, writer: anytype, text: []const u8) !void {
        _ = self;

        for (text) |char| {
            switch (char) {
                '<' => try writer.writeAll("&lt;"),
                '>' => try writer.writeAll("&gt;"),
                '&' => try writer.writeAll("&amp;"),
                '"' => try writer.writeAll("&quot;"),
                '\'' => try writer.writeAll("&apos;"),
                // Control characters that are invalid in XML
                0x00...0x08, 0x0B, 0x0C, 0x0E...0x1F => try writer.print("&#x{X:0>2};", .{char}),
                else => try writer.writeByte(char),
            }
        }
    }
};

/// Tracking allocator for precise memory monitoring
/// Uses GeneralPurposeAllocator with leak detection for accurate tracking
pub const TrackingAllocator = struct {
    gpa: std.heap.GeneralPurposeAllocator(.{
        .enable_memory_limit = false,
        .thread_safe = true,
    }),
    allocation_count: u32 = 0,
    deallocation_count: u32 = 0,
    total_allocated: usize = 0,
    total_deallocated: usize = 0,
    peak_memory: usize = 0,
    mutex: std.Thread.Mutex = .{},

    const Self = @This();

    pub fn init(backing_allocator: Allocator) Self {
        _ = backing_allocator; // We use our own GPA for accurate tracking
        return Self{
            .gpa = std.heap.GeneralPurposeAllocator(.{
                .enable_memory_limit = false,
                .thread_safe = true,
            }){},
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self.gpa.deinit();
    }

    pub fn allocator(self: *Self) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
                .remap = remap,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        const result = self.gpa.allocator().rawAlloc(len, ptr_align, ret_addr);
        if (result) |_| {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.allocation_count += 1;
            self.total_allocated += len;

            const current = self.total_allocated - self.total_deallocated;
            if (current > self.peak_memory) {
                self.peak_memory = current;
            }
        }
        return result;
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Self = @ptrCast(@alignCast(ctx));

        const result = self.gpa.allocator().rawResize(buf, buf_align, new_len, ret_addr);
        if (result) {
            self.mutex.lock();
            defer self.mutex.unlock();

            const old_len = buf.len;
            if (new_len > old_len) {
                const additional = new_len - old_len;
                self.total_allocated += additional;

                const current = self.total_allocated - self.total_deallocated;
                if (current > self.peak_memory) {
                    self.peak_memory = current;
                }
            } else if (new_len < old_len) {
                const freed = old_len - new_len;
                self.total_deallocated += freed;
            }
        }
        return result;
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
        const self: *Self = @ptrCast(@alignCast(ctx));

        self.mutex.lock();
        defer self.mutex.unlock();

        self.deallocation_count += 1;
        self.total_deallocated += buf.len;

        self.gpa.allocator().rawFree(buf, buf_align, ret_addr);
    }

    fn remap(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, old_len: usize, new_len: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));
        _ = old_len; // Unused, we track based on actual allocation sizes
        const ret_addr = @returnAddress();

        // Use the backing allocator's realloc
        if (self.gpa.allocator().rawAlloc(new_len, buf_align, ret_addr)) |new_ptr| {
            // Copy data if new allocation succeeded
            @memcpy(new_ptr[0..@min(buf.len, new_len)], buf[0..@min(buf.len, new_len)]);

            // Free old allocation
            self.gpa.allocator().rawFree(buf, buf_align, ret_addr);

            // Update tracking
            self.mutex.lock();
            defer self.mutex.unlock();

            // Account for reallocation as new alloc + free
            self.allocation_count += 1;
            self.deallocation_count += 1;
            self.total_allocated += new_len;
            self.total_deallocated += buf.len;

            const current = self.total_allocated - self.total_deallocated;
            if (current > self.peak_memory) {
                self.peak_memory = current;
            }

            return new_ptr;
        }

        return null;
    }

    pub fn reset(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.allocation_count = 0;
        self.deallocation_count = 0;
        self.total_allocated = 0;
        self.total_deallocated = 0;
        self.peak_memory = 0;
    }

    pub fn getStats(self: *Self) struct {
        allocation_count: u32,
        deallocation_count: u32,
        total_allocated: usize,
        total_deallocated: usize,
        current_allocated: usize,
        peak_memory: usize,
        has_leaks: bool,
    } {
        self.mutex.lock();
        defer self.mutex.unlock();

        const current = self.total_allocated - self.total_deallocated;

        return .{
            .allocation_count = self.allocation_count,
            .deallocation_count = self.deallocation_count,
            .total_allocated = self.total_allocated,
            .total_deallocated = self.total_deallocated,
            .current_allocated = current,
            .peak_memory = self.peak_memory,
            .has_leaks = current > 0,
        };
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
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();

        var tracking_allocator = TrackingAllocator.init(gpa.allocator());
        defer tracking_allocator.deinit();

        // Warmup phase
        for (0..self.warmup_iterations) |_| {
            _ = try func(tracking_allocator.allocator(), args);
        }

        // Reset tracking for actual measurement
        tracking_allocator.reset();

        const start_time = std.time.nanoTimestamp();

        for (0..self.iterations) |_| {
            _ = try func(tracking_allocator.allocator(), args);
        }

        const end_time = std.time.nanoTimestamp();
        const stats = tracking_allocator.getStats();

        return PerformanceMetrics{
            .duration_ns = @intCast(end_time - start_time),
            .memory_used = stats.total_allocated,
            .allocations = stats.allocation_count,
            .deallocations = stats.deallocation_count,
            .peak_memory = stats.peak_memory,
            .iterations = self.iterations,
        };
    }
};

/// Enhanced memory leak detector using TrackingAllocator
pub const MemoryTracker = struct {
    backing_allocator: Allocator,
    tracking_allocator: TrackingAllocator,
    allocations: std.AutoHashMap(usize, AllocationInfo),
    enabled: bool = true,

    const AllocationInfo = struct {
        size: usize,
        timestamp: i128,
        stack_trace: ?[]usize = null, // Stack frames
        allocator_ref: ?Allocator = null, // For deallocation
    };

    const Self = @This();

    pub fn init(backing_allocator: Allocator) !Self {
        const tracking = TrackingAllocator.init(backing_allocator);
        return Self{
            .backing_allocator = backing_allocator,
            .tracking_allocator = tracking,
            .allocations = std.AutoHashMap(usize, AllocationInfo).init(backing_allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        // Clean up any remaining stack traces
        var iter = self.allocations.iterator();
        while (iter.next()) |entry| {
            const info = entry.value_ptr.*;
            if (info.stack_trace) |trace| {
                if (info.allocator_ref) |alloc| {
                    alloc.free(trace);
                }
            }
        }

        self.tracking_allocator.deinit();
        self.allocations.deinit();
    }

    pub fn allocator(self: *Self) Allocator {
        if (!self.enabled) {
            return self.backing_allocator;
        }
        return self.tracking_allocator.allocator();
    }

    pub fn enable(self: *Self) void {
        self.enabled = true;
    }

    pub fn disable(self: *Self) void {
        self.enabled = false;
    }

    pub fn reset(self: *Self) void {
        self.tracking_allocator.reset();
        self.allocations.clearAndFree();
    }

    pub fn trackAllocation(self: *Self, ptr: usize, size: usize) !void {
        if (!self.enabled) return;

        // Capture stack trace
        var stack_trace: ?[]usize = null;
        if (std.debug.have_ucontext) {
            var stack_trace_buf: std.builtin.StackTrace = undefined;
            var addresses: [32]usize = undefined;
            stack_trace_buf.instruction_addresses = &addresses;
            stack_trace_buf.index = 0;

            std.debug.captureStackTrace(2, &stack_trace_buf); // Skip 2 frames
            if (stack_trace_buf.index > 0) {
                const frames = addresses[0..stack_trace_buf.index];
                stack_trace = try self.backing_allocator.dupe(usize, frames);
            }
        }

        const info = AllocationInfo{
            .size = size,
            .timestamp = std.time.nanoTimestamp(),
            .stack_trace = stack_trace,
            .allocator_ref = self.backing_allocator,
        };
        try self.allocations.put(ptr, info);
    }

    pub fn trackFree(self: *Self, ptr: usize) void {
        if (!self.enabled) return;

        if (self.allocations.fetchRemove(ptr)) |removed| {
            const info = removed.value;
            if (info.stack_trace) |trace| {
                if (info.allocator_ref) |alloc| {
                    alloc.free(trace);
                }
            }
        }
    }

    pub fn checkLeaks(self: *Self) !void {
        const stats = self.tracking_allocator.getStats();

        if (stats.has_leaks) {
            std.log.err("Memory leaks detected:", .{});
            std.log.err("  Current allocated: {} bytes", .{stats.current_allocated});
            std.log.err("  Total allocations: {}", .{stats.allocation_count});
            std.log.err("  Total deallocations: {}", .{stats.deallocation_count});
            std.log.err("  Peak memory usage: {} bytes", .{stats.peak_memory});

            if (self.allocations.count() > 0) {
                std.log.err("  Detailed leak information:");
                var iter = self.allocations.iterator();
                while (iter.next()) |entry| {
                    const info = entry.value_ptr.*;
                    std.log.err("    {} bytes at 0x{X} (allocated at {}ns)", .{ info.size, entry.key_ptr.*, info.timestamp });

                    // Print stack trace if available
                    if (info.stack_trace) |trace| {
                        std.log.err("      Stack trace:");
                        self.printStackTrace(trace) catch {};
                    } else {
                        std.log.err("      Stack trace: not available");
                    }
                }
            }

            return error.MemoryLeak;
        }
    }

    fn printStackTrace(self: *Self, trace: []const usize) !void {
        _ = self; // Unused but needed for method signature
        for (trace, 0..) |addr, i| {
            if (i >= 10) break; // Limit to first 10 frames

            // Try to symbolicate the address
            if (std.debug.getSelfDebugInfo()) |debug_info| {
                if (std.debug.getSymbolName(debug_info, addr)) |symbol| {
                    std.log.err("        [{d}] 0x{X} {s}", .{ i, addr, symbol });
                } else {
                    std.log.err("        [{d}] 0x{X} <unknown>", .{ i, addr });
                }
            } else {
                std.log.err("        [{d}] 0x{X}", .{ i, addr });
            }
        }
    }

    pub fn getStats(self: *Self) struct {
        allocated: usize,
        freed: usize,
        leaked: usize,
        peak: usize,
        allocation_count: u32,
        deallocation_count: u32,
    } {
        const tracking_stats = self.tracking_allocator.getStats();

        return .{
            .allocated = tracking_stats.total_allocated,
            .freed = tracking_stats.total_deallocated,
            .leaked = tracking_stats.current_allocated,
            .peak = tracking_stats.peak_memory,
            .allocation_count = tracking_stats.allocation_count,
            .deallocation_count = tracking_stats.deallocation_count,
        };
    }

    pub fn printReport(self: *Self) void {
        const stats = self.getStats();

        std.debug.print("\n=== Memory Tracking Report ===\n");
        std.debug.print("Total allocated:   {} bytes ({} allocations)\n", .{ stats.allocated, stats.allocation_count });
        std.debug.print("Total freed:       {} bytes ({} deallocations)\n", .{ stats.freed, stats.deallocation_count });
        std.debug.print("Currently leaked:  {} bytes\n", .{stats.leaked});
        std.debug.print("Peak memory usage: {} bytes\n", .{stats.peak});

        if (stats.leaked > 0) {
            std.debug.print("{}WARNING: Memory leaks detected!\x1b[0m\n", .{TestResult.fail.color()});
        } else {
            std.debug.print("{}No memory leaks detected.\x1b[0m\n", .{TestResult.pass.color()});
        }
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

// Test helper functions
fn passingTestFunction(allocator: std.mem.Allocator) anyerror!void {
    _ = allocator;
    // This test always passes
    try Assert.isTrue(true);
}

fn failingTestFunction(allocator: std.mem.Allocator) anyerror!void {
    _ = allocator;
    // This test always fails
    try Assert.isTrue(false);
}

fn errorTestFunction(allocator: std.mem.Allocator) anyerror!void {
    _ = allocator;
    // This test throws an error
    return error.TestError;
}

fn memoryLeakTestFunction(allocator: std.mem.Allocator) anyerror!void {
    // This test allocates memory and properly frees it
    const memory = try allocator.alloc(u8, 100);
    defer allocator.free(memory);
    try Assert.isTrue(true);
}

test "TestSuite.runAll basic functionality" {
    var suite = TestSuite.init(std.testing.allocator, "Test Suite", "Test suite for runAll testing");
    defer suite.deinit();

    // Add a passing test
    try suite.addTest(TestCase.withFunction(
        "passing_test",
        .unit,
        .medium,
        "A test that should pass",
        passingTestFunction,
    ));

    // Add a failing test
    try suite.addTest(TestCase.withFunction(
        "failing_test",
        .unit,
        .medium,
        "A test that should fail",
        failingTestFunction,
    ));

    // Add a disabled test
    var disabled_test = TestCase.withFunction(
        "disabled_test",
        .unit,
        .low,
        "A test that is disabled",
        passingTestFunction,
    );
    disabled_test.enabled = false;
    try suite.addTest(disabled_test);

    // Run all tests
    var summary = try suite.runAll();
    defer summary.deinit();

    // Verify results
    try std.testing.expect(suite.tests.items.len == 3);

    // Check passing test
    try std.testing.expect(suite.tests.items[0].result == .pass);
    try std.testing.expect(suite.tests.items[0].metrics != null);
    try std.testing.expect(suite.tests.items[0].duration_ms() > 0);

    // Check failing test
    try std.testing.expect(suite.tests.items[1].result == .fail);
    try std.testing.expect(suite.tests.items[1].error_message != null);
    try std.testing.expect(suite.tests.items[1].metrics != null);

    // Check disabled test
    try std.testing.expect(suite.tests.items[2].result == .skip);
}

test "TestSuite.runAll error handling" {
    var suite = TestSuite.init(std.testing.allocator, "Error Test Suite", "Testing error handling");
    defer suite.deinit();

    // Add an error-throwing test
    try suite.addTest(TestCase.withFunction(
        "error_test",
        .unit,
        .high,
        "A test that throws an error",
        errorTestFunction,
    ));

    // Add a test without a test function
    const no_function_test = TestCase{
        .name = "no_function_test",
        .category = .unit,
        .priority = .medium,
        .description = "A test without a function",
    };
    try suite.addTest(no_function_test);

    // Run all tests
    var summary = try suite.runAll();
    defer summary.deinit();

    // Verify results
    try std.testing.expect(suite.tests.items.len == 2);

    // Check error test
    try std.testing.expect(suite.tests.items[0].result == .@"error");
    try std.testing.expect(suite.tests.items[0].error_message != null);

    // Check no function test
    try std.testing.expect(suite.tests.items[1].result == .skip);
    try std.testing.expectEqualStrings("No test function provided", suite.tests.items[1].error_message.?);
}

test "TestSuite.runAll memory tracking" {
    var suite = TestSuite.init(std.testing.allocator, "Memory Test Suite", "Testing memory tracking");
    defer suite.deinit();

    // Add a test that allocates and frees memory
    try suite.addTest(TestCase.withFunction(
        "memory_allocation_test",
        .unit,
        .high,
        "A test that allocates and frees memory",
        memoryLeakTestFunction,
    ));

    // Run all tests
    var summary = try suite.runAll();
    defer summary.deinit();

    // Verify that metrics were collected
    try std.testing.expect(suite.tests.items.len == 1);
    try std.testing.expect(suite.tests.items[0].metrics != null);

    const metrics = suite.tests.items[0].metrics.?;
    try std.testing.expect(metrics.allocations > 0);
    try std.testing.expect(!metrics.memoryLeaked()); // Should not leak memory
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

test "TrackingAllocator memory tracking" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var tracking = TrackingAllocator.init(gpa.allocator());
    const alloc = tracking.allocator();

    // Test basic allocation tracking
    const ptr1 = try alloc.alloc(u8, 100);
    const stats1 = tracking.getStats();
    try Assert.equals(u32, 1, stats1.allocation_count);
    try Assert.equals(usize, 100, stats1.total_allocated);
    try Assert.equals(usize, 100, stats1.current_allocated);
    try Assert.equals(usize, 100, stats1.peak_memory);

    // Test multiple allocations
    const ptr2 = try alloc.alloc(u8, 200);
    const stats2 = tracking.getStats();
    try Assert.equals(u32, 2, stats2.allocation_count);
    try Assert.equals(usize, 300, stats2.total_allocated);
    try Assert.equals(usize, 300, stats2.current_allocated);
    try Assert.equals(usize, 300, stats2.peak_memory);

    // Test deallocation tracking
    alloc.free(ptr1);
    const stats3 = tracking.getStats();
    try Assert.equals(u32, 1, stats3.deallocation_count);
    try Assert.equals(usize, 100, stats3.total_deallocated);
    try Assert.equals(usize, 200, stats3.current_allocated);
    try Assert.equals(usize, 300, stats3.peak_memory); // Peak should remain

    // Clean up
    alloc.free(ptr2);
    const stats4 = tracking.getStats();
    try Assert.equals(u32, 2, stats4.deallocation_count);
    try Assert.equals(usize, 300, stats4.total_deallocated);
    try Assert.equals(usize, 0, stats4.current_allocated);
    try Assert.isFalse(stats4.has_leaks);
}

test "MemoryTracker leak detection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var tracker = try MemoryTracker.init(gpa.allocator());
    defer tracker.deinit();

    const alloc = tracker.allocator();

    // Test no leaks scenario
    {
        const ptr = try alloc.alloc(u8, 50);
        alloc.free(ptr);

        const stats = tracker.getStats();
        try Assert.equals(usize, 0, stats.leaked);
    }

    // Reset for leak test
    tracker.reset();

    // Test leak detection and then properly free
    {
        const ptr = try alloc.alloc(u8, 100);

        // Check that tracker detects the allocated memory
        var stats = tracker.getStats();
        try Assert.equals(usize, 100, stats.leaked);
        try Assert.equals(usize, 100, stats.allocated);
        try Assert.equals(usize, 0, stats.freed);

        // Now properly free to avoid actual leak
        alloc.free(ptr);
        stats = tracker.getStats();
        try Assert.equals(usize, 0, stats.leaked);
    }
}

test "Benchmark with memory tracking" {
    // Simple function to benchmark that allocates memory
    const TestFn = struct {
        fn allocateAndFree(alloc: Allocator, size: usize) !void {
            const ptr = try alloc.alloc(u8, size);
            defer alloc.free(ptr);

            // Do some work with the memory
            for (ptr, 0..) |*byte, i| {
                byte.* = @intCast(i % 256);
            }
        }
    };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var benchmark = Benchmark.init(gpa.allocator(), 100);
    benchmark.warmup_iterations = 10; // Reduce for faster test

    const metrics = try benchmark.run(TestFn.allocateAndFree, @as(usize, 1024));

    // Verify we tracked memory operations
    try Assert.isTrue(metrics.allocations > 0);
    try Assert.isTrue(metrics.deallocations > 0);
    try Assert.isTrue(metrics.memory_used > 0);
    try Assert.isTrue(metrics.peak_memory > 0);
    try Assert.equals(u32, 100, metrics.iterations);

    // Should have no leaks (allocations == deallocations)
    try Assert.isFalse(metrics.memoryLeaked());
}

test "TrackingAllocator allocation lifecycle" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var tracking = TrackingAllocator.init(gpa.allocator());
    defer tracking.deinit();
    const alloc = tracking.allocator();

    // Test basic allocation and free cycle
    const ptr1 = try alloc.alloc(u8, 100);
    const stats1 = tracking.getStats();
    try Assert.equals(u32, 1, stats1.allocation_count);
    try Assert.isTrue(stats1.current_allocated >= 100);

    // Allocate more memory
    const ptr2 = try alloc.alloc(u8, 200);
    const stats2 = tracking.getStats();
    try Assert.equals(u32, 2, stats2.allocation_count);
    try Assert.isTrue(stats2.current_allocated >= 300);

    // Free first allocation
    alloc.free(ptr1);
    const stats3 = tracking.getStats();
    try Assert.equals(u32, 1, stats3.deallocation_count);
    try Assert.isTrue(stats3.current_allocated >= 200);
    try Assert.isTrue(stats3.current_allocated < stats2.current_allocated);

    // Free second allocation
    alloc.free(ptr2);
    const stats4 = tracking.getStats();
    try Assert.equals(u32, 2, stats4.deallocation_count);
    try Assert.equals(usize, 0, stats4.current_allocated);
    try Assert.isFalse(stats4.has_leaks);
}

test "JUnit XML generation basic functionality" {
    var suite = TestSuite.init(std.testing.allocator, "Core Tests", "Basic functionality tests");
    defer suite.deinit();

    // Add some test cases with different results
    const passing_test = TestCase{
        .name = "test_passing",
        .category = .unit,
        .priority = .high,
        .description = "A passing test",
        .result = .pass,
        .start_time = 1000000000, // 1ms in nanoseconds
        .end_time = 1005000000, // 5ms in nanoseconds
    };

    const failing_test = TestCase{
        .name = "test_failing",
        .category = .unit,
        .priority = .medium,
        .description = "A failing test",
        .result = .fail,
        .error_message = "Expected 42 but got 24",
        .start_time = 2000000000,
        .end_time = 2003000000,
    };

    const skipped_test = TestCase{
        .name = "test_skipped",
        .category = .integration,
        .priority = .low,
        .description = "A skipped test",
        .result = .skip,
        .error_message = "Feature not implemented",
        .start_time = 0,
        .end_time = 0,
    };

    try suite.addTest(passing_test);
    try suite.addTest(failing_test);
    try suite.addTest(skipped_test);

    var summary = TestSummary.init(std.testing.allocator);
    defer summary.deinit();
    try summary.addSuite(&suite);

    // Generate XML to a buffer
    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();

    try summary.writeJUnitToWriter(buffer.writer());
    const xml = buffer.items;

    // Verify XML structure and content
    try Assert.stringContains(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    try Assert.stringContains(xml, "<testsuites tests=\"3\" failures=\"1\" errors=\"0\" skipped=\"1\"");
    try Assert.stringContains(xml, "<testsuite name=\"Core Tests\"");
    try Assert.stringContains(xml, "<testcase name=\"test_passing\"");
    try Assert.stringContains(xml, "<testcase name=\"test_failing\"");
    try Assert.stringContains(xml, "<testcase name=\"test_skipped\"");
    try Assert.stringContains(xml, "<failure");
    try Assert.stringContains(xml, "<skipped");
    try Assert.stringContains(xml, "Expected 42 but got 24");
    try Assert.stringContains(xml, "</testsuites>");
}

test "JUnit XML escaping and special characters" {
    var suite = TestSuite.init(std.testing.allocator, "Special Characters & Tests <\"'>", "Tests with special XML characters");
    defer suite.deinit();

    const test_with_special_chars = TestCase{
        .name = "test_with_<>&\"'_chars",
        .category = .unit,
        .priority = .high,
        .description = "Test with special characters",
        .result = .fail,
        .error_message = "Error with <tags> & \"quotes\" and 'apostrophes'",
        .start_time = 1000000000,
        .end_time = 1001000000,
    };

    try suite.addTest(test_with_special_chars);

    var summary = TestSummary.init(std.testing.allocator);
    defer summary.deinit();
    try summary.addSuite(&suite);

    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();

    try summary.writeJUnitToWriter(buffer.writer());
    const xml = buffer.items;

    // Verify special characters are properly escaped
    try Assert.stringContains(xml, "&lt;tags&gt;");
    try Assert.stringContains(xml, "&amp;");
    try Assert.stringContains(xml, "&quot;quotes&quot;");
    try Assert.stringContains(xml, "&apos;apostrophes&apos;");

    // Verify XML is well-formed (no unescaped special chars in content)
    try Assert.isTrue(std.mem.indexOf(u8, xml, "<tags>") == null);
    try Assert.isTrue(std.mem.indexOf(u8, xml, "& \"") == null);
}

test "JUnit XML file output" {
    var suite = TestSuite.init(std.testing.allocator, "File Output Tests", "Testing file output functionality");
    defer suite.deinit();

    const test_case = TestCase{
        .name = "file_output_test",
        .category = .unit,
        .priority = .medium,
        .description = "Test file output",
        .result = .pass,
        .start_time = 1000000000,
        .end_time = 1002000000,
    };

    try suite.addTest(test_case);

    var summary = TestSummary.init(std.testing.allocator);
    defer summary.deinit();
    try summary.addSuite(&suite);

    // Write to file
    const test_file = "test_results.xml";
    try summary.writeJUnitToFile(test_file);
    defer std.fs.cwd().deleteFile(test_file) catch {};

    // Read file and verify content
    const file = try std.fs.cwd().openFile(test_file, .{});
    defer file.close();

    const file_size = try file.getEndPos();
    const content = try std.testing.allocator.alloc(u8, file_size);
    defer std.testing.allocator.free(content);

    _ = try file.readAll(content);

    try Assert.stringContains(content, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    try Assert.stringContains(content, "<testsuite name=\"File Output Tests\"");
    try Assert.stringContains(content, "<testcase name=\"file_output_test\"");
}

test "JUnit XML timeout and error handling" {
    var suite = TestSuite.init(std.testing.allocator, "Error Tests", "Testing error and timeout scenarios");
    defer suite.deinit();

    const timeout_test = TestCase{
        .name = "timeout_test",
        .category = .performance,
        .priority = .high,
        .description = "Test that times out",
        .result = .timeout,
        .timeout_ms = 5000,
        .start_time = 1000000000,
        .end_time = 1006000000000, // 6 seconds (exceeds timeout)
    };

    const error_test = TestCase{
        .name = "error_test",
        .category = .unit,
        .priority = .critical,
        .description = "Test with error",
        .result = .@"error",
        .error_message = "Unexpected system error occurred",
        .start_time = 2000000000,
        .end_time = 2001000000,
    };

    try suite.addTest(timeout_test);
    try suite.addTest(error_test);

    var summary = TestSummary.init(std.testing.allocator);
    defer summary.deinit();
    try summary.addSuite(&suite);

    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();

    try summary.writeJUnitToWriter(buffer.writer());
    const xml = buffer.items;

    // Verify timeout is treated as error
    try Assert.stringContains(xml, "errors=\"2\"");
    try Assert.stringContains(xml, "TimeoutError");
    try Assert.stringContains(xml, "Test timed out after 5000ms");
    try Assert.stringContains(xml, "TestError");
    try Assert.stringContains(xml, "Unexpected system error occurred");
}

test "JUnit XML empty test suite" {
    var suite = TestSuite.init(std.testing.allocator, "Empty Suite", "Suite with no tests");
    defer suite.deinit();

    var summary = TestSummary.init(std.testing.allocator);
    defer summary.deinit();
    try summary.addSuite(&suite);

    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();

    try summary.writeJUnitToWriter(buffer.writer());
    const xml = buffer.items;

    // Verify empty suite is handled correctly
    try Assert.stringContains(xml, "tests=\"0\"");
    try Assert.stringContains(xml, "failures=\"0\"");
    try Assert.stringContains(xml, "errors=\"0\"");
    try Assert.stringContains(xml, "<testsuite name=\"Empty Suite\" tests=\"0\"");
}

test "JUnit XML multiple test suites" {
    var suite1 = TestSuite.init(std.testing.allocator, "Suite One", "First test suite");
    defer suite1.deinit();

    var suite2 = TestSuite.init(std.testing.allocator, "Suite Two", "Second test suite");
    defer suite2.deinit();

    // Add tests to first suite
    const test1 = TestCase{
        .name = "suite1_test1",
        .category = .unit,
        .priority = .high,
        .description = "First test",
        .result = .pass,
        .start_time = 1000000000,
        .end_time = 1001000000,
    };
    try suite1.addTest(test1);

    // Add tests to second suite
    const test2 = TestCase{
        .name = "suite2_test1",
        .category = .integration,
        .priority = .medium,
        .description = "Second test",
        .result = .fail,
        .error_message = "Integration test failed",
        .start_time = 2000000000,
        .end_time = 2002000000,
    };
    try suite2.addTest(test2);

    var summary = TestSummary.init(std.testing.allocator);
    defer summary.deinit();
    try summary.addSuite(&suite1);
    try summary.addSuite(&suite2);

    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();

    try summary.writeJUnitToWriter(buffer.writer());
    const xml = buffer.items;

    // Verify both suites are present
    try Assert.stringContains(xml, "<testsuite name=\"Suite One\"");
    try Assert.stringContains(xml, "<testsuite name=\"Suite Two\"");
    try Assert.stringContains(xml, "suite1_test1");
    try Assert.stringContains(xml, "suite2_test1");
    try Assert.stringContains(xml, "tests=\"2\""); // Total tests across all suites
    try Assert.stringContains(xml, "failures=\"1\""); // One failure total
}
