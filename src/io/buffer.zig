//! High-performance Buffer management for Ferret
//!
//! This module provides efficient buffer implementations optimized for I/O operations:
//! - Buffer: Dynamic growable buffer with efficient read/write operations
//! - RingBuffer: Fixed-size circular buffer for streaming data
//! - BufferPool: Memory pool for efficient buffer allocation/reuse
//! - FixedBuffer: Stack-allocated buffer for small, fixed-size operations
//!
//! All implementations focus on performance and memory efficiency for network I/O.

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const testing = std.testing;
const assert = std.debug.assert;

/// Errors that can occur during buffer operations
pub const BufferError = error{
    /// Buffer has reached its maximum capacity
    BufferFull,
    /// Not enough data available to read
    NotEnoughData,
    /// Invalid offset or length provided
    InvalidRange,
    /// Attempted to allocate memory but allocation failed
    OutOfMemory,
};

/// Dynamic growable buffer optimized for I/O operations
/// Provides efficient read/write operations with automatic growth
pub const Buffer = struct {
    const Self = @This();
    const DEFAULT_CAPACITY = 4096; // Use default value, can be overridden at runtime
    const GROWTH_FACTOR = 2;

    data: []u8,
    read_pos: usize,
    write_pos: usize,
    capacity: usize,
    allocator: Allocator,

    /// Initialize a new Buffer with default capacity
    pub fn init(allocator: Allocator) BufferError!Self {
        return Self.initWithCapacity(allocator, DEFAULT_CAPACITY);
    }

    /// Initialize a new Buffer with specified capacity
    pub fn initWithCapacity(allocator: Allocator, capacity: usize) BufferError!Self {
        const data = allocator.alloc(u8, capacity) catch return BufferError.OutOfMemory;
        return Self{
            .data = data,
            .read_pos = 0,
            .write_pos = 0,
            .capacity = capacity,
            .allocator = allocator,
        };
    }

    /// Deinitialize the buffer and free memory
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.data);
        self.* = undefined;
    }

    /// Write data to the buffer, growing if necessary
    pub fn write(self: *Self, data: []const u8) BufferError!usize {
        if (data.len == 0) return 0;

        // Ensure we have enough space
        try self.ensureCapacity(data.len);

        // Copy data to buffer
        @memcpy(self.data[self.write_pos .. self.write_pos + data.len], data);
        self.write_pos += data.len;

        return data.len;
    }

    /// Write a single byte to the buffer
    pub fn writeByte(self: *Self, byte: u8) BufferError!void {
        try self.ensureCapacity(1);
        self.data[self.write_pos] = byte;
        self.write_pos += 1;
    }

    /// Read data from the buffer into provided slice
    /// Returns number of bytes actually read
    pub fn read(self: *Self, dest: []u8) usize {
        const available_bytes = self.available();
        const to_read = @min(dest.len, available_bytes);

        if (to_read > 0) {
            @memcpy(dest[0..to_read], self.data[self.read_pos .. self.read_pos + to_read]);
            self.read_pos += to_read;
        }

        return to_read;
    }

    /// Read a single byte from the buffer
    pub fn readByte(self: *Self) ?u8 {
        if (self.available() == 0) return null;

        const byte = self.data[self.read_pos];
        self.read_pos += 1;
        return byte;
    }

    /// Peek at data without consuming it
    pub fn peek(self: *const Self, dest: []u8) usize {
        const available_bytes = self.available();
        const to_peek = @min(dest.len, available_bytes);

        if (to_peek > 0) {
            @memcpy(dest[0..to_peek], self.data[self.read_pos .. self.read_pos + to_peek]);
        }

        return to_peek;
    }

    /// Get a slice of readable data without consuming it
    pub fn readable(self: *const Self) []const u8 {
        return self.data[self.read_pos..self.write_pos];
    }

    /// Get a slice of writable space
    pub fn writable(self: *Self) []u8 {
        return self.data[self.write_pos..self.capacity];
    }

    /// Mark bytes as written (useful after direct writes to writable())
    pub fn commitWrite(self: *Self, bytes: usize) BufferError!void {
        if (self.write_pos + bytes > self.capacity) {
            return BufferError.InvalidRange;
        }
        self.write_pos += bytes;
    }

    /// Mark bytes as read (useful after direct reads from readable())
    pub fn commitRead(self: *Self, bytes: usize) BufferError!void {
        if (self.read_pos + bytes > self.write_pos) {
            return BufferError.InvalidRange;
        }
        self.read_pos += bytes;
    }

    /// Skip the specified number of bytes in the read buffer
    pub fn skip(self: *Self, bytes: usize) BufferError!void {
        if (self.read_pos + bytes > self.write_pos) {
            return BufferError.NotEnoughData;
        }
        self.read_pos += bytes;
    }

    /// Reset the buffer to empty state (keep allocated memory)
    pub fn reset(self: *Self) void {
        self.read_pos = 0;
        self.write_pos = 0;
    }

    /// Compact the buffer by moving unread data to the beginning
    pub fn compact(self: *Self) void {
        const available_data = self.available();
        if (available_data > 0 and self.read_pos > 0) {
            std.mem.copyForwards(u8, self.data[0..available_data], self.data[self.read_pos..self.write_pos]);
        }
        self.read_pos = 0;
        self.write_pos = available_data;
    }

    /// Get number of bytes available for reading
    pub fn available(self: *const Self) usize {
        return self.write_pos - self.read_pos;
    }

    /// Get number of bytes that can be written without growing
    pub fn writerSpace(self: *const Self) usize {
        return self.capacity - self.write_pos;
    }

    /// Check if buffer is empty
    pub fn isEmpty(self: *const Self) bool {
        return self.read_pos == self.write_pos;
    }

    /// Get current capacity
    pub fn getCapacity(self: *const Self) usize {
        return self.capacity;
    }

    /// Ensure buffer has at least the specified writable capacity
    fn ensureCapacity(self: *Self, needed: usize) BufferError!void {
        const space_needed = needed;
        const space_available = self.writerSpace();

        if (space_available >= space_needed) {
            return; // Already have enough space
        }

        // Try compacting first
        self.compact();
        if (self.writerSpace() >= space_needed) {
            return;
        }

        // Need to grow the buffer
        var new_capacity = self.capacity;
        while (new_capacity < self.available() + space_needed) {
            new_capacity *= GROWTH_FACTOR;
        }

        const new_data = self.allocator.realloc(self.data, new_capacity) catch return BufferError.OutOfMemory;
        self.data = new_data;
        self.capacity = new_capacity;
    }
};

/// Fixed-size circular buffer for streaming data
/// Optimized for high-throughput scenarios with known buffer sizes
pub fn RingBuffer(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        data: [capacity]u8,
        read_pos: usize,
        write_pos: usize,
        full: bool,

        /// Initialize a new RingBuffer
        pub fn init() Self {
            return Self{
                .data = undefined,
                .read_pos = 0,
                .write_pos = 0,
                .full = false,
            };
        }

        /// Write data to the ring buffer
        /// Returns number of bytes actually written
        pub fn write(self: *Self, data: []const u8) usize {
            var written: usize = 0;

            for (data) |byte| {
                if (self.isFull()) break;

                self.data[self.write_pos] = byte;
                self.write_pos = (self.write_pos + 1) % capacity;

                if (self.write_pos == self.read_pos) {
                    self.full = true;
                }

                written += 1;
            }

            return written;
        }

        /// Write a single byte, overwriting old data if buffer is full
        pub fn writeByte(self: *Self, byte: u8) void {
            self.data[self.write_pos] = byte;
            self.write_pos = (self.write_pos + 1) % capacity;

            if (self.full) {
                // Overwrite mode: advance read position
                self.read_pos = (self.read_pos + 1) % capacity;
            }

            if (self.write_pos == self.read_pos) {
                self.full = true;
            }
        }

        /// Read data from the ring buffer
        pub fn read(self: *Self, dest: []u8) usize {
            var read_count: usize = 0;

            for (dest) |*byte| {
                if (self.isEmpty()) break;

                byte.* = self.data[self.read_pos];
                self.read_pos = (self.read_pos + 1) % capacity;
                self.full = false;
                read_count += 1;
            }

            return read_count;
        }

        /// Read a single byte
        pub fn readByte(self: *Self) ?u8 {
            if (self.isEmpty()) return null;

            const byte = self.data[self.read_pos];
            self.read_pos = (self.read_pos + 1) % capacity;
            self.full = false;
            return byte;
        }

        /// Get number of bytes available for reading
        pub fn available(self: *const Self) usize {
            if (self.full) return capacity;
            if (self.write_pos >= self.read_pos) {
                return self.write_pos - self.read_pos;
            } else {
                return capacity - self.read_pos + self.write_pos;
            }
        }

        /// Get number of bytes that can be written
        pub fn writerSpace(self: *const Self) usize {
            return capacity - self.available();
        }

        /// Check if buffer is empty
        pub fn isEmpty(self: *const Self) bool {
            return !self.full and (self.read_pos == self.write_pos);
        }

        /// Check if buffer is full
        pub fn isFull(self: *const Self) bool {
            return self.full;
        }

        /// Reset the buffer to empty state
        pub fn reset(self: *Self) void {
            self.read_pos = 0;
            self.write_pos = 0;
            self.full = false;
        }

        /// Get the capacity of the ring buffer
        pub fn getCapacity() usize {
            return capacity;
        }
    };
}

/// Buffer pool for efficient allocation and reuse
pub const BufferPool = struct {
    const Self = @This();
    const PooledBuffer = struct {
        buffer: Buffer,
        in_use: bool,
        next: ?*PooledBuffer,
    };

    free_list: ?*PooledBuffer,
    all_buffers: ArrayList(*PooledBuffer),
    allocator: Allocator,
    default_capacity: usize,

    /// Initialize a new BufferPool
    pub fn init(allocator: Allocator, default_capacity: usize) Self {
        return Self{
            .free_list = null,
            .all_buffers = ArrayList(*PooledBuffer).init(allocator),
            .allocator = allocator,
            .default_capacity = default_capacity,
        };
    }

    /// Deinitialize the buffer pool
    pub fn deinit(self: *Self) void {
        for (self.all_buffers.items) |pooled| {
            pooled.buffer.deinit();
            self.allocator.destroy(pooled);
        }
        self.all_buffers.deinit();
    }

    /// Acquire a buffer from the pool
    pub fn acquire(self: *Self) BufferError!*Buffer {
        // Check free list first
        if (self.free_list) |pooled| {
            self.free_list = pooled.next;
            pooled.in_use = true;
            pooled.next = null;
            pooled.buffer.reset();
            return &pooled.buffer;
        }

        // No free buffer, create a new one
        const pooled = self.allocator.create(PooledBuffer) catch return BufferError.OutOfMemory;
        pooled.* = PooledBuffer{
            .buffer = Buffer.initWithCapacity(self.allocator, self.default_capacity) catch {
                self.allocator.destroy(pooled);
                return BufferError.OutOfMemory;
            },
            .in_use = true,
            .next = null,
        };

        try self.all_buffers.append(pooled);
        return &pooled.buffer;
    }

    /// Release a buffer back to the pool
    pub fn release(self: *Self, buffer: *Buffer) void {
        // Find the pooled buffer that contains this buffer
        for (self.all_buffers.items) |pooled| {
            if (&pooled.buffer == buffer) {
                pooled.in_use = false;
                pooled.next = self.free_list;
                self.free_list = pooled;
                break;
            }
        }
    }

    /// Get statistics about the pool
    pub fn stats(self: *const Self) struct { total: usize, in_use: usize, free: usize } {
        var in_use_count: usize = 0;
        for (self.all_buffers.items) |pooled| {
            if (pooled.in_use) in_use_count += 1;
        }

        return .{
            .total = self.all_buffers.items.len,
            .in_use = in_use_count,
            .free = self.all_buffers.items.len - in_use_count,
        };
    }
};

/// Fixed-size stack-allocated buffer for small operations
pub fn FixedBuffer(comptime size: usize) type {
    return struct {
        const Self = @This();

        data: [size]u8,
        len: usize,

        /// Initialize a new FixedBuffer
        pub fn init() Self {
            return Self{
                .data = undefined,
                .len = 0,
            };
        }

        /// Write data to the buffer
        pub fn write(self: *Self, data: []const u8) BufferError!usize {
            const space_available = size - self.len;

            if (data.len > space_available) return BufferError.BufferFull;

            @memcpy(self.data[self.len .. self.len + data.len], data);
            self.len += data.len;
            return data.len;
        }

        /// Write a single byte
        pub fn writeByte(self: *Self, byte: u8) BufferError!void {
            if (self.len >= size) return BufferError.BufferFull;
            self.data[self.len] = byte;
            self.len += 1;
        }

        /// Get the readable data as a slice
        pub fn readable(self: *const Self) []const u8 {
            return self.data[0..self.len];
        }

        /// Get writable space as a slice
        pub fn writable(self: *Self) []u8 {
            return self.data[self.len..];
        }

        /// Mark bytes as written
        pub fn commitWrite(self: *Self, bytes: usize) BufferError!void {
            if (self.len + bytes > size) return BufferError.InvalidRange;
            self.len += bytes;
        }

        /// Reset the buffer
        pub fn reset(self: *Self) void {
            self.len = 0;
        }

        /// Check if buffer is empty
        pub fn isEmpty(self: *const Self) bool {
            return self.len == 0;
        }

        /// Check if buffer is full
        pub fn isFull(self: *const Self) bool {
            return self.len >= size;
        }

        /// Get current length
        pub fn getLen(self: *const Self) usize {
            return self.len;
        }

        /// Get capacity
        pub fn getCapacity() usize {
            return size;
        }
    };
}

// Tests
test "Buffer basic operations" {
    var buffer = try Buffer.init(testing.allocator);
    defer buffer.deinit();

    // Test writing
    try testing.expect(try buffer.write("hello") == 5);
    try testing.expect(try buffer.write(" world") == 6);
    try testing.expect(buffer.available() == 11);

    // Test reading
    var read_buf: [20]u8 = undefined;
    try testing.expect(buffer.read(&read_buf) == 11);
    try testing.expectEqualStrings("hello world", read_buf[0..11]);
    try testing.expect(buffer.isEmpty());
}

test "Buffer growth and compaction" {
    var buffer = try Buffer.initWithCapacity(testing.allocator, 8);
    defer buffer.deinit();

    // Fill buffer
    _ = try buffer.write("12345678");
    try testing.expect(buffer.getCapacity() == 8);

    // Read some data
    var read_buf: [4]u8 = undefined;
    _ = buffer.read(&read_buf);

    // Write more data to trigger growth
    _ = try buffer.write("abcdefghij");
    try testing.expect(buffer.getCapacity() > 8);

    // Verify data integrity
    var full_read: [14]u8 = undefined;
    const read_count = buffer.read(&full_read);
    try testing.expectEqualStrings("5678abcdefghij", full_read[0..read_count]);
}

test "RingBuffer operations" {
    var ring = RingBuffer(4).init();

    // Test writing
    try testing.expect(ring.write("abc".ptr[0..3]) == 3);
    try testing.expect(ring.available() == 3);
    try testing.expect(!ring.isFull());

    // Fill buffer
    ring.writeByte('d');
    try testing.expect(ring.isFull());

    // Test reading
    var read_buf: [4]u8 = undefined;
    try testing.expect(ring.read(&read_buf) == 4);
    try testing.expectEqualStrings("abcd", read_buf[0..4]);
    try testing.expect(ring.isEmpty());

    // Test overwrite mode
    _ = ring.write("1234".ptr[0..4]);
    ring.writeByte('5'); // Should overwrite '1'
    _ = ring.read(&read_buf);
    try testing.expectEqualStrings("2345", read_buf[0..4]);
}

test "BufferPool management" {
    var pool = BufferPool.init(testing.allocator, 1024);
    defer pool.deinit();

    // Acquire buffers
    var buf1 = try pool.acquire();
    var buf2 = try pool.acquire();

    _ = try buf1.write("test1");
    _ = try buf2.write("test2");

    var stats = pool.stats();
    try testing.expect(stats.total == 2);
    try testing.expect(stats.in_use == 2);
    try testing.expect(stats.free == 0);

    // Release a buffer
    pool.release(buf1);
    stats = pool.stats();
    try testing.expect(stats.in_use == 1);
    try testing.expect(stats.free == 1);

    // Acquire again (should reuse)
    var buf3 = try pool.acquire();
    try testing.expect(buf3 == buf1); // Should be the same buffer
    try testing.expect(buf3.isEmpty()); // Should be reset
}

test "FixedBuffer operations" {
    var buffer = FixedBuffer(8).init();

    // Test writing
    try testing.expect(try buffer.write("hello") == 5);
    try testing.expectError(BufferError.BufferFull, buffer.write("world!"));

    // Test exact fit write
    try testing.expect(try buffer.write("wor") == 3);
    try testing.expect(buffer.isFull());

    // Test readable data
    try testing.expectEqualStrings("hellowor", buffer.readable());
}

test "Buffer edge cases" {
    // Test empty operations
    var buffer = try Buffer.init(testing.allocator);
    defer buffer.deinit();

    try testing.expect(buffer.readByte() == null);
    try testing.expect(buffer.isEmpty());

    var empty_buf: [10]u8 = undefined;
    try testing.expect(buffer.peek(&empty_buf) == 0);

    // Test single byte operations
    try buffer.writeByte('A');
    try testing.expect(buffer.readByte().? == 'A');
    try testing.expect(buffer.isEmpty());
}

test "Buffer performance characteristics" {
    const iterations = 10000;

    var buffer = try Buffer.init(testing.allocator);
    defer buffer.deinit();

    // Write performance
    const start = std.time.nanoTimestamp();
    for (0..iterations) |i| {
        var temp_buf: [8]u8 = undefined;
        const data = std.fmt.bufPrint(&temp_buf, "{}", .{i}) catch unreachable;
        _ = try buffer.write(data);
    }
    const write_time = std.time.nanoTimestamp() - start;

    // Read performance
    const read_start = std.time.nanoTimestamp();
    var read_buf: [1024]u8 = undefined;
    while (!buffer.isEmpty()) {
        _ = buffer.read(&read_buf);
    }
    const read_time = std.time.nanoTimestamp() - read_start;

    std.log.info("Buffer performance: {} iterations", .{iterations});
    std.log.info("  Write: {d:.2} ns/op", .{@as(f64, @floatFromInt(write_time)) / @as(f64, @floatFromInt(iterations))});
    std.log.info("  Read throughput: {d:.2} ns/op", .{@as(f64, @floatFromInt(read_time)) / @as(f64, @floatFromInt(iterations))});
}
