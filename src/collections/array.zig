//! Dynamic array implementation for Ferret
//!
//! Provides a type-safe, generic dynamic array with automatic resizing
//! and memory management through explicit allocators.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Generic dynamic array implementation
pub fn Array(comptime T: type) type {
    return struct {
        const Self = @This();

        items: []T,
        capacity: usize,
        allocator: Allocator,

        /// Initialize an empty array with the given allocator
        pub fn init(allocator: Allocator) Self {
            return Self{
                .items = &[_]T{},
                .capacity = 0,
                .allocator = allocator,
            };
        }

        /// Initialize an array with a specific initial capacity
        pub fn initCapacity(allocator: Allocator, capacity: usize) !Self {
            if (capacity == 0) {
                return init(allocator);
            }

            const new_memory = try allocator.alloc(T, capacity);
            return Self{
                .items = new_memory[0..0],
                .capacity = capacity,
                .allocator = allocator,
            };
        }

        /// Initialize array from existing slice (takes ownership)
        pub fn fromSlice(allocator: Allocator, items: []T) Self {
            return Self{
                .items = items,
                .capacity = items.len,
                .allocator = allocator,
            };
        }

        /// Free all allocated memory
        pub fn deinit(self: *Self) void {
            if (self.capacity > 0) {
                self.allocator.free(self.items.ptr[0..self.capacity]);
            }
        }

        /// Get current length of the array
        pub fn len(self: Self) usize {
            return self.items.len;
        }

        /// Get current capacity of the array
        pub fn cap(self: Self) usize {
            return self.capacity;
        }

        /// Check if array is empty
        pub fn isEmpty(self: Self) bool {
            return self.items.len == 0;
        }

        /// Get element at index (bounds checked)
        pub fn get(self: Self, index: usize) ?T {
            if (index >= self.items.len) {
                return null;
            }
            return self.items[index];
        }

        /// Get element at index (unchecked access)
        pub fn at(self: Self, index: usize) T {
            return self.items[index];
        }

        /// Get mutable pointer to element at index
        pub fn getPtr(self: *Self, index: usize) ?*T {
            if (index >= self.items.len) {
                return null;
            }
            return &self.items[index];
        }

        /// Set element at index
        pub fn set(self: *Self, index: usize, item: T) !void {
            if (index >= self.items.len) {
                return error.IndexOutOfBounds;
            }
            self.items[index] = item;
        }

        /// Get first element
        pub fn first(self: Self) ?T {
            if (self.items.len == 0) {
                return null;
            }
            return self.items[0];
        }

        /// Get last element
        pub fn last(self: Self) ?T {
            if (self.items.len == 0) {
                return null;
            }
            return self.items[self.items.len - 1];
        }

        /// Ensure capacity for at least `new_capacity` elements
        pub fn ensureCapacity(self: *Self, new_capacity: usize) !void {
            if (new_capacity <= self.capacity) {
                return;
            }

            const better_capacity = growCapacity(self.capacity, new_capacity);
            return self.ensureTotalCapacity(better_capacity);
        }

        /// Ensure exact capacity
        pub fn ensureTotalCapacity(self: *Self, new_capacity: usize) !void {
            if (new_capacity <= self.capacity) {
                return;
            }

            const old_memory = self.items.ptr[0..self.capacity];

            if (self.allocator.resize(old_memory, new_capacity)) {
                self.capacity = new_capacity;
            } else {
                const new_memory = try self.allocator.alloc(T, new_capacity);
                @memcpy(new_memory[0..self.items.len], self.items);

                if (self.capacity > 0) {
                    self.allocator.free(old_memory);
                }

                self.items.ptr = new_memory.ptr;
                self.capacity = new_capacity;
            }
        }

        /// Add element to end of array
        pub fn append(self: *Self, item: T) !void {
            try self.ensureCapacity(self.items.len + 1);
            self.items.ptr[self.items.len] = item;
            self.items.len += 1;
        }

        /// Add multiple elements to end of array
        pub fn appendSlice(self: *Self, items: []const T) !void {
            try self.ensureCapacity(self.items.len + items.len);
            @memcpy(self.items.ptr[self.items.len .. self.items.len + items.len], items);
            self.items.len += items.len;
        }

        /// Insert element at index, shifting existing elements right
        pub fn insert(self: *Self, index: usize, item: T) !void {
            if (index > self.items.len) {
                return error.IndexOutOfBounds;
            }

            try self.ensureCapacity(self.items.len + 1);

            // Shift elements to the right
            if (index < self.items.len) {
                std.mem.copyBackwards(T, self.items.ptr[index + 1 .. self.items.len + 1], self.items[index..self.items.len]);
            }

            self.items.ptr[index] = item;
            self.items.len += 1;
        }

        /// Remove and return element at index, shifting remaining elements left
        pub fn remove(self: *Self, index: usize) !T {
            if (index >= self.items.len) {
                return error.IndexOutOfBounds;
            }

            const item = self.items[index];

            // Shift elements to the left
            if (index < self.items.len - 1) {
                std.mem.copyForwards(T, self.items[index .. self.items.len - 1], self.items[index + 1 .. self.items.len]);
            }

            self.items.len -= 1;
            return item;
        }

        /// Remove and return last element
        pub fn pop(self: *Self) ?T {
            if (self.items.len == 0) {
                return null;
            }

            const item = self.items[self.items.len - 1];
            self.items.len -= 1;
            return item;
        }

        /// Remove last element without returning it
        pub fn popOrNull(self: *Self) void {
            if (self.items.len > 0) {
                self.items.len -= 1;
            }
        }

        /// Swap elements at two indices
        pub fn swap(self: *Self, a: usize, b: usize) !void {
            if (a >= self.items.len or b >= self.items.len) {
                return error.IndexOutOfBounds;
            }

            const temp = self.items[a];
            self.items[a] = self.items[b];
            self.items[b] = temp;
        }

        /// Reverse the array in-place
        pub fn reverse(self: *Self) void {
            std.mem.reverse(T, self.items);
        }

        /// Sort the array using the provided comparison function
        pub fn sort(self: *Self, comptime lessThan: fn (T, T) bool) void {
            std.mem.sort(T, self.items, {}, struct {
                fn inner(context: void, a: T, b: T) bool {
                    _ = context;
                    return lessThan(a, b);
                }
            }.inner);
        }

        /// Find first occurrence of item, returns index or null
        pub fn find(self: Self, item: T) ?usize {
            for (self.items, 0..) |elem, i| {
                if (std.meta.eql(elem, item)) {
                    return i;
                }
            }
            return null;
        }

        /// Check if array contains item
        pub fn contains(self: Self, item: T) bool {
            return self.find(item) != null;
        }

        /// Clear all elements but keep capacity
        pub fn clear(self: *Self) void {
            self.items.len = 0;
        }

        /// Resize array to new length, filling with default value if growing
        pub fn resize(self: *Self, new_len: usize, fill_item: T) !void {
            if (new_len > self.items.len) {
                try self.ensureCapacity(new_len);
                for (self.items.len..new_len) |i| {
                    self.items.ptr[i] = fill_item;
                }
            }
            self.items.len = new_len;
        }

        /// Get slice view of the array
        pub fn slice(self: Self) []T {
            return self.items;
        }

        /// Get const slice view of the array
        pub fn constSlice(self: Self) []const T {
            return self.items;
        }

        /// Clone the array with a new allocator
        pub fn clone(self: Self, allocator: Allocator) !Self {
            var result = try Self.initCapacity(allocator, self.items.len);
            try result.appendSlice(self.items);
            return result;
        }

        /// Create array from existing slice by copying
        pub fn fromSliceCopy(allocator: Allocator, items: []const T) !Self {
            var result = try Self.initCapacity(allocator, items.len);
            try result.appendSlice(items);
            return result;
        }
    };
}

/// Calculate a better capacity for growing arrays
fn growCapacity(current: usize, minimum: usize) usize {
    var new_capacity = current;
    while (true) {
        new_capacity +|= new_capacity / 2 + 8;
        if (new_capacity >= minimum) {
            return new_capacity;
        }
    }
}

test "Array basic operations" {
    const allocator = std.testing.allocator;

    var arr = Array(i32).init(allocator);
    defer arr.deinit();

    try std.testing.expect(arr.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), arr.len());

    try arr.append(1);
    try arr.append(2);
    try arr.append(3);

    try std.testing.expectEqual(@as(usize, 3), arr.len());
    try std.testing.expect(!arr.isEmpty());

    try std.testing.expectEqual(@as(?i32, 1), arr.get(0));
    try std.testing.expectEqual(@as(?i32, 2), arr.get(1));
    try std.testing.expectEqual(@as(?i32, 3), arr.get(2));
    try std.testing.expectEqual(@as(?i32, null), arr.get(3));

    try std.testing.expectEqual(@as(?i32, 1), arr.first());
    try std.testing.expectEqual(@as(?i32, 3), arr.last());
}

test "Array insertion and removal" {
    const allocator = std.testing.allocator;

    var arr = Array(i32).init(allocator);
    defer arr.deinit();

    try arr.append(1);
    try arr.append(3);
    try arr.insert(1, 2);

    try std.testing.expectEqual(@as(i32, 1), arr.at(0));
    try std.testing.expectEqual(@as(i32, 2), arr.at(1));
    try std.testing.expectEqual(@as(i32, 3), arr.at(2));

    const removed = try arr.remove(1);
    try std.testing.expectEqual(@as(i32, 2), removed);
    try std.testing.expectEqual(@as(usize, 2), arr.len());

    const popped = arr.pop();
    try std.testing.expectEqual(@as(?i32, 3), popped);
    try std.testing.expectEqual(@as(usize, 1), arr.len());
}

test "Array slice operations" {
    const allocator = std.testing.allocator;

    const data = [_]i32{ 1, 2, 3, 4, 5 };
    var arr = try Array(i32).fromSliceCopy(allocator, &data);
    defer arr.deinit();

    try std.testing.expectEqual(@as(usize, 5), arr.len());

    const slice = arr.slice();
    try std.testing.expectEqual(@as(i32, 1), slice[0]);
    try std.testing.expectEqual(@as(i32, 5), slice[4]);

    try arr.appendSlice(&[_]i32{ 6, 7 });
    try std.testing.expectEqual(@as(usize, 7), arr.len());
}

test "Array search and modification" {
    const allocator = std.testing.allocator;

    var arr = Array(i32).init(allocator);
    defer arr.deinit();

    try arr.appendSlice(&[_]i32{ 3, 1, 4, 1, 5 });

    try std.testing.expectEqual(@as(?usize, 1), arr.find(1));
    try std.testing.expect(arr.contains(4));
    try std.testing.expect(!arr.contains(2));

    arr.reverse();
    try std.testing.expectEqual(@as(i32, 5), arr.at(0));
    try std.testing.expectEqual(@as(i32, 3), arr.at(4));

    arr.sort(struct {
        fn lessThan(a: i32, b: i32) bool {
            return a < b;
        }
    }.lessThan);

    try std.testing.expectEqual(@as(i32, 1), arr.at(0));
    try std.testing.expectEqual(@as(i32, 5), arr.at(4));
}

test "Array capacity management" {
    const allocator = std.testing.allocator;

    var arr = try Array(i32).initCapacity(allocator, 10);
    defer arr.deinit();

    try std.testing.expectEqual(@as(usize, 10), arr.cap());
    try std.testing.expectEqual(@as(usize, 0), arr.len());

    try arr.ensureCapacity(20);
    try std.testing.expect(arr.cap() >= 20);

    try arr.resize(5, 42);
    try std.testing.expectEqual(@as(usize, 5), arr.len());
    try std.testing.expectEqual(@as(i32, 42), arr.at(0));
}
