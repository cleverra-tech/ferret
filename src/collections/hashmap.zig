//! High-performance hash map implementation for Ferret
//!
//! Provides a generic hash map with customizable hashing and equality functions.
//! Uses robin hood hashing for excellent performance characteristics.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Generic hash map implementation using robin hood hashing
pub fn HashMap(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        pub const Entry = struct {
            key: K,
            value: V,
            distance: u32, // Distance from ideal position (for robin hood)
        };

        const EMPTY_DISTANCE = std.math.maxInt(u32);

        entries: []?Entry,
        count: usize,
        allocator: Allocator,
        max_load_factor: f32,

        /// Initialize empty hash map
        pub fn init(allocator: Allocator) Self {
            return Self{
                .entries = &[_]?Entry{},
                .count = 0,
                .allocator = allocator,
                .max_load_factor = 0.75,
            };
        }

        /// Initialize hash map with specific capacity
        pub fn initCapacity(allocator: Allocator, initial_capacity: usize) !Self {
            if (initial_capacity == 0) {
                return init(allocator);
            }

            const actual_capacity = nextPowerOfTwo(initial_capacity);
            const entries = try allocator.alloc(?Entry, actual_capacity);
            @memset(entries, null);

            return Self{
                .entries = entries,
                .count = 0,
                .allocator = allocator,
                .max_load_factor = 0.75,
            };
        }

        /// Free all allocated memory
        pub fn deinit(self: *Self) void {
            if (self.entries.len > 0) {
                self.allocator.free(self.entries);
            }
        }

        /// Get current number of entries
        pub fn len(self: Self) usize {
            return self.count;
        }

        /// Get current capacity
        pub fn capacity(self: Self) usize {
            return self.entries.len;
        }

        /// Check if map is empty
        pub fn isEmpty(self: Self) bool {
            return self.count == 0;
        }

        /// Set the maximum load factor (0.1 to 0.9)
        pub fn setMaxLoadFactor(self: *Self, factor: f32) void {
            self.max_load_factor = std.math.clamp(factor, 0.1, 0.9);
        }

        /// Check if we need to resize
        fn needsResize(self: Self) bool {
            if (self.entries.len == 0) return true;
            const load_factor = @as(f32, @floatFromInt(self.count)) / @as(f32, @floatFromInt(self.entries.len));
            return load_factor > self.max_load_factor;
        }

        /// Resize the hash map
        fn resize(self: *Self, new_capacity: usize) !void {
            const old_entries = self.entries;
            const actual_capacity = nextPowerOfTwo(new_capacity);

            self.entries = try self.allocator.alloc(?Entry, actual_capacity);
            @memset(self.entries, null);
            self.count = 0;

            // Rehash all existing entries
            for (old_entries) |maybe_entry| {
                if (maybe_entry) |entry| {
                    try self.putInternal(entry.key, entry.value);
                }
            }

            if (old_entries.len > 0) {
                self.allocator.free(old_entries);
            }
        }

        /// Hash function for keys
        fn hash(key: K) u64 {
            const type_info = @typeInfo(K);
            switch (type_info) {
                .int, .float, .bool, .@"enum" => {
                    // For simple types, hash the bytes directly
                    const bytes = std.mem.asBytes(&key);
                    return std.hash.Wyhash.hash(0, bytes);
                },
                .pointer => |ptr_info| {
                    if (ptr_info.size == .slice and ptr_info.child == u8) {
                        // String slices
                        return std.hash.Wyhash.hash(0, key);
                    } else {
                        // Hash pointer value
                        return std.hash.Wyhash.hash(0, std.mem.asBytes(&key));
                    }
                },
                else => {
                    // For complex types, hash the bytes
                    const bytes = std.mem.asBytes(&key);
                    return std.hash.Wyhash.hash(0, bytes);
                },
            }
        }

        /// Equality function for keys
        fn eql(a: K, b: K) bool {
            return std.meta.eql(a, b);
        }

        /// Find slot for key (returns index and whether key exists)
        fn findSlot(self: Self, key: K) struct { index: usize, exists: bool } {
            if (self.entries.len == 0) {
                return .{ .index = 0, .exists = false };
            }

            const key_hash = hash(key);
            const mask = self.entries.len - 1;
            var index = key_hash & mask;
            var distance: u32 = 0;

            while (self.entries[index]) |entry| {
                if (eql(entry.key, key)) {
                    return .{ .index = index, .exists = true };
                }

                if (distance > entry.distance) {
                    // We've gone further than this entry's ideal position,
                    // so the key doesn't exist
                    return .{ .index = index, .exists = false };
                }

                index = (index + 1) & mask;
                distance += 1;
            }

            return .{ .index = index, .exists = false };
        }

        /// Internal put implementation (assumes capacity is sufficient)
        fn putInternal(self: *Self, key: K, value: V) !void {
            const key_hash = hash(key);
            const mask = self.entries.len - 1;
            var index = key_hash & mask;
            var distance: u32 = 0;

            var new_entry = Entry{
                .key = key,
                .value = value,
                .distance = distance,
            };

            while (true) {
                if (self.entries[index] == null) {
                    // Found empty slot
                    self.entries[index] = new_entry;
                    self.count += 1;
                    return;
                }

                var existing = &self.entries[index].?;

                if (eql(existing.key, key)) {
                    // Update existing entry
                    existing.value = value;
                    return;
                }

                // Robin Hood: if new entry has traveled further, swap
                if (distance > existing.distance) {
                    std.mem.swap(Entry, &new_entry, existing);
                }

                index = (index + 1) & mask;
                new_entry.distance += 1;
                distance += 1;
            }
        }

        /// Insert or update key-value pair
        pub fn put(self: *Self, key: K, value: V) !void {
            if (self.needsResize()) {
                const new_capacity = if (self.entries.len == 0) 16 else self.entries.len * 2;
                try self.resize(new_capacity);
            }

            return self.putInternal(key, value);
        }

        /// Get value by key
        pub fn get(self: Self, key: K) ?V {
            const result = self.findSlot(key);
            if (result.exists) {
                return self.entries[result.index].?.value;
            }
            return null;
        }

        /// Get mutable pointer to value by key
        pub fn getPtr(self: *Self, key: K) ?*V {
            const result = self.findSlot(key);
            if (result.exists) {
                return &self.entries[result.index].?.value;
            }
            return null;
        }

        /// Check if key exists
        pub fn contains(self: Self, key: K) bool {
            return self.findSlot(key).exists;
        }

        /// Remove entry by key, returns whether key existed
        pub fn remove(self: *Self, key: K) bool {
            const result = self.findSlot(key);
            if (!result.exists) {
                return false;
            }

            var index = result.index;
            const mask = self.entries.len - 1;

            // Mark as deleted
            self.entries[index] = null;
            self.count -= 1;

            // Shift following entries back to fill the gap
            var next_index = (index + 1) & mask;
            while (self.entries[next_index]) |*entry| {
                if (entry.distance == 0) {
                    // This entry is in its ideal position, stop shifting
                    break;
                }

                // Move this entry back one slot
                entry.distance -= 1;
                self.entries[index] = self.entries[next_index];
                self.entries[next_index] = null;

                index = next_index;
                next_index = (next_index + 1) & mask;
            }

            return true;
        }

        /// Clear all entries
        pub fn clear(self: *Self) void {
            @memset(self.entries, null);
            self.count = 0;
        }

        /// Clone the hash map with a new allocator
        pub fn clone(self: Self, allocator: Allocator) !Self {
            var result = try Self.initCapacity(allocator, self.count);

            for (self.entries) |maybe_entry| {
                if (maybe_entry) |entry| {
                    try result.put(entry.key, entry.value);
                }
            }

            return result;
        }

        /// Iterator for entries
        pub const Iterator = struct {
            entries: []?Entry,
            index: usize,

            pub fn next(self: *Iterator) ?Entry {
                while (self.index < self.entries.len) {
                    const maybe_entry = self.entries[self.index];
                    self.index += 1;
                    if (maybe_entry) |entry| {
                        return entry;
                    }
                }
                return null;
            }
        };

        /// Get iterator over all entries
        pub fn iterator(self: *const Self) Iterator {
            return Iterator{
                .entries = self.entries,
                .index = 0,
            };
        }

        /// Key iterator
        pub const KeyIterator = struct {
            inner: Iterator,

            pub fn next(self: *KeyIterator) ?K {
                if (self.inner.next()) |entry| {
                    return entry.key;
                }
                return null;
            }
        };

        /// Get iterator over all keys
        pub fn keyIterator(self: *const Self) KeyIterator {
            return KeyIterator{
                .inner = self.iterator(),
            };
        }

        /// Value iterator
        pub const ValueIterator = struct {
            inner: Iterator,

            pub fn next(self: *ValueIterator) ?V {
                if (self.inner.next()) |entry| {
                    return entry.value;
                }
                return null;
            }
        };

        /// Get iterator over all values
        pub fn valueIterator(self: *const Self) ValueIterator {
            return ValueIterator{
                .inner = self.iterator(),
            };
        }
    };
}

/// Find next power of two greater than or equal to n
fn nextPowerOfTwo(n: usize) usize {
    if (n == 0) return 1;
    return std.math.ceilPowerOfTwo(usize, n) catch std.math.maxInt(usize);
}

test "HashMap basic operations" {
    const allocator = std.testing.allocator;

    var map = HashMap([]const u8, i32).init(allocator);
    defer map.deinit();

    try std.testing.expect(map.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), map.len());

    try map.put("hello", 1);
    try map.put("world", 2);
    try map.put("test", 3);

    try std.testing.expectEqual(@as(usize, 3), map.len());
    try std.testing.expect(!map.isEmpty());

    try std.testing.expectEqual(@as(?i32, 1), map.get("hello"));
    try std.testing.expectEqual(@as(?i32, 2), map.get("world"));
    try std.testing.expectEqual(@as(?i32, 3), map.get("test"));
    try std.testing.expectEqual(@as(?i32, null), map.get("missing"));

    try std.testing.expect(map.contains("hello"));
    try std.testing.expect(!map.contains("missing"));
}

test "HashMap update and removal" {
    const allocator = std.testing.allocator;

    var map = HashMap(i32, []const u8).init(allocator);
    defer map.deinit();

    try map.put(1, "one");
    try map.put(2, "two");

    // Update existing key
    try map.put(1, "ONE");
    try std.testing.expectEqualStrings("ONE", map.get(1).?);
    try std.testing.expectEqual(@as(usize, 2), map.len());

    // Remove key
    try std.testing.expect(map.remove(1));
    try std.testing.expect(!map.remove(1)); // Already removed
    try std.testing.expectEqual(@as(usize, 1), map.len());
    try std.testing.expectEqual(@as(?[]const u8, null), map.get(1));
}

test "HashMap iterators" {
    const allocator = std.testing.allocator;

    var map = HashMap(i32, i32).init(allocator);
    defer map.deinit();

    try map.put(1, 10);
    try map.put(2, 20);
    try map.put(3, 30);

    var sum_keys: i32 = 0;
    var sum_values: i32 = 0;

    var key_iter = map.keyIterator();
    while (key_iter.next()) |key| {
        sum_keys += key;
    }

    var value_iter = map.valueIterator();
    while (value_iter.next()) |value| {
        sum_values += value;
    }

    try std.testing.expectEqual(@as(i32, 6), sum_keys); // 1 + 2 + 3
    try std.testing.expectEqual(@as(i32, 60), sum_values); // 10 + 20 + 30

    var entry_count: usize = 0;
    var iter = map.iterator();
    while (iter.next()) |entry| {
        entry_count += 1;
        try std.testing.expect(entry.value == entry.key * 10);
    }

    try std.testing.expectEqual(@as(usize, 3), entry_count);
}

test "HashMap capacity and resizing" {
    const allocator = std.testing.allocator;

    var map = try HashMap(i32, i32).initCapacity(allocator, 4);
    defer map.deinit();

    try std.testing.expect(map.capacity() >= 4);

    // Add many items to trigger resize
    for (0..100) |i| {
        try map.put(@intCast(i), @intCast(i * 2));
    }

    try std.testing.expectEqual(@as(usize, 100), map.len());

    // Verify all items are still there
    for (0..100) |i| {
        const expected: i32 = @intCast(i * 2);
        try std.testing.expectEqual(@as(?i32, expected), map.get(@intCast(i)));
    }
}

test "HashMap clone" {
    const allocator = std.testing.allocator;

    var original = HashMap(i32, []const u8).init(allocator);
    defer original.deinit();

    try original.put(1, "one");
    try original.put(2, "two");

    var cloned = try original.clone(allocator);
    defer cloned.deinit();

    try std.testing.expectEqual(@as(usize, 2), cloned.len());
    try std.testing.expectEqualStrings("one", cloned.get(1).?);
    try std.testing.expectEqualStrings("two", cloned.get(2).?);

    // Modify original, clone should be unaffected
    try original.put(3, "three");
    try std.testing.expectEqual(@as(usize, 3), original.len());
    try std.testing.expectEqual(@as(usize, 2), cloned.len());
}
