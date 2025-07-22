//! Atomic operations and synchronization primitives for Ferret

const std = @import("std");

/// Atomic counter with common operations
pub const AtomicCounter = struct {
    const Self = @This();

    value: std.atomic.Value(u64),

    pub fn init(initial_value: u64) Self {
        return Self{
            .value = std.atomic.Value(u64).init(initial_value),
        };
    }

    pub fn load(self: *const Self) u64 {
        return self.value.load(.monotonic);
    }

    pub fn store(self: *Self, new_value: u64) void {
        self.value.store(new_value, .monotonic);
    }

    pub fn increment(self: *Self) u64 {
        return self.value.fetchAdd(1, .monotonic) + 1;
    }

    pub fn decrement(self: *Self) u64 {
        return self.value.fetchSub(1, .monotonic) - 1;
    }

    pub fn add(self: *Self, delta: u64) u64 {
        return self.value.fetchAdd(delta, .monotonic) + delta;
    }

    pub fn sub(self: *Self, delta: u64) u64 {
        return self.value.fetchSub(delta, .monotonic) - delta;
    }

    pub fn compareAndSwap(self: *Self, expected: u64, new_value: u64) bool {
        return self.value.cmpxchgWeak(expected, new_value, .acq_rel, .monotonic) == null;
    }
};

/// Atomic flag for simple signaling
pub const AtomicFlag = struct {
    const Self = @This();

    value: std.atomic.Value(bool),

    pub fn init(initial_state: bool) Self {
        return Self{
            .value = std.atomic.Value(bool).init(initial_state),
        };
    }

    pub fn isSet(self: *const Self) bool {
        return self.value.load(.monotonic);
    }

    pub fn set(self: *Self) void {
        self.value.store(true, .release);
    }

    pub fn clear(self: *Self) void {
        self.value.store(false, .release);
    }

    pub fn testAndSet(self: *Self) bool {
        return self.value.swap(true, .acq_rel);
    }

    pub fn testAndClear(self: *Self) bool {
        return self.value.swap(false, .acq_rel);
    }
};

/// Simple lock-free queue implementation using atomic operations
/// This implementation prioritizes correctness over absolute performance
/// and uses a simplified approach to avoid common Michael & Scott pitfalls
pub fn LockFreeQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        const Node = struct {
            data: T,
            next: std.atomic.Value(?*Node),

            fn init(data: T) Node {
                return Node{
                    .data = data,
                    .next = std.atomic.Value(?*Node).init(null),
                };
            }
        };

        /// Optional deallocator function for memory management
        pub const ItemDeallocator = ?*const fn (allocator: std.mem.Allocator, item: T) void;

        head: std.atomic.Value(?*Node),
        tail: std.atomic.Value(?*Node),
        allocator: std.mem.Allocator,
        item_deallocator: ItemDeallocator,

        pub fn init(allocator: std.mem.Allocator) !Self {
            return Self{
                .head = std.atomic.Value(?*Node).init(null),
                .tail = std.atomic.Value(?*Node).init(null),
                .allocator = allocator,
                .item_deallocator = null,
            };
        }

        pub fn initWithDeallocator(allocator: std.mem.Allocator, item_deallocator: ItemDeallocator) !Self {
            return Self{
                .head = std.atomic.Value(?*Node).init(null),
                .tail = std.atomic.Value(?*Node).init(null),
                .allocator = allocator,
                .item_deallocator = item_deallocator,
            };
        }

        pub fn deinit(self: *Self) void {
            // Dequeue and deallocate all remaining items
            if (self.item_deallocator) |deallocator| {
                while (self.dequeue()) |item| {
                    deallocator(self.allocator, item);
                }
            } else {
                while (self.dequeue()) |_| {}
            }
        }

        pub fn enqueue(self: *Self, data: T) !void {
            const new_node = try self.allocator.create(Node);
            new_node.* = Node.init(data);

            // Simple approach: atomically update tail
            while (true) {
                const current_tail = self.tail.load(.acquire);

                if (current_tail == null) {
                    // Empty queue, try to set both head and tail
                    if (self.head.cmpxchgWeak(null, new_node, .acq_rel, .acquire) != null) {
                        continue; // Head was changed by another thread, retry
                    }
                    if (self.tail.cmpxchgWeak(null, new_node, .acq_rel, .acquire) != null) {
                        // Tail was changed, need to fix head
                        _ = self.head.cmpxchgWeak(new_node, null, .acq_rel, .acquire);
                        continue;
                    }
                    return; // Successfully added first item
                } else {
                    // Queue not empty, append to tail
                    if (current_tail.?.next.cmpxchgWeak(null, new_node, .acq_rel, .acquire) != null) {
                        // Another thread added to this node, help advance tail and retry
                        _ = self.tail.cmpxchgWeak(current_tail, current_tail.?.next.load(.acquire), .acq_rel, .acquire);
                        continue;
                    }
                    // Successfully linked, now update tail
                    _ = self.tail.cmpxchgWeak(current_tail, new_node, .acq_rel, .acquire);
                    return;
                }
            }
        }

        /// Remove and return the first item from the queue.
        /// Returns null if the queue is empty.
        ///
        /// IMPORTANT: If T is a dynamically allocated type (e.g., []u8, ArrayList, etc.),
        /// the caller is responsible for deallocating the returned item to prevent memory leaks.
        /// The queue only manages the storage nodes, not the item contents.
        pub fn dequeue(self: *Self) ?T {
            while (true) {
                const current_head = self.head.load(.acquire);

                if (current_head == null) {
                    return null; // Empty queue
                }

                const next = current_head.?.next.load(.acquire);

                // Try to advance head
                if (self.head.cmpxchgWeak(current_head, next, .acq_rel, .acquire) != null) {
                    continue; // Head was changed by another thread, retry
                }

                // If this was the last item, clear tail too
                if (next == null) {
                    _ = self.tail.cmpxchgWeak(current_head, null, .acq_rel, .acquire);
                }

                const data = current_head.?.data;
                self.allocator.destroy(current_head.?);
                return data;
            }
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.head.load(.acquire) == null;
        }

        /// Get approximate length of the queue
        /// Note: This is inherently racy in a lock-free environment and should
        /// only be used for monitoring/debugging purposes
        pub fn len(self: *const Self) usize {
            var count: usize = 0;
            var current = self.head.load(.acquire);

            while (current) |node| {
                count += 1;
                current = node.next.load(.acquire);

                // Prevent infinite loops if queue is being modified
                if (count > 1000000) break;
            }

            return count;
        }
    };
}

/// Simple spinlock implementation
pub const SpinLock = struct {
    const Self = @This();

    locked: std.atomic.Value(bool),

    pub fn init() Self {
        return Self{
            .locked = std.atomic.Value(bool).init(false),
        };
    }

    pub fn lock(self: *Self) void {
        while (self.locked.swap(true, .acquire)) {
            // Spin with pause instruction to be friendly to hyperthreading
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *Self) void {
        self.locked.store(false, .release);
    }

    pub fn tryLock(self: *Self) bool {
        return !self.locked.swap(true, .acquire);
    }
};

/// Read-write lock using atomic operations
pub const RwLock = struct {
    const Self = @This();
    const READER_MASK = 0x7FFFFFFF;
    const WRITER_BIT = 0x80000000;

    state: std.atomic.Value(u32),

    pub fn init() Self {
        return Self{
            .state = std.atomic.Value(u32).init(0),
        };
    }

    pub fn readLock(self: *Self) void {
        while (true) {
            const current = self.state.load(.acquire);
            if ((current & WRITER_BIT) == 0) {
                const new_state = current + 1;
                if (self.state.cmpxchgWeak(current, new_state, .acq_rel, .monotonic) == null) {
                    return;
                }
            }
            std.atomic.spinLoopHint();
        }
    }

    pub fn readUnlock(self: *Self) void {
        _ = self.state.fetchSub(1, .release);
    }

    pub fn writeLock(self: *Self) void {
        while (true) {
            const current = self.state.load(.acquire);
            if (current == 0) {
                if (self.state.cmpxchgWeak(0, WRITER_BIT, .acq_rel, .monotonic) == null) {
                    return;
                }
            }
            std.atomic.spinLoopHint();
        }
    }

    pub fn writeUnlock(self: *Self) void {
        self.state.store(0, .release);
    }

    pub fn tryReadLock(self: *Self) bool {
        const current = self.state.load(.acquire);
        if ((current & WRITER_BIT) == 0) {
            const new_state = current + 1;
            return self.state.cmpxchgWeak(current, new_state, .acq_rel, .monotonic) == null;
        }
        return false;
    }

    pub fn tryWriteLock(self: *Self) bool {
        return self.state.cmpxchgWeak(0, WRITER_BIT, .acq_rel, .monotonic) == null;
    }
};

test "AtomicCounter operations" {
    var counter = AtomicCounter.init(10);

    try std.testing.expectEqual(@as(u64, 10), counter.load());

    try std.testing.expectEqual(@as(u64, 11), counter.increment());
    try std.testing.expectEqual(@as(u64, 11), counter.load());

    try std.testing.expectEqual(@as(u64, 10), counter.decrement());
    try std.testing.expectEqual(@as(u64, 10), counter.load());

    try std.testing.expectEqual(@as(u64, 15), counter.add(5));
    try std.testing.expectEqual(@as(u64, 15), counter.load());

    try std.testing.expect(counter.compareAndSwap(15, 20));
    try std.testing.expectEqual(@as(u64, 20), counter.load());

    try std.testing.expect(!counter.compareAndSwap(15, 25));
    try std.testing.expectEqual(@as(u64, 20), counter.load());
}

test "AtomicFlag operations" {
    var flag = AtomicFlag.init(false);

    try std.testing.expect(!flag.isSet());

    flag.set();
    try std.testing.expect(flag.isSet());

    try std.testing.expect(flag.testAndClear());
    try std.testing.expect(!flag.isSet());

    try std.testing.expect(!flag.testAndSet());
    try std.testing.expect(flag.isSet());
}

test "LockFreeQueue basic operations" {
    const allocator = std.testing.allocator;

    var queue = try LockFreeQueue(i32).init(allocator);
    defer queue.deinit();

    try std.testing.expect(queue.isEmpty());
    try std.testing.expectEqual(@as(?i32, null), queue.dequeue());

    try queue.enqueue(1);
    try queue.enqueue(2);
    try queue.enqueue(3);

    try std.testing.expect(!queue.isEmpty());

    try std.testing.expectEqual(@as(?i32, 1), queue.dequeue());
    try std.testing.expectEqual(@as(?i32, 2), queue.dequeue());
    try std.testing.expectEqual(@as(?i32, 3), queue.dequeue());

    try std.testing.expect(queue.isEmpty());
    try std.testing.expectEqual(@as(?i32, null), queue.dequeue());
}

test "LockFreeQueue stress test" {
    const allocator = std.testing.allocator;
    var queue = try LockFreeQueue(usize).init(allocator);
    defer queue.deinit();

    const num_items = 10000;

    // Enqueue many items
    for (0..num_items) |i| {
        try queue.enqueue(i);
    }

    // Verify length is approximate (due to concurrent nature)
    const len = queue.len();
    try std.testing.expect(len <= num_items);

    // Dequeue all items in order
    for (0..num_items) |i| {
        const value = queue.dequeue();
        try std.testing.expect(value != null);
        try std.testing.expectEqual(@as(usize, i), value.?);
    }

    try std.testing.expect(queue.isEmpty());
    try std.testing.expectEqual(@as(?usize, null), queue.dequeue());
}

test "LockFreeQueue concurrent access simulation" {
    const allocator = std.testing.allocator;
    var queue = try LockFreeQueue(i32).init(allocator);
    defer queue.deinit();

    // Simulate concurrent access by interleaving operations
    try queue.enqueue(1);
    try queue.enqueue(2);

    const val1 = queue.dequeue();
    try std.testing.expectEqual(@as(?i32, 1), val1);

    try queue.enqueue(3);
    try queue.enqueue(4);

    const val2 = queue.dequeue();
    const val3 = queue.dequeue();
    const val4 = queue.dequeue();

    try std.testing.expectEqual(@as(?i32, 2), val2);
    try std.testing.expectEqual(@as(?i32, 3), val3);
    try std.testing.expectEqual(@as(?i32, 4), val4);

    try std.testing.expect(queue.isEmpty());
}

test "LockFreeQueue edge cases" {
    const allocator = std.testing.allocator;
    var queue = try LockFreeQueue(i32).init(allocator);
    defer queue.deinit();

    // Test single item
    try queue.enqueue(42);
    try std.testing.expect(!queue.isEmpty());
    try std.testing.expectEqual(@as(?i32, 42), queue.dequeue());
    try std.testing.expect(queue.isEmpty());

    // Test many enqueue/dequeue cycles
    for (0..100) |i| {
        try queue.enqueue(@intCast(i));
        const val = queue.dequeue();
        try std.testing.expectEqual(@as(?i32, @intCast(i)), val);
        try std.testing.expect(queue.isEmpty());
    }
}

test "SpinLock basic operations" {
    var lock = SpinLock.init();

    try std.testing.expect(lock.tryLock());
    try std.testing.expect(!lock.tryLock());

    lock.unlock();

    lock.lock();
    try std.testing.expect(!lock.tryLock());
    lock.unlock();
}

test "RwLock basic operations" {
    var rwlock = RwLock.init();

    rwlock.readLock();
    try std.testing.expect(rwlock.tryReadLock());
    try std.testing.expect(!rwlock.tryWriteLock());

    rwlock.readUnlock();
    rwlock.readUnlock();

    try std.testing.expect(rwlock.tryWriteLock());
    try std.testing.expect(!rwlock.tryReadLock());
    try std.testing.expect(!rwlock.tryWriteLock());

    rwlock.writeUnlock();
}
