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

/// Simple atomic queue using a spinlock
/// Note: This uses a spinlock for simplicity, not truly lock-free
pub fn LockFreeQueue(comptime T: type) type {
    return struct {
        const Self = @This();
        const Node = struct {
            data: T,
            next: ?*Node,
        };

        head: ?*Node,
        tail: ?*Node,
        allocator: std.mem.Allocator,
        lock: SpinLock,

        pub fn init(allocator: std.mem.Allocator) Self {
            return Self{
                .head = null,
                .tail = null,
                .allocator = allocator,
                .lock = SpinLock.init(),
            };
        }

        pub fn deinit(self: *Self) void {
            while (self.dequeue()) |_| {}
        }

        pub fn enqueue(self: *Self, data: T) !void {
            const new_node = try self.allocator.create(Node);
            new_node.* = Node{
                .data = data,
                .next = null,
            };

            self.lock.lock();
            defer self.lock.unlock();

            if (self.tail) |tail| {
                tail.next = new_node;
                self.tail = new_node;
            } else {
                self.head = new_node;
                self.tail = new_node;
            }
        }

        pub fn dequeue(self: *Self) ?T {
            self.lock.lock();
            defer self.lock.unlock();

            const head = self.head orelse return null;
            const data = head.data;

            self.head = head.next;
            if (self.head == null) {
                self.tail = null;
            }

            self.allocator.destroy(head);
            return data;
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.head == null;
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

    var queue = LockFreeQueue(i32).init(allocator);
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
