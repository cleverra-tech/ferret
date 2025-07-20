//! High-performance Queue implementations for Ferret
//!
//! This module provides multiple queue implementations optimized for different use cases:
//! - ArrayQueue: Ring buffer-based queue with fixed capacity for high performance
//! - LinkedQueue: Dynamic linked-list queue with unlimited capacity
//! - Queue: Type alias for the recommended general-purpose implementation
//!
//! All implementations are generic over the element type and provide consistent APIs.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// Errors that can occur during queue operations
pub const QueueError = error{
    /// Queue has reached its maximum capacity (ArrayQueue only)
    QueueFull,
    /// Attempted to allocate memory but allocation failed
    OutOfMemory,
    /// Invalid capacity provided (e.g., zero capacity)
    InvalidCapacity,
};

/// Ring buffer-based queue with fixed capacity
/// Optimized for high performance with O(1) operations and minimal allocations
pub fn ArrayQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        items: []T,
        head: usize,
        tail: usize,
        count: usize,
        capacity: usize,
        allocator: Allocator,

        /// Initialize a new ArrayQueue with the specified capacity
        pub fn init(allocator: Allocator, capacity: usize) QueueError!Self {
            if (capacity == 0) return QueueError.InvalidCapacity;

            const items = allocator.alloc(T, capacity) catch return QueueError.OutOfMemory;
            return Self{
                .items = items,
                .head = 0,
                .tail = 0,
                .count = 0,
                .capacity = capacity,
                .allocator = allocator,
            };
        }

        /// Deinitialize the queue and free all memory
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.items);
            self.* = undefined;
        }

        /// Add an item to the back of the queue
        /// Returns QueueError.QueueFull if the queue is at capacity
        pub fn enqueue(self: *Self, item: T) QueueError!void {
            if (self.count >= self.capacity) {
                return QueueError.QueueFull;
            }

            self.items[self.tail] = item;
            self.tail = (self.tail + 1) % self.capacity;
            self.count += 1;
        }

        /// Remove and return an item from the front of the queue
        /// Returns null if the queue is empty
        pub fn dequeue(self: *Self) ?T {
            if (self.count == 0) {
                return null;
            }

            const item = self.items[self.head];
            self.head = (self.head + 1) % self.capacity;
            self.count -= 1;
            return item;
        }

        /// Peek at the front item without removing it
        /// Returns null if the queue is empty
        pub fn peek(self: *const Self) ?T {
            if (self.count == 0) {
                return null;
            }
            return self.items[self.head];
        }

        /// Peek at the back item without removing it
        /// Returns null if the queue is empty
        pub fn peekLast(self: *const Self) ?T {
            if (self.count == 0) {
                return null;
            }
            const last_index = if (self.tail == 0) self.capacity - 1 else self.tail - 1;
            return self.items[last_index];
        }

        /// Check if the queue is empty
        pub fn isEmpty(self: *const Self) bool {
            return self.count == 0;
        }

        /// Check if the queue is full
        pub fn isFull(self: *const Self) bool {
            return self.count >= self.capacity;
        }

        /// Get the current number of items in the queue
        pub fn len(self: *const Self) usize {
            return self.count;
        }

        /// Clear all items from the queue
        pub fn clear(self: *Self) void {
            self.head = 0;
            self.tail = 0;
            self.count = 0;
        }

        /// Get an iterator over the queue items (from front to back)
        pub fn iterator(self: *const Self) Iterator {
            return Iterator{
                .queue = self,
                .index = 0,
            };
        }

        pub const Iterator = struct {
            queue: *const Self,
            index: usize,

            pub fn next(self: *Iterator) ?T {
                if (self.index >= self.queue.count) {
                    return null;
                }
                const actual_index = (self.queue.head + self.index) % self.queue.capacity;
                const item = self.queue.items[actual_index];
                self.index += 1;
                return item;
            }
        };
    };
}

/// Dynamic linked-list queue with unlimited capacity
/// Provides flexible memory usage with O(1) operations
pub fn LinkedQueue(comptime T: type) type {
    return struct {
        const Self = @This();
        const Node = struct {
            data: T,
            next: ?*Node,
        };

        head: ?*Node,
        tail: ?*Node,
        count: usize,
        allocator: Allocator,

        /// Initialize a new LinkedQueue
        pub fn init(allocator: Allocator) Self {
            return Self{
                .head = null,
                .tail = null,
                .count = 0,
                .allocator = allocator,
            };
        }

        /// Deinitialize the queue and free all nodes
        pub fn deinit(self: *Self) void {
            while (self.dequeue()) |_| {}
            self.* = undefined;
        }

        /// Add an item to the back of the queue
        pub fn enqueue(self: *Self, data: T) QueueError!void {
            const new_node = self.allocator.create(Node) catch return QueueError.OutOfMemory;
            new_node.* = Node{
                .data = data,
                .next = null,
            };

            if (self.tail) |tail| {
                tail.next = new_node;
                self.tail = new_node;
            } else {
                self.head = new_node;
                self.tail = new_node;
            }
            self.count += 1;
        }

        /// Remove and return an item from the front of the queue
        /// Returns null if the queue is empty
        pub fn dequeue(self: *Self) ?T {
            const head = self.head orelse return null;
            const data = head.data;

            self.head = head.next;
            if (self.head == null) {
                self.tail = null;
            }
            self.count -= 1;

            self.allocator.destroy(head);
            return data;
        }

        /// Peek at the front item without removing it
        /// Returns null if the queue is empty
        pub fn peek(self: *const Self) ?T {
            const head = self.head orelse return null;
            return head.data;
        }

        /// Peek at the back item without removing it
        /// Returns null if the queue is empty
        pub fn peekLast(self: *const Self) ?T {
            const tail = self.tail orelse return null;
            return tail.data;
        }

        /// Check if the queue is empty
        pub fn isEmpty(self: *const Self) bool {
            return self.head == null;
        }

        /// Get the current number of items in the queue
        pub fn len(self: *const Self) usize {
            return self.count;
        }

        /// Clear all items from the queue
        pub fn clear(self: *Self) void {
            while (self.dequeue()) |_| {}
        }

        /// Get an iterator over the queue items (from front to back)
        pub fn iterator(self: *const Self) Iterator {
            return Iterator{
                .current = self.head,
            };
        }

        pub const Iterator = struct {
            current: ?*Node,

            pub fn next(self: *Iterator) ?T {
                const current = self.current orelse return null;
                self.current = current.next;
                return current.data;
            }
        };
    };
}

/// General-purpose queue type (defaults to LinkedQueue for flexibility)
/// For high-performance scenarios with known capacity, use ArrayQueue directly
pub fn Queue(comptime T: type) type {
    return LinkedQueue(T);
}

// Tests
test "ArrayQueue basic operations" {
    var queue = try ArrayQueue(i32).init(testing.allocator, 4);
    defer queue.deinit();

    // Test empty queue
    try testing.expect(queue.isEmpty());
    try testing.expect(!queue.isFull());
    try testing.expect(queue.len() == 0);
    try testing.expect(queue.peek() == null);
    try testing.expect(queue.dequeue() == null);

    // Test enqueue
    try queue.enqueue(1);
    try queue.enqueue(2);
    try queue.enqueue(3);

    try testing.expect(!queue.isEmpty());
    try testing.expect(!queue.isFull());
    try testing.expect(queue.len() == 3);
    try testing.expect(queue.peek() == 1);
    try testing.expect(queue.peekLast() == 3);

    // Test full queue
    try queue.enqueue(4);
    try testing.expect(queue.isFull());
    try testing.expectError(QueueError.QueueFull, queue.enqueue(5));

    // Test dequeue
    try testing.expect(queue.dequeue() == 1);
    try testing.expect(queue.dequeue() == 2);
    try testing.expect(queue.len() == 2);
    try testing.expect(queue.peek() == 3);

    // Test wrap-around
    try queue.enqueue(5);
    try queue.enqueue(6);
    try testing.expect(queue.isFull());

    try testing.expect(queue.dequeue() == 3);
    try testing.expect(queue.dequeue() == 4);
    try testing.expect(queue.dequeue() == 5);
    try testing.expect(queue.dequeue() == 6);
    try testing.expect(queue.isEmpty());
}

test "ArrayQueue iterator" {
    var queue = try ArrayQueue(i32).init(testing.allocator, 4);
    defer queue.deinit();

    try queue.enqueue(10);
    try queue.enqueue(20);
    try queue.enqueue(30);

    var iter = queue.iterator();
    try testing.expect(iter.next() == 10);
    try testing.expect(iter.next() == 20);
    try testing.expect(iter.next() == 30);
    try testing.expect(iter.next() == null);
}

test "LinkedQueue basic operations" {
    var queue = LinkedQueue(i32).init(testing.allocator);
    defer queue.deinit();

    // Test empty queue
    try testing.expect(queue.isEmpty());
    try testing.expect(queue.len() == 0);
    try testing.expect(queue.peek() == null);
    try testing.expect(queue.dequeue() == null);

    // Test enqueue and dequeue
    try queue.enqueue(1);
    try queue.enqueue(2);
    try queue.enqueue(3);

    try testing.expect(!queue.isEmpty());
    try testing.expect(queue.len() == 3);
    try testing.expect(queue.peek() == 1);
    try testing.expect(queue.peekLast() == 3);

    try testing.expect(queue.dequeue() == 1);
    try testing.expect(queue.dequeue() == 2);
    try testing.expect(queue.len() == 1);
    try testing.expect(queue.peek() == 3);

    try testing.expect(queue.dequeue() == 3);
    try testing.expect(queue.isEmpty());
    try testing.expect(queue.dequeue() == null);
}

test "LinkedQueue iterator" {
    var queue = LinkedQueue(i32).init(testing.allocator);
    defer queue.deinit();

    try queue.enqueue(100);
    try queue.enqueue(200);
    try queue.enqueue(300);

    var iter = queue.iterator();
    try testing.expect(iter.next() == 100);
    try testing.expect(iter.next() == 200);
    try testing.expect(iter.next() == 300);
    try testing.expect(iter.next() == null);
}

test "Queue clear operations" {
    var array_queue = try ArrayQueue(i32).init(testing.allocator, 4);
    defer array_queue.deinit();

    var linked_queue = LinkedQueue(i32).init(testing.allocator);
    defer linked_queue.deinit();

    // Test ArrayQueue clear
    try array_queue.enqueue(1);
    try array_queue.enqueue(2);
    array_queue.clear();
    try testing.expect(array_queue.isEmpty());
    try testing.expect(array_queue.len() == 0);

    // Test LinkedQueue clear
    try linked_queue.enqueue(1);
    try linked_queue.enqueue(2);
    linked_queue.clear();
    try testing.expect(linked_queue.isEmpty());
    try testing.expect(linked_queue.len() == 0);
}

test "Queue with different types" {
    // Test with strings
    var str_queue = LinkedQueue([]const u8).init(testing.allocator);
    defer str_queue.deinit();

    try str_queue.enqueue("hello");
    try str_queue.enqueue("world");

    try testing.expectEqualStrings("hello", str_queue.dequeue().?);
    try testing.expectEqualStrings("world", str_queue.dequeue().?);

    // Test with structs
    const Point = struct { x: i32, y: i32 };
    var point_queue = try ArrayQueue(Point).init(testing.allocator, 2);
    defer point_queue.deinit();

    try point_queue.enqueue(Point{ .x = 1, .y = 2 });
    try point_queue.enqueue(Point{ .x = 3, .y = 4 });

    const p1 = point_queue.dequeue().?;
    try testing.expect(p1.x == 1 and p1.y == 2);

    const p2 = point_queue.dequeue().?;
    try testing.expect(p2.x == 3 and p2.y == 4);
}

test "Queue performance characteristics" {
    const iterations = 10000;

    // Test ArrayQueue performance
    var array_queue = try ArrayQueue(usize).init(testing.allocator, iterations);
    defer array_queue.deinit();

    // Enqueue performance
    const start = std.time.nanoTimestamp();
    for (0..iterations) |i| {
        try array_queue.enqueue(i);
    }
    const enqueue_time = std.time.nanoTimestamp() - start;

    // Dequeue performance
    const dequeue_start = std.time.nanoTimestamp();
    for (0..iterations) |i| {
        const value = array_queue.dequeue().?;
        try testing.expect(value == i);
    }
    const dequeue_time = std.time.nanoTimestamp() - dequeue_start;

    std.log.info("ArrayQueue performance: {} items", .{iterations});
    std.log.info("  Enqueue: {d:.2} ns/op", .{@as(f64, @floatFromInt(enqueue_time)) / @as(f64, @floatFromInt(iterations))});
    std.log.info("  Dequeue: {d:.2} ns/op", .{@as(f64, @floatFromInt(dequeue_time)) / @as(f64, @floatFromInt(iterations))});
}
