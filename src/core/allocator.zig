//! Memory management utilities and specialized allocators for Ferret

const std = @import("std");
const types = @import("types.zig");

pub const Allocator = std.mem.Allocator;

/// Pool allocator for high-frequency object allocation
pub fn Pool(comptime T: type) type {
    return struct {
        const Self = @This();
        const Node = struct {
            next: ?*Node,
            data: T,
        };

        allocator: Allocator,
        free_list: ?*Node,
        allocated_nodes: std.ArrayList(*Node),

        pub fn init(allocator: Allocator) Self {
            return Self{
                .allocator = allocator,
                .free_list = null,
                .allocated_nodes = std.ArrayList(*Node).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.allocated_nodes.items) |node| {
                self.allocator.destroy(node);
            }
            self.allocated_nodes.deinit();
        }

        pub fn acquire(self: *Self) !*T {
            if (self.free_list) |node| {
                self.free_list = node.next;
                return &node.data;
            }

            const node = try self.allocator.create(Node);
            try self.allocated_nodes.append(node);
            return &node.data;
        }

        pub fn release(self: *Self, item: *T) void {
            const node: *Node = @alignCast(@fieldParentPtr("data", item));
            node.next = self.free_list;
            self.free_list = node;
        }

        pub fn count(self: Self) usize {
            return self.allocated_nodes.items.len;
        }

        pub fn freeCount(self: Self) usize {
            var free_count: usize = 0;
            var current = self.free_list;
            while (current != null) {
                free_count += 1;
                current = current.?.next;
            }
            return free_count;
        }
    };
}

/// Tracking allocator that monitors memory usage and leaks
pub const TrackingAllocator = struct {
    const Self = @This();
    const AllocationInfo = struct {
        size: usize,
        alignment: u8,
        return_address: usize,
    };

    parent_allocator: Allocator,
    allocations: std.HashMap(usize, AllocationInfo, std.hash_map.AutoContext(usize), 80),
    total_allocated: usize,
    peak_allocated: usize,
    allocation_count: usize,

    pub fn init(parent_allocator: Allocator) Self {
        return Self{
            .parent_allocator = parent_allocator,
            .allocations = std.HashMap(usize, AllocationInfo, std.hash_map.AutoContext(usize), 80).init(parent_allocator),
            .total_allocated = 0,
            .peak_allocated = 0,
            .allocation_count = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.allocations.count() > 0) {
            std.log.warn("Memory leak detected: {} allocations not freed", .{self.allocations.count()});
            var iterator = self.allocations.iterator();
            while (iterator.next()) |entry| {
                const addr = entry.key_ptr.*;
                const info = entry.value_ptr.*;
                std.log.warn("  Leaked {} bytes at 0x{x} (allocated from 0x{x})", .{ info.size, addr, info.return_address });
            }
        }
        self.allocations.deinit();
    }

    pub fn allocator(self: *Self) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
                .remap = Allocator.noRemap,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, log2_ptr_align: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        const ptr = self.parent_allocator.rawAlloc(len, log2_ptr_align, ra) orelse return null;
        const addr = @intFromPtr(ptr);

        self.allocations.put(addr, AllocationInfo{
            .size = len,
            .alignment = @intFromEnum(log2_ptr_align),
            .return_address = ra,
        }) catch return null;

        self.total_allocated += len;
        self.peak_allocated = @max(self.peak_allocated, self.total_allocated);
        self.allocation_count += 1;

        return ptr;
    }

    fn resize(ctx: *anyopaque, buf: []u8, log2_buf_align: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *Self = @ptrCast(@alignCast(ctx));
        const addr = @intFromPtr(buf.ptr);

        if (self.allocations.get(addr)) |old_info| {
            if (self.parent_allocator.rawResize(buf, log2_buf_align, new_len, ra)) {
                self.total_allocated = self.total_allocated - old_info.size + new_len;
                self.peak_allocated = @max(self.peak_allocated, self.total_allocated);

                self.allocations.put(addr, AllocationInfo{
                    .size = new_len,
                    .alignment = old_info.alignment,
                    .return_address = old_info.return_address,
                }) catch return false;

                return true;
            }
        }

        return false;
    }

    fn free(ctx: *anyopaque, buf: []u8, log2_buf_align: std.mem.Alignment, ra: usize) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        const addr = @intFromPtr(buf.ptr);

        if (self.allocations.fetchRemove(addr)) |entry| {
            self.total_allocated -= entry.value.size;
            self.parent_allocator.rawFree(buf, log2_buf_align, ra);
        } else {
            std.log.warn("Attempted to free untracked memory at 0x{x}", .{addr});
        }
    }

    pub fn getStats(self: Self) struct {
        total_allocated: usize,
        peak_allocated: usize,
        allocation_count: usize,
        current_allocations: usize,
    } {
        return .{
            .total_allocated = self.total_allocated,
            .peak_allocated = self.peak_allocated,
            .allocation_count = self.allocation_count,
            .current_allocations = self.allocations.count(),
        };
    }
};

/// Arena allocator that can be reset for request-scoped memory
pub const Arena = struct {
    const Self = @This();

    arena: std.heap.ArenaAllocator,

    pub fn init(child_allocator: Allocator) Self {
        return Self{
            .arena = std.heap.ArenaAllocator.init(child_allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.arena.deinit();
    }

    pub fn allocator(self: *Self) Allocator {
        return self.arena.allocator();
    }

    pub fn reset(self: *Self) void {
        _ = self.arena.reset(.retain_capacity);
    }

    pub fn queryCapacity(self: Self) usize {
        return self.arena.queryCapacity();
    }
};

/// Fixed buffer allocator for stack-like allocation patterns
pub const FixedBuffer = struct {
    const Self = @This();

    fba: std.heap.FixedBufferAllocator,

    pub fn init(buffer: []u8) Self {
        return Self{
            .fba = std.heap.FixedBufferAllocator.init(buffer),
        };
    }

    pub fn allocator(self: *Self) Allocator {
        return self.fba.allocator();
    }

    pub fn reset(self: *Self) void {
        self.fba.reset();
    }

    pub fn end_index(self: Self) usize {
        return self.fba.end_index;
    }
};

test "Pool allocator basic operations" {
    const allocator = std.testing.allocator;

    var pool = Pool(i32).init(allocator);
    defer pool.deinit();

    const item1 = try pool.acquire();
    item1.* = 42;

    const item2 = try pool.acquire();
    item2.* = 84;

    try std.testing.expectEqual(@as(usize, 2), pool.count());
    try std.testing.expectEqual(@as(usize, 0), pool.freeCount());

    pool.release(item1);
    try std.testing.expectEqual(@as(usize, 1), pool.freeCount());

    const item3 = try pool.acquire();
    try std.testing.expectEqual(@as(usize, 0), pool.freeCount());
    try std.testing.expectEqual(@as(i32, 42), item3.*); // Reused item1
}

test "Tracking allocator memory tracking" {
    const base_allocator = std.testing.allocator;

    var tracking = TrackingAllocator.init(base_allocator);
    defer tracking.deinit();

    const allocator = tracking.allocator();

    const data1 = try allocator.alloc(u8, 100);
    const data2 = try allocator.alloc(u8, 200);

    const stats = tracking.getStats();
    try std.testing.expectEqual(@as(usize, 300), stats.total_allocated);
    try std.testing.expectEqual(@as(usize, 300), stats.peak_allocated);
    try std.testing.expectEqual(@as(usize, 2), stats.allocation_count);
    try std.testing.expectEqual(@as(usize, 2), stats.current_allocations);

    allocator.free(data1);

    const stats2 = tracking.getStats();
    try std.testing.expectEqual(@as(usize, 200), stats2.total_allocated);
    try std.testing.expectEqual(@as(usize, 300), stats2.peak_allocated);
    try std.testing.expectEqual(@as(usize, 1), stats2.current_allocations);

    allocator.free(data2);
}

test "Arena allocator reset functionality" {
    const base_allocator = std.testing.allocator;

    var arena = Arena.init(base_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const data1 = try allocator.alloc(u8, 100);
    _ = data1;

    const capacity_after_alloc = arena.queryCapacity();

    arena.reset();

    const capacity_after_reset = arena.queryCapacity();
    try std.testing.expect(capacity_after_reset >= capacity_after_alloc);

    const data2 = try allocator.alloc(u8, 50);
    _ = data2;
}

test "Fixed buffer allocator" {
    var buffer: [1024]u8 = undefined;
    var fba = FixedBuffer.init(&buffer);
    const allocator = fba.allocator();

    const data1 = try allocator.alloc(u8, 100);
    const data2 = try allocator.alloc(u8, 200);

    _ = data1;
    _ = data2;

    try std.testing.expectEqual(@as(usize, 300), fba.end_index());

    fba.reset();
    try std.testing.expectEqual(@as(usize, 0), fba.end_index());
}
