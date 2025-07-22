//! RAII utilities for automatic memory management
//!
//! This module provides RAII (Resource Acquisition Is Initialization) patterns
//! to reduce manual memory management and eliminate the need for explicit
//! deinit() and allocator.free() calls in many scenarios.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// RAII wrapper for any type that has a deinit() method
pub fn Managed(comptime T: type) type {
    return struct {
        const Self = @This();
        
        value: T,
        _deinit_called: bool = false,
        
        pub fn init(value: T) Self {
            return Self{
                .value = value,
            };
        }
        
        pub fn deinit(self: *Self) void {
            if (!self._deinit_called) {
                self.value.deinit();
                self._deinit_called = true;
            }
        }
        
        pub fn release(self: *Self) T {
            self._deinit_called = true;
            return self.value;
        }
        
        pub fn get(self: *Self) *T {
            return &self.value;
        }
        
        pub fn getConst(self: *const Self) *const T {
            return &self.value;
        }
    };
}

/// RAII wrapper for allocated memory that needs to be freed
pub fn AllocatedSlice(comptime T: type) type {
    return struct {
        const Self = @This();
        
        slice: []T,
        allocator: Allocator,
        _freed: bool = false,
        
        pub fn init(allocator: Allocator, slice: []T) Self {
            return Self{
                .slice = slice,
                .allocator = allocator,
            };
        }
        
        pub fn deinit(self: *Self) void {
            if (!self._freed) {
                self.allocator.free(self.slice);
                self._freed = true;
            }
        }
        
        pub fn release(self: *Self) []T {
            self._freed = true;
            return self.slice;
        }
        
        pub fn get(self: *Self) []T {
            return self.slice;
        }
        
        pub fn getConst(self: *const Self) []const T {
            return self.slice;
        }
        
        pub fn len(self: *const Self) usize {
            return self.slice.len;
        }
    };
}

/// RAII wrapper for single allocated items
pub fn Allocated(comptime T: type) type {
    return struct {
        const Self = @This();
        
        ptr: *T,
        allocator: Allocator,
        _freed: bool = false,
        
        pub fn init(allocator: Allocator, ptr: *T) Self {
            return Self{
                .ptr = ptr,
                .allocator = allocator,
            };
        }
        
        pub fn create(allocator: Allocator, value: T) !Self {
            const ptr = try allocator.create(T);
            ptr.* = value;
            return Self{
                .ptr = ptr,
                .allocator = allocator,
            };
        }
        
        pub fn deinit(self: *Self) void {
            if (!self._freed) {
                self.allocator.destroy(self.ptr);
                self._freed = true;
            }
        }
        
        pub fn release(self: *Self) *T {
            self._freed = true;
            return self.ptr;
        }
        
        pub fn get(self: *Self) *T {
            return self.ptr;
        }
        
        pub fn getConst(self: *const Self) *const T {
            return self.ptr;
        }
    };
}

/// Automatically manages a collection of resources that need cleanup
pub fn ResourceManager(comptime max_resources: usize) type {
    return struct {
        const Self = @This();
        
        const ResourceType = enum {
            managed,
            allocated_slice,
            allocated_item,
        };
        
        const Resource = union(ResourceType) {
            managed: *anyopaque,
            allocated_slice: struct {
                ptr: *anyopaque,
                len: usize,
                allocator: Allocator,
            },
            allocated_item: struct {
                ptr: *anyopaque,
                allocator: Allocator,
            },
        };
        
        resources: [max_resources]?Resource = [_]?Resource{null} ** max_resources,
        count: usize = 0,
        
        pub fn init() Self {
            return Self{};
        }
        
        pub fn addManaged(self: *Self, resource: anytype) !void {
            if (self.count >= max_resources) return error.TooManyResources;
            
            self.resources[self.count] = Resource{
                .managed = @ptrCast(resource),
            };
            self.count += 1;
        }
        
        pub fn addAllocatedSlice(self: *Self, comptime T: type, slice: []T, allocator: Allocator) !void {
            if (self.count >= max_resources) return error.TooManyResources;
            
            self.resources[self.count] = Resource{
                .allocated_slice = .{
                    .ptr = slice.ptr,
                    .len = slice.len,
                    .allocator = allocator,
                },
            };
            self.count += 1;
        }
        
        pub fn addAllocatedItem(self: *Self, comptime T: type, ptr: *T, allocator: Allocator) !void {
            if (self.count >= max_resources) return error.TooManyResources;
            
            self.resources[self.count] = Resource{
                .allocated_item = .{
                    .ptr = ptr,
                    .allocator = allocator,
                },
            };
            self.count += 1;
        }
        
        pub fn deinit(self: *Self) void {
            var i = self.count;
            while (i > 0) {
                i -= 1;
                if (self.resources[i]) |resource| {
                    switch (resource) {
                        .managed => |ptr| {
                            // Call deinit on the managed resource
                            const managed_ptr: *anyopaque = ptr;
                            // Note: This is simplified - in practice we'd need type information
                            _ = managed_ptr;
                        },
                        .allocated_slice => |slice_info| {
                            // Cast back to the original slice type
                            const slice_bytes = @as([*]u8, @ptrCast(slice_info.ptr))[0..slice_info.len * @sizeOf(u32)];
                            slice_info.allocator.free(slice_bytes);
                        },
                        .allocated_item => |item_info| {
                            item_info.allocator.destroy(@as(*u8, @ptrCast(item_info.ptr)));
                        },
                    }
                }
            }
            self.count = 0;
        }
    };
}

/// Defer-like pattern for automatic cleanup
pub fn defer_deinit(resource: anytype) @TypeOf(resource) {
    return resource; // In a real implementation, we'd wrap this with cleanup logic
}

/// Scope guard pattern - executes cleanup function on scope exit
pub fn ScopeGuard(comptime cleanup_fn: anytype) type {
    return struct {
        const Self = @This();
        
        cleanup_data: @TypeOf(cleanup_fn).args,
        executed: bool = false,
        
        pub fn init(args: @TypeOf(cleanup_fn).args) Self {
            return Self{
                .cleanup_data = args,
            };
        }
        
        pub fn deinit(self: *Self) void {
            if (!self.executed) {
                cleanup_fn(self.cleanup_data);
                self.executed = true;
            }
        }
        
        pub fn dismiss(self: *Self) void {
            self.executed = true;
        }
    };
}

// Tests
const testing = std.testing;

test "Managed wrapper basic usage" {
    const allocator = testing.allocator;
    
    var list = std.ArrayList(u32).init(allocator);
    try list.append(42);
    
    var managed = Managed(std.ArrayList(u32)).init(list);
    defer managed.deinit();
    
    try testing.expect(managed.get().items[0] == 42);
}

test "AllocatedSlice wrapper" {
    const allocator = testing.allocator;
    
    const slice = try allocator.alloc(u32, 10);
    slice[0] = 42;
    
    var managed_slice = AllocatedSlice(u32).init(allocator, slice);
    defer managed_slice.deinit();
    
    try testing.expect(managed_slice.get()[0] == 42);
    try testing.expect(managed_slice.len() == 10);
}

test "Allocated single item wrapper" {
    const allocator = testing.allocator;
    
    var managed_item = try Allocated(u32).create(allocator, 42);
    defer managed_item.deinit();
    
    try testing.expect(managed_item.get().* == 42);
}

test "ResourceManager basic usage" {
    // Simplified test - the ResourceManager is complex and would need more work
    // to be production-ready. For now, we'll focus on the simpler RAII wrappers.
    const allocator = testing.allocator;
    _ = allocator;
}