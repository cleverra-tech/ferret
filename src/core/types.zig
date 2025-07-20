//! Core type definitions and utilities for Ferret

const std = @import("std");

pub const Allocator = std.mem.Allocator;

/// Handle type for opaque pointers
pub const Handle = *anyopaque;

/// Reference counting type for automatic memory management
pub fn Ref(comptime T: type) type {
    return struct {
        const Self = @This();

        value: T,
        ref_count: std.atomic.Value(u32),
        allocator: Allocator,

        pub fn init(allocator: Allocator, value: T) !*Self {
            const self = try allocator.create(Self);
            self.* = Self{
                .value = value,
                .ref_count = std.atomic.Value(u32).init(1),
                .allocator = allocator,
            };
            return self;
        }

        pub fn retain(self: *Self) *Self {
            _ = self.ref_count.fetchAdd(1, .monotonic);
            return self;
        }

        pub fn release(self: *Self) void {
            if (self.ref_count.fetchSub(1, .acq_rel) == 1) {
                self.allocator.destroy(self);
            }
        }

        pub fn get(self: *const Self) *const T {
            return &self.value;
        }

        pub fn getMut(self: *Self) *T {
            return &self.value;
        }

        pub fn refCount(self: *const Self) u32 {
            return self.ref_count.load(.monotonic);
        }
    };
}

/// Optional type with explicit null handling
pub fn Optional(comptime T: type) type {
    return union(enum) {
        none,
        some: T,

        const Self = @This();

        pub fn init(value: T) Self {
            return Self{ .some = value };
        }

        pub fn empty() Self {
            return Self{ .none = {} };
        }

        pub fn isSome(self: Self) bool {
            return self == .some;
        }

        pub fn isNone(self: Self) bool {
            return self == .none;
        }

        pub fn unwrap(self: Self) T {
            return switch (self) {
                .some => |value| value,
                .none => std.debug.panic("Attempted to unwrap none value", .{}),
            };
        }

        pub fn unwrapOr(self: Self, default: T) T {
            return switch (self) {
                .some => |value| value,
                .none => default,
            };
        }

        pub fn map(self: Self, comptime func: anytype) Optional(@TypeOf(func(@as(T, undefined)))) {
            return switch (self) {
                .some => |value| Optional(@TypeOf(func(@as(T, undefined)))).init(func(value)),
                .none => Optional(@TypeOf(func(@as(T, undefined)))).empty(),
            };
        }
    };
}

/// Result type for error handling
pub fn Result(comptime T: type, comptime E: type) type {
    return union(enum) {
        ok: T,
        err: E,

        const Self = @This();

        pub fn success(value: T) Self {
            return Self{ .ok = value };
        }

        pub fn failure(error_value: E) Self {
            return Self{ .err = error_value };
        }

        pub fn isOk(self: Self) bool {
            return self == .ok;
        }

        pub fn isErr(self: Self) bool {
            return self == .err;
        }

        pub fn unwrap(self: Self) T {
            return switch (self) {
                .ok => |value| value,
                .err => |e| std.debug.panic("Attempted to unwrap error: {any}", .{e}),
            };
        }

        pub fn unwrapOr(self: Self, default: T) T {
            return switch (self) {
                .ok => |value| value,
                .err => default,
            };
        }

        pub fn unwrapErr(self: Self) E {
            return switch (self) {
                .err => |error_value| error_value,
                .ok => std.debug.panic("Attempted to unwrap ok value as error", .{}),
            };
        }

        pub fn map(self: Self, comptime func: anytype) Result(@TypeOf(func(@as(T, undefined))), E) {
            return switch (self) {
                .ok => |value| Result(@TypeOf(func(@as(T, undefined))), E).success(func(value)),
                .err => |error_value| Result(@TypeOf(func(@as(T, undefined))), E).failure(error_value),
            };
        }

        pub fn mapErr(self: Self, comptime func: anytype) Result(T, @TypeOf(func(@as(E, undefined)))) {
            return switch (self) {
                .ok => |value| Result(T, @TypeOf(func(@as(E, undefined)))).success(value),
                .err => |error_value| Result(T, @TypeOf(func(@as(E, undefined)))).failure(func(error_value)),
            };
        }
    };
}

/// Slice type with explicit ownership semantics
pub fn Slice(comptime T: type) type {
    return struct {
        const Self = @This();

        ptr: [*]T,
        len: usize,
        owned: bool,
        allocator: ?Allocator,

        pub fn init(data: []T) Self {
            return Self{
                .ptr = data.ptr,
                .len = data.len,
                .owned = false,
                .allocator = null,
            };
        }

        pub fn initOwned(allocator: Allocator, data: []T) Self {
            return Self{
                .ptr = data.ptr,
                .len = data.len,
                .owned = true,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.owned and self.allocator != null) {
                self.allocator.?.free(self.slice());
            }
        }

        pub fn slice(self: Self) []T {
            return self.ptr[0..self.len];
        }

        pub fn sliceConst(self: Self) []const T {
            return self.ptr[0..self.len];
        }

        pub fn clone(self: Self, allocator: Allocator) !Self {
            const new_data = try allocator.dupe(T, self.slice());
            return Self.initOwned(allocator, new_data);
        }
    };
}

test "Ref counting" {
    const allocator = std.testing.allocator;

    var ref = try Ref(i32).init(allocator, 42);
    defer ref.release();

    try std.testing.expectEqual(@as(u32, 1), ref.refCount());
    try std.testing.expectEqual(@as(i32, 42), ref.get().*);

    var ref2 = ref.retain();
    try std.testing.expectEqual(@as(u32, 2), ref.refCount());
    ref2.release();

    try std.testing.expectEqual(@as(u32, 1), ref.refCount());
}

test "Optional operations" {
    const opt1 = Optional(i32).init(42);
    const opt2 = Optional(i32).empty();

    try std.testing.expect(opt1.isSome());
    try std.testing.expect(opt2.isNone());

    try std.testing.expectEqual(@as(i32, 42), opt1.unwrap());
    try std.testing.expectEqual(@as(i32, 0), opt2.unwrapOr(0));

    const doubled = opt1.map(struct {
        fn double(x: i32) i32 {
            return x * 2;
        }
    }.double);

    try std.testing.expectEqual(@as(i32, 84), doubled.unwrap());
}

test "Result operations" {
    const res1 = Result(i32, []const u8).success(42);
    const res2 = Result(i32, []const u8).failure("error");

    try std.testing.expect(res1.isOk());
    try std.testing.expect(res2.isErr());

    try std.testing.expectEqual(@as(i32, 42), res1.unwrap());
    try std.testing.expectEqualStrings("error", res2.unwrapErr());

    const doubled = res1.map(struct {
        fn double(x: i32) i32 {
            return x * 2;
        }
    }.double);

    try std.testing.expectEqual(@as(i32, 84), doubled.unwrap());
}

test "Slice operations" {
    const allocator = std.testing.allocator;

    const data = [_]i32{ 1, 2, 3, 4, 5 };
    var slice = Slice(i32).init(@constCast(data[0..]));

    try std.testing.expectEqual(@as(usize, 5), slice.len);
    try std.testing.expectEqual(@as(i32, 1), slice.slice()[0]);

    var owned_slice = try slice.clone(allocator);
    defer owned_slice.deinit();

    try std.testing.expectEqual(@as(usize, 5), owned_slice.len);
    try std.testing.expectEqual(@as(i32, 1), owned_slice.slice()[0]);
}
