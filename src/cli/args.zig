//! CLI argument parsing for Ferret
//! Placeholder implementation

const std = @import("std");

pub fn Cli(comptime T: type) type {
    _ = T;
    return struct {
        const Self = @This();

        pub fn init() Self {
            return Self{};
        }

        pub fn deinit(self: *Self) void {
            _ = self;
        }
    };
}
