//! I/O reactor implementation for Ferret
//! Placeholder implementation

const std = @import("std");

pub const Reactor = struct {
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }
};
