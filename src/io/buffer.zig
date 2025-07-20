//! Buffer implementation for Ferret
//! Placeholder implementation

const std = @import("std");

pub const Buffer = struct {
    const Self = @This();

    pub fn init() Self {
        return Self{};
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }
};
