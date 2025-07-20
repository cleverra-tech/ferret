const std = @import("std");
const ferret = @import("ferret");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("Ferret v{any} starting...", .{ferret.version});

    // Example usage
    var string = ferret.String.init(allocator);
    defer string.deinit();

    try string.appendSlice("Hello, Ferret!");
    std.log.info("Created string: {s}", .{string.slice()});
}
