const std = @import("std");
const ferret = @import("ferret");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const version_str = try ferret.versionString(allocator);
    defer allocator.free(version_str);
    std.log.info("Ferret v{s} starting...", .{version_str});

    // Example usage
    var string = ferret.String.init(allocator);
    defer string.deinit();

    try string.appendSlice("Hello, Ferret!");
    std.log.info("Created string: {s}", .{string.slice()});
}
