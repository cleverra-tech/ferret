const std = @import("std");
const ferret = @import("ferret");

const Args = struct {
    verbose: ?bool = null,
    port: ?u16 = null,
    host: ?[]const u8 = null,
    config: ?[]const u8 = null,
    workers: ?u32 = null,
    help: ?bool = null,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const version_str = try ferret.versionString(allocator);
    defer allocator.free(version_str);

    // Parse command line arguments
    var cli = try ferret.Cli(Args).init(allocator, ferret.CliConfig{
        .program_name = "ferret",
        .version = version_str,
        .description = "High-performance web framework for Zig",
        .author = "Ferret Contributors",
        .after_help = "For more information, visit: https://github.com/cleverra-tech/ferret",
    });
    defer cli.deinit();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    var result = cli.parse(argv) catch |err| switch (err) {
        ferret.CliError.HelpRequested, ferret.CliError.VersionRequested => return,
        else => return err,
    };
    defer result.deinit();

    // Configure logging level
    if (result.getBool("verbose")) {
        std.log.info("Verbose logging enabled", .{});
    }

    std.log.info("Ferret v{s} starting...", .{version_str});

    // Display configuration
    const port = result.getUint("port") orelse 8080;
    const host = result.getString("host") orelse "localhost";
    const workers = result.getUint("workers") orelse 4;

    std.log.info("Configuration:", .{});
    std.log.info("  Host: {s}", .{host});
    std.log.info("  Port: {}", .{port});
    std.log.info("  Workers: {}", .{workers});

    if (result.getString("config")) |config_file| {
        std.log.info("  Config file: {s}", .{config_file});
    }

    // Example usage
    var string = ferret.String.init(allocator);
    defer string.deinit();

    try string.appendSlice("Hello, Ferret!");
    std.log.info("Created string: {s}", .{string.slice()});

    std.log.info("Server would start here (not implemented yet)", .{});
}
