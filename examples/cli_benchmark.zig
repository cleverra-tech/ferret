//! CLI argument parsing performance benchmark

const std = @import("std");
const ferret = @import("ferret");

const BenchArgs = struct {
    verbose: ?bool = null,
    output: ?[]const u8 = null,
    count: ?u32 = null,
    threads: ?u32 = null,
    config: ?[]const u8 = null,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== CLI Argument Parsing Benchmark ===\n", .{});

    try benchmarkParsing(allocator);
    try benchmarkHelpGeneration(allocator);

    std.log.info("\n=== Benchmark Complete ===", .{});
}

fn benchmarkParsing(allocator: std.mem.Allocator) !void {
    const iterations = 100_000;

    var cli = try ferret.Cli(BenchArgs).init(allocator, ferret.CliConfig{
        .program_name = "benchmark",
        .version = "1.0.0",
        .description = "CLI parsing benchmark",
    });
    defer cli.deinit();

    // Test simple parsing
    const simple_argv = [_][]const u8{ "benchmark", "--verbose", "--count", "42" };

    const start_simple = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        var result = cli.parse(simple_argv[0..]) catch continue;
        result.deinit();
    }
    const simple_time = std.time.nanoTimestamp() - start_simple;

    // Test complex parsing
    const complex_argv = [_][]const u8{ "benchmark", "--verbose", "--output", "result.txt", "--count", "1000", "--threads", "8", "--config", "/etc/app.conf" };

    const start_complex = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        var result = cli.parse(complex_argv[0..]) catch continue;
        result.deinit();
    }
    const complex_time = std.time.nanoTimestamp() - start_complex;

    const simple_ns_per_op = @as(f64, @floatFromInt(simple_time)) / @as(f64, @floatFromInt(iterations));
    const complex_ns_per_op = @as(f64, @floatFromInt(complex_time)) / @as(f64, @floatFromInt(iterations));

    std.log.info("CLI Parsing Performance ({} iterations):", .{iterations});
    std.log.info("  Simple (2 args): {d:.2} ns/op ({d:.2} ops/sec)", .{ simple_ns_per_op, 1_000_000_000.0 / simple_ns_per_op });
    std.log.info("  Complex (5 args): {d:.2} ns/op ({d:.2} ops/sec)", .{ complex_ns_per_op, 1_000_000_000.0 / complex_ns_per_op });
}

fn benchmarkHelpGeneration(allocator: std.mem.Allocator) !void {
    const iterations = 10_000;

    var cli = try ferret.Cli(BenchArgs).init(allocator, ferret.CliConfig{
        .program_name = "benchmark",
        .version = "1.0.0",
        .description = "CLI parsing benchmark with a longer description to test help generation performance and formatting capabilities",
        .author = "Benchmark Suite",
        .after_help = "This is additional help text that appears after the main help content.",
    });
    defer cli.deinit();

    // Redirect stdout to measure help generation performance
    const start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        // Note: This would normally print to stdout, but we're just measuring the generation time
        cli.printHelp();
    }
    const help_time = std.time.nanoTimestamp() - start;

    const help_ns_per_op = @as(f64, @floatFromInt(help_time)) / @as(f64, @floatFromInt(iterations));

    std.log.info("Help Generation Performance ({} iterations):", .{iterations});
    std.log.info("  Help text: {d:.2} ns/op ({d:.2} ops/sec)", .{ help_ns_per_op, 1_000_000_000.0 / help_ns_per_op });
}
