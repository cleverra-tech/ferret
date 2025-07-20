const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create ferret module
    const ferret_mod = b.addModule("ferret", .{
        .root_source_file = b.path("src/ferret.zig"),
        .target = target,
    });

    // Main executable
    const exe = b.addExecutable(.{
        .name = "ferret",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(exe);

    // Run step
    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Tests
    const lib_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ferret.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);

    // JSON benchmark
    const json_benchmark = b.addExecutable(.{
        .name = "json_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/json_benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(json_benchmark);

    const run_json_benchmark = b.addRunArtifact(json_benchmark);
    const benchmark_step = b.step("benchmark", "Run JSON benchmark");
    benchmark_step.dependOn(&run_json_benchmark.step);
}
