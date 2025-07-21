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

    // Programmatic build configuration
    const BuildConfig = struct {
        name: []const u8,
        file: []const u8,
        step_name: []const u8,
        description: []const u8,
    };

    const benchmarks = [_]BuildConfig{
        .{ .name = "json_benchmark", .file = "bench/json_benchmark.zig", .step_name = "benchmark-json", .description = "Run JSON benchmark" },
        .{ .name = "reactor_benchmark", .file = "bench/reactor_benchmark.zig", .step_name = "benchmark-reactor", .description = "Run reactor benchmark" },
        .{ .name = "crypto_benchmark", .file = "bench/crypto_benchmark.zig", .step_name = "benchmark-crypto", .description = "Run crypto benchmark" },
        .{ .name = "queue_benchmark", .file = "bench/queue_benchmark.zig", .step_name = "benchmark-queue", .description = "Run Queue performance benchmark" },
        .{ .name = "buffer_benchmark", .file = "bench/buffer_benchmark.zig", .step_name = "benchmark-buffer", .description = "Run Buffer performance benchmark" },
        .{ .name = "socket_benchmark", .file = "bench/socket_benchmark.zig", .step_name = "benchmark-socket", .description = "Run Socket performance benchmark" },
        .{ .name = "atomic_benchmark", .file = "bench/atomic_benchmark.zig", .step_name = "benchmark-atomic", .description = "Run Atomic operations performance benchmark" },
        .{ .name = "config_benchmark", .file = "bench/config_benchmark.zig", .step_name = "benchmark-config", .description = "Run configuration system performance benchmark" },
        .{ .name = "websocket_benchmark", .file = "bench/websocket_benchmark.zig", .step_name = "benchmark-websocket", .description = "Run WebSocket connection upgrade and processing benchmark" },
        .{ .name = "asymmetric_crypto_benchmark", .file = "bench/asymmetric_crypto_benchmark.zig", .step_name = "benchmark-asymmetric-crypto", .description = "Run asymmetric cryptography performance benchmark" },
        .{ .name = "http3_benchmark", .file = "bench/http3_benchmark.zig", .step_name = "benchmark-http3", .description = "Run HTTP/3 performance benchmark" },
        .{ .name = "http3_sendrequest_benchmark", .file = "bench/http3_sendrequest_benchmark.zig", .step_name = "benchmark-http3-sendrequest", .description = "Run HTTP/3 sendRequest benchmark" },
    };

    const tests = [_]BuildConfig{
        .{ .name = "integration_tests", .file = "tests/integration_tests.zig", .step_name = "test-integration", .description = "Run integration tests" },
        .{ .name = "http_test", .file = "tests/http_test.zig", .step_name = "test-http", .description = "Run HTTP test" },
        .{ .name = "unicode_test", .file = "tests/unicode_test.zig", .step_name = "test-unicode", .description = "Run Unicode validation test" },
        .{ .name = "http_client_test", .file = "tests/http_client_test.zig", .step_name = "test-http-client", .description = "Run HTTP client test and benchmark" },
        .{ .name = "http_server_test", .file = "tests/http_server_test.zig", .step_name = "test-http-server", .description = "Run HTTP server test and benchmark" },
    };

    const examples = [_]BuildConfig{
        .{ .name = "http3_demo", .file = "examples/http3_demo.zig", .step_name = "demo-http3", .description = "Run HTTP/3 demo" },
        .{ .name = "config_demo", .file = "examples/config_demo.zig", .step_name = "demo-config", .description = "Run configuration system demo" },
        .{ .name = "http2_demo", .file = "examples/http2_demo.zig", .step_name = "demo-http2", .description = "Run HTTP/2 demo" },
        .{ .name = "http_protocols_comparison", .file = "examples/http_protocols_comparison.zig", .step_name = "demo-http-comparison", .description = "Run HTTP protocols comparison demo" },
        .{ .name = "unified_http_demo", .file = "examples/unified_http_demo.zig", .step_name = "demo-unified-http", .description = "Run unified HTTP API demo" },
        .{ .name = "data_structures_demo", .file = "examples/data_structures_demo.zig", .step_name = "demo-data-structures", .description = "Run data structures demo" },
        .{ .name = "simple_http3_demo", .file = "examples/simple_http3_demo.zig", .step_name = "demo-simple-http3", .description = "Run simple HTTP/3 demo" },
    };

    // Build benchmarks
    var benchmark_runs: [benchmarks.len]*std.Build.Step.Run = undefined;
    for (benchmarks, 0..) |config, i| {
        const bench_exe = b.addExecutable(.{
            .name = config.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(config.file),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "ferret", .module = ferret_mod },
                },
            }),
        });
        b.installArtifact(bench_exe);
        const bench_run_cmd = b.addRunArtifact(bench_exe);
        benchmark_runs[i] = bench_run_cmd;
        const step = b.step(config.step_name, config.description);
        step.dependOn(&bench_run_cmd.step);
    }

    // Build tests
    for (tests) |config| {
        const test_exe = b.addExecutable(.{
            .name = config.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(config.file),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "ferret", .module = ferret_mod },
                },
            }),
        });
        b.installArtifact(test_exe);
        const test_run_cmd = b.addRunArtifact(test_exe);
        const step = b.step(config.step_name, config.description);
        step.dependOn(&test_run_cmd.step);
    }

    // Build examples
    for (examples) |config| {
        const example_exe = b.addExecutable(.{
            .name = config.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(config.file),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "ferret", .module = ferret_mod },
                },
            }),
        });
        b.installArtifact(example_exe);
        const example_run_cmd = b.addRunArtifact(example_exe);
        const step = b.step(config.step_name, config.description);
        step.dependOn(&example_run_cmd.step);
    }

    // Combined benchmark step
    const benchmark_step = b.step("benchmark", "Run all benchmarks");
    for (benchmark_runs) |bench_run_cmd| {
        benchmark_step.dependOn(&bench_run_cmd.step);
    }
}
