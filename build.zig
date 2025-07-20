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

    // Integration tests
    const integration_tests = b.addExecutable(.{
        .name = "integration_tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(integration_tests);

    const run_integration_tests = b.addRunArtifact(integration_tests);
    const integration_test_step = b.step("test-integration", "Run integration tests");
    integration_test_step.dependOn(&run_integration_tests.step);

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
    const json_benchmark_step = b.step("benchmark-json", "Run JSON benchmark");
    json_benchmark_step.dependOn(&run_json_benchmark.step);

    // Reactor benchmark
    const reactor_benchmark = b.addExecutable(.{
        .name = "reactor_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/reactor_benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(reactor_benchmark);

    const run_reactor_benchmark = b.addRunArtifact(reactor_benchmark);
    const reactor_benchmark_step = b.step("benchmark-reactor", "Run reactor benchmark");
    reactor_benchmark_step.dependOn(&run_reactor_benchmark.step);

    // Crypto benchmark
    const crypto_benchmark = b.addExecutable(.{
        .name = "crypto_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/crypto_benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(crypto_benchmark);

    const run_crypto_benchmark = b.addRunArtifact(crypto_benchmark);
    const crypto_benchmark_step = b.step("benchmark-crypto", "Run crypto benchmark");
    crypto_benchmark_step.dependOn(&run_crypto_benchmark.step);

    // HTTP test
    const http_test = b.addExecutable(.{
        .name = "http_test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(http_test);

    const run_http_test = b.addRunArtifact(http_test);
    const http_test_step = b.step("test-http", "Run HTTP test");
    http_test_step.dependOn(&run_http_test.step);

    // HTTP/3 demo
    const http3_demo = b.addExecutable(.{
        .name = "http3_demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http3_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(http3_demo);

    const run_http3_demo = b.addRunArtifact(http3_demo);
    const http3_demo_step = b.step("demo-http3", "Run HTTP/3 demo");
    http3_demo_step.dependOn(&run_http3_demo.step);

    // HTTP/3 sendRequest benchmark
    const http3_sendrequest_benchmark = b.addExecutable(.{
        .name = "http3_sendrequest_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http3_sendrequest_benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(http3_sendrequest_benchmark);

    const run_http3_sendrequest_benchmark = b.addRunArtifact(http3_sendrequest_benchmark);
    const http3_sendrequest_benchmark_step = b.step("benchmark-http3-sendrequest", "Run HTTP/3 sendRequest benchmark");
    http3_sendrequest_benchmark_step.dependOn(&run_http3_sendrequest_benchmark.step);

    // Configuration demo
    const config_demo = b.addExecutable(.{
        .name = "config_demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/config_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(config_demo);

    const run_config_demo = b.addRunArtifact(config_demo);
    const config_demo_step = b.step("demo-config", "Run configuration system demo");
    config_demo_step.dependOn(&run_config_demo.step);

    // HTTP/2 demo
    const http2_demo = b.addExecutable(.{
        .name = "http2_demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http2_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(http2_demo);

    const run_http2_demo = b.addRunArtifact(http2_demo);
    const http2_demo_step = b.step("demo-http2", "Run HTTP/2 demo");
    http2_demo_step.dependOn(&run_http2_demo.step);

    // HTTP protocols comparison demo
    const http_comparison_demo = b.addExecutable(.{
        .name = "http_protocols_comparison",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http_protocols_comparison.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(http_comparison_demo);

    const run_http_comparison_demo = b.addRunArtifact(http_comparison_demo);
    const http_comparison_demo_step = b.step("demo-http-comparison", "Run HTTP protocols comparison demo");
    http_comparison_demo_step.dependOn(&run_http_comparison_demo.step);

    // Unified HTTP demo
    const unified_http_demo = b.addExecutable(.{
        .name = "unified_http_demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/unified_http_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(unified_http_demo);

    const run_unified_http_demo = b.addRunArtifact(unified_http_demo);
    const unified_http_demo_step = b.step("demo-unified-http", "Run unified HTTP API demo");
    unified_http_demo_step.dependOn(&run_unified_http_demo.step);

    // Unicode test
    const unicode_test = b.addExecutable(.{
        .name = "unicode_test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/unicode_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(unicode_test);

    const run_unicode_test = b.addRunArtifact(unicode_test);
    const unicode_test_step = b.step("test-unicode", "Run Unicode validation test");
    unicode_test_step.dependOn(&run_unicode_test.step);

    // Queue benchmark
    const queue_benchmark = b.addExecutable(.{
        .name = "queue_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/queue_benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(queue_benchmark);

    const run_queue_benchmark = b.addRunArtifact(queue_benchmark);
    const queue_benchmark_step = b.step("benchmark-queue", "Run Queue performance benchmark");
    queue_benchmark_step.dependOn(&run_queue_benchmark.step);

    // Buffer benchmark
    const buffer_benchmark = b.addExecutable(.{
        .name = "buffer_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/buffer_benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(buffer_benchmark);

    const run_buffer_benchmark = b.addRunArtifact(buffer_benchmark);
    const buffer_benchmark_step = b.step("benchmark-buffer", "Run Buffer performance benchmark");
    buffer_benchmark_step.dependOn(&run_buffer_benchmark.step);

    // Socket benchmark
    const socket_benchmark = b.addExecutable(.{
        .name = "socket_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/socket_benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(socket_benchmark);

    const run_socket_benchmark = b.addRunArtifact(socket_benchmark);
    const socket_benchmark_step = b.step("benchmark-socket", "Run Socket performance benchmark");
    socket_benchmark_step.dependOn(&run_socket_benchmark.step);

    // Atomic benchmark
    const atomic_benchmark = b.addExecutable(.{
        .name = "atomic_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/atomic_benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(atomic_benchmark);

    const run_atomic_benchmark = b.addRunArtifact(atomic_benchmark);
    const atomic_benchmark_step = b.step("benchmark-atomic", "Run Atomic operations performance benchmark");
    atomic_benchmark_step.dependOn(&run_atomic_benchmark.step);

    // CLI benchmark
    const cli_benchmark = b.addExecutable(.{
        .name = "cli_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/cli_benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(cli_benchmark);

    const run_cli_benchmark = b.addRunArtifact(cli_benchmark);
    const cli_benchmark_step = b.step("benchmark-cli", "Run CLI parsing performance benchmark");
    cli_benchmark_step.dependOn(&run_cli_benchmark.step);

    // Configuration benchmark
    const config_benchmark = b.addExecutable(.{
        .name = "config_benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/config_benchmark.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(config_benchmark);

    const run_config_benchmark = b.addRunArtifact(config_benchmark);
    const config_benchmark_step = b.step("benchmark-config", "Run configuration system performance benchmark");
    config_benchmark_step.dependOn(&run_config_benchmark.step);

    // HTTP client test
    const http_client_test = b.addExecutable(.{
        .name = "http_client_test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http_client_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(http_client_test);

    const run_http_client_test = b.addRunArtifact(http_client_test);
    const http_client_test_step = b.step("test-http-client", "Run HTTP client test and benchmark");
    http_client_test_step.dependOn(&run_http_client_test.step);

    // HTTP server test
    const http_server_test = b.addExecutable(.{
        .name = "http_server_test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http_server_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ferret", .module = ferret_mod },
            },
        }),
    });
    b.installArtifact(http_server_test);

    const run_http_server_test = b.addRunArtifact(http_server_test);
    const http_server_test_step = b.step("test-http-server", "Run HTTP server test and benchmark");
    http_server_test_step.dependOn(&run_http_server_test.step);

    // Combined benchmark step
    const benchmark_step = b.step("benchmark", "Run all benchmarks");
    benchmark_step.dependOn(&run_json_benchmark.step);
    benchmark_step.dependOn(&run_reactor_benchmark.step);
    benchmark_step.dependOn(&run_crypto_benchmark.step);
    benchmark_step.dependOn(&run_queue_benchmark.step);
    benchmark_step.dependOn(&run_buffer_benchmark.step);
    benchmark_step.dependOn(&run_socket_benchmark.step);
    benchmark_step.dependOn(&run_atomic_benchmark.step);
    benchmark_step.dependOn(&run_cli_benchmark.step);
    benchmark_step.dependOn(&run_config_benchmark.step);
}
