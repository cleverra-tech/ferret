//! Simple HTTP parser test
const std = @import("std");
const ferret = @import("ferret");
const http = ferret.Http;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    _ = gpa.allocator();

    std.log.info("=== HTTP Parser Test ===", .{});

    // Test simple GET request
    const request_data = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    
    var parser = http.Parser.init();
    
    std.log.info("Parsing: {s}", .{request_data});
    
    const parsed = parser.parse(request_data) catch |err| {
        std.log.err("Parse error: {}", .{err});
        return;
    };
    
    std.log.info("Parsed {} bytes", .{parsed});
    std.log.info("Parser state: {}", .{parser.state});
    std.log.info("Message complete: {}", .{parser.flags.message_complete});
    
    // Try parsing empty data to trigger state transition
    if (parser.state == .headers_done) {
        std.log.info("Triggering state transition...", .{});
        _ = parser.parse("") catch |err| {
            std.log.err("Parse error on empty: {}", .{err});
        };
        std.log.info("After empty parse - state: {}, complete: {}", .{ parser.state, parser.flags.message_complete });
    }
    
    // Test with body
    std.log.info("--- POST with body ---", .{});
    const post_data = "POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    
    parser.reset();
    std.log.info("Parsing: {s}", .{post_data});
    
    const parsed2 = parser.parse(post_data) catch |err| {
        std.log.err("Parse error: {}", .{err});
        return;
    };
    
    std.log.info("Parsed {} bytes", .{parsed2});
    std.log.info("Parser state: {}", .{parser.state});
    std.log.info("Message complete: {}", .{parser.flags.message_complete});
    std.log.info("Content length: {}", .{parser.content_length});
    std.log.info("Bytes read: {}", .{parser.bytes_read});
}