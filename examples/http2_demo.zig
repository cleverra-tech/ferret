//! HTTP/2 demonstration - showcasing binary framing and HPACK
//!
//! This example demonstrates:
//! - HTTP/2 binary framing layer
//! - HPACK header compression
//! - Stream multiplexing capabilities
//! - Frame parsing and generation
//! - Connection and stream management

const std = @import("std");
const ferret = @import("ferret");
const Http2 = ferret.Http2;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== HTTP/2 Demo ===", .{});

    // Demonstrate HTTP/2 frame types
    std.log.info("\n--- HTTP/2 Frame Types ---", .{});
    const frame_types = [_]Http2.FrameType{ .data, .headers, .priority, .rst_stream, .settings, .push_promise, .ping, .goaway, .window_update, .continuation };
    
    for (frame_types) |frame_type| {
        std.log.info("{s} (0x{X})", .{ frame_type.toString(), @intFromEnum(frame_type) });
    }

    // Demonstrate HTTP/2 error codes
    std.log.info("\n--- HTTP/2 Error Codes ---", .{});
    const error_codes = [_]Http2.ErrorCode{ .no_error, .protocol_error, .internal_error, .flow_control_error, .settings_timeout, .stream_closed, .frame_size_error };
    
    for (error_codes) |error_code| {
        std.log.info("{s} ({})", .{ error_code.toString(), @intFromEnum(error_code) });
    }

    // Frame header parsing demonstration
    std.log.info("\n--- HTTP/2 Frame Header Parsing ---", .{});
    
    // Create a HEADERS frame header: length=10, type=HEADERS(1), flags=0x05, stream_id=1
    const header_data = [_]u8{ 0x00, 0x00, 0x0A, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01 };
    
    if (Http2.FrameHeader.parse(&header_data)) |header| {
        std.log.info("Parsed frame header:", .{});
        std.log.info("  Length: {}", .{header.length});
        std.log.info("  Type: {s}", .{header.frame_type.toString()});
        std.log.info("  Flags: 0x{X:0>2}", .{header.flags.toByte()});
        std.log.info("  Stream ID: {}", .{header.stream_id});
        std.log.info("  END_STREAM: {}", .{header.flags.endStream()});
        std.log.info("  END_HEADERS: {}", .{header.flags.endHeaders()});
    }

    // Frame creation demonstration
    std.log.info("\n--- HTTP/2 Frame Creation ---", .{});
    
    // Create DATA frame
    const data_payload = "Hello, HTTP/2 world!";
    const data_frame = Http2.Frame.data(1, data_payload, true);
    std.log.info("DATA frame:", .{});
    std.log.info("  Stream ID: {}", .{data_frame.header.stream_id});
    std.log.info("  Payload length: {}", .{data_frame.header.length});
    std.log.info("  END_STREAM: {}", .{data_frame.header.flags.endStream()});
    std.log.info("  Total size: {} bytes", .{data_frame.totalSize()});

    // Create HEADERS frame
    const header_payload = ":method: GET\r\n:path: /api/users\r\n:authority: example.com\r\n";
    const headers_frame = Http2.Frame.headers(1, header_payload, false, true);
    std.log.info("HEADERS frame:", .{});
    std.log.info("  Stream ID: {}", .{headers_frame.header.stream_id});
    std.log.info("  Payload length: {}", .{headers_frame.header.length});
    std.log.info("  END_HEADERS: {}", .{headers_frame.header.flags.endHeaders()});

    // Create SETTINGS frame
    var settings_data: [12]u8 = undefined;
    std.mem.writeInt(u16, settings_data[0..2], @intFromEnum(Http2.SettingsId.max_frame_size), .big);
    std.mem.writeInt(u32, settings_data[2..6], 32768, .big);
    std.mem.writeInt(u16, settings_data[6..8], @intFromEnum(Http2.SettingsId.enable_push), .big);
    std.mem.writeInt(u32, settings_data[8..12], 0, .big);

    const settings_frame = Http2.Frame.settings(&settings_data, false);
    std.log.info("SETTINGS frame:", .{});
    std.log.info("  Stream ID: {}", .{settings_frame.header.stream_id});
    std.log.info("  Payload length: {}", .{settings_frame.header.length});
    std.log.info("  ACK: {}", .{settings_frame.header.flags.ack()});

    // Create PING frame
    const ping_data = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    const ping_frame = Http2.Frame.ping(ping_data, false);
    std.log.info("PING frame:", .{});
    std.log.info("  Payload length: {}", .{ping_frame.header.length});
    std.log.info("  ACK: {}", .{ping_frame.header.flags.ack()});

    // RST_STREAM frame
    const rst_frame = Http2.Frame.rstStream(1, .cancel);
    std.log.info("RST_STREAM frame:", .{});
    std.log.info("  Stream ID: {}", .{rst_frame.header.stream_id});
    std.log.info("  Error code: {s}", .{Http2.ErrorCode.cancel.toString()});

    // WINDOW_UPDATE frame
    const window_frame = Http2.Frame.windowUpdate(1, 65536);
    std.log.info("WINDOW_UPDATE frame:", .{});
    std.log.info("  Stream ID: {}", .{window_frame.header.stream_id});
    std.log.info("  Window size increment: {}", .{65536});

    // HPACK static table demonstration
    std.log.info("\n--- HPACK Static Table ---", .{});
    std.log.info("Static table entries (first 10):", .{});
    for (0..10) |i| {
        const entry = Http2.STATIC_TABLE[i];
        std.log.info("  {}: \"{s}\" = \"{s}\"", .{ i + 1, entry.name, entry.value });
    }

    // HTTP/2 connection demonstration
    std.log.info("\n--- HTTP/2 Connection Management ---", .{});
    var connection = Http2.Connection.init(allocator, true);
    defer connection.deinit();

    std.log.info("Server connection initialized:", .{});
    std.log.info("  Is server: {}", .{connection.is_server});
    std.log.info("  Next stream ID: {}", .{connection.next_stream_id});
    std.log.info("  Max frame size: {}", .{connection.settings.max_frame_size});
    std.log.info("  Initial window size: {}", .{connection.settings.initial_window_size});
    std.log.info("  Enable push: {}", .{connection.settings.enable_push});
    std.log.info("  Header table size: {}", .{connection.settings.header_table_size});

    // HTTP/2 stream demonstration  
    std.log.info("\n--- HTTP/2 Stream Management ---", .{});
    var stream = Http2.Stream.init(allocator, 1);
    defer stream.deinit();

    std.log.info("Stream created:", .{});
    std.log.info("  Stream ID: {}", .{stream.id});
    std.log.info("  State: {s}", .{@tagName(stream.state)});
    std.log.info("  Window size: {}", .{stream.window_size});
    std.log.info("  Headers count: {}", .{stream.headers.items.len});

    // HTTP/2 settings demonstration
    std.log.info("\n--- HTTP/2 Settings ---", .{});
    const default_settings = Http2.Settings.getDefaultSettings();
    std.log.info("Default settings:", .{});
    std.log.info("  Header table size: {}", .{default_settings.header_table_size});
    std.log.info("  Enable push: {}", .{default_settings.enable_push});
    std.log.info("  Initial window size: {}", .{default_settings.initial_window_size});
    std.log.info("  Max frame size: {}", .{default_settings.max_frame_size});
    if (default_settings.max_concurrent_streams) |max_streams| {
        std.log.info("  Max concurrent streams: {}", .{max_streams});
    } else {
        std.log.info("  Max concurrent streams: unlimited", .{});
    }

    // HTTP/2 connection preface
    std.log.info("\n--- HTTP/2 Connection Preface ---", .{});
    std.log.info("Connection preface: {s}", .{Http2.CONNECTION_PREFACE});

    // Performance benefits
    std.log.info("\n--- HTTP/2 Performance Benefits ---", .{});
    std.log.info("[OK] Binary framing for efficient parsing", .{});
    std.log.info("[OK] Request/response multiplexing", .{});
    std.log.info("[OK] HPACK header compression", .{});
    std.log.info("[OK] Server push capabilities", .{});
    std.log.info("[OK] Stream prioritization", .{});
    std.log.info("[OK] Flow control mechanisms", .{});
    
    std.log.info("\n=== HTTP/2 Demo Complete ===", .{});
}