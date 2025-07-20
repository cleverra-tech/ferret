//! High-performance I/O reactor and event loop for Ferret
//!
//! This implementation provides:
//! - Epoll-based event loop on Linux
//! - Edge-triggered mode for maximum performance
//! - Type-safe event handling with Zig generics
//! - Memory-efficient event storage
//! - Timeout support for periodic tasks
//! - Signal-safe operation

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;
const AutoHashMap = std.AutoHashMap;

/// Event types that can be monitored
pub const EventType = struct {
    read: bool = false,
    write: bool = false,
    err: bool = false,
    hangup: bool = false,
    edge_triggered: bool = true,
    oneshot: bool = false,

    pub fn toEpollEvents(self: EventType) u32 {
        var events: u32 = 0;
        if (self.read) events |= linux.EPOLL.IN;
        if (self.write) events |= linux.EPOLL.OUT;
        if (self.err) events |= linux.EPOLL.ERR;
        if (self.hangup) events |= linux.EPOLL.HUP;
        if (self.edge_triggered) events |= linux.EPOLL.ET;
        if (self.oneshot) events |= linux.EPOLL.ONESHOT;
        return events;
    }

    pub fn fromEpollEvents(events: u32) EventType {
        return EventType{
            .read = (events & linux.EPOLL.IN) != 0,
            .write = (events & linux.EPOLL.OUT) != 0,
            .err = (events & linux.EPOLL.ERR) != 0,
            .hangup = (events & linux.EPOLL.HUP) != 0,
            .edge_triggered = (events & linux.EPOLL.ET) != 0,
            .oneshot = (events & linux.EPOLL.ONESHOT) != 0,
        };
    }
};

/// Event data passed to callbacks
pub const Event = struct {
    fd: posix.fd_t,
    events: EventType,
    data: ?*anyopaque = null,
};

/// Reactor errors
pub const ReactorError = error{
    EpollCreateFailed,
    EpollCtlFailed,
    EpollWaitFailed,
    TimerCreateFailed,
    InvalidFileDescriptor,
    OutOfMemory,
    SystemError,
};

/// Event handler callback type
pub const EventHandler = *const fn (event: Event) void;

/// Timer callback type
pub const TimerHandler = *const fn (data: ?*anyopaque) void;

/// Timer entry
const Timer = struct {
    id: u64,
    deadline: i64, // nanoseconds since epoch
    interval: ?u64 = null, // nanoseconds, null for one-shot
    handler: TimerHandler,
    data: ?*anyopaque = null,
};

/// File descriptor registration
const FdRegistration = struct {
    events: EventType,
    handler: EventHandler,
    data: ?*anyopaque = null,
};

/// High-performance I/O reactor using epoll
pub const Reactor = struct {
    allocator: Allocator,
    epoll_fd: posix.fd_t,
    registrations: AutoHashMap(posix.fd_t, FdRegistration),
    timers: ArrayList(Timer),
    next_timer_id: u64,
    running: bool,
    max_events: u32,
    event_buffer: []linux.epoll_event,

    const Self = @This();
    const DEFAULT_MAX_EVENTS = 1024;

    /// Initialize reactor with default settings
    pub fn init(allocator: Allocator) ReactorError!Self {
        return initWithCapacity(allocator, DEFAULT_MAX_EVENTS);
    }

    /// Initialize reactor with specific event capacity
    pub fn initWithCapacity(allocator: Allocator, max_events: u32) ReactorError!Self {
        // Create epoll instance
        const epoll_fd = std.posix.epoll_create1(std.os.linux.EPOLL.CLOEXEC) catch |err| switch (err) {
            error.SystemResources => return ReactorError.EpollCreateFailed,
            else => return ReactorError.SystemError,
        };
        errdefer posix.close(epoll_fd);

        // Allocate event buffer
        const event_buffer = allocator.alloc(linux.epoll_event, max_events) catch {
            return ReactorError.OutOfMemory;
        };
        errdefer allocator.free(event_buffer);

        return Self{
            .allocator = allocator,
            .epoll_fd = epoll_fd,
            .registrations = AutoHashMap(posix.fd_t, FdRegistration).init(allocator),
            .timers = ArrayList(Timer).init(allocator),
            .next_timer_id = 1,
            .running = false,
            .max_events = max_events,
            .event_buffer = event_buffer,
        };
    }

    /// Clean up reactor resources
    pub fn deinit(self: *Self) void {
        self.stop();
        self.registrations.deinit();
        self.timers.deinit();
        self.allocator.free(self.event_buffer);
        posix.close(self.epoll_fd);
    }

    /// Register file descriptor for events
    pub fn register(self: *Self, fd: posix.fd_t, events: EventType, handler: EventHandler, data: ?*anyopaque) ReactorError!void {
        // Create epoll event
        var epoll_event = linux.epoll_event{
            .events = events.toEpollEvents(),
            .data = linux.epoll_data{ .fd = fd },
        };

        // Add to epoll
        std.posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, fd, &epoll_event) catch |err| switch (err) {
            error.FileDescriptorAlreadyPresentInSet => {
                // File descriptor already registered, modify instead
                return self.modify(fd, events, handler, data);
            },
            error.FileDescriptorNotRegistered => return ReactorError.InvalidFileDescriptor,
            error.SystemResources => return ReactorError.EpollCtlFailed,
            else => return ReactorError.SystemError,
        };

        // Store registration
        try self.registrations.put(fd, FdRegistration{
            .events = events,
            .handler = handler,
            .data = data,
        });
    }

    /// Modify existing file descriptor registration
    pub fn modify(self: *Self, fd: posix.fd_t, events: EventType, handler: EventHandler, data: ?*anyopaque) ReactorError!void {
        // Update epoll event
        var epoll_event = linux.epoll_event{
            .events = events.toEpollEvents(),
            .data = linux.epoll_data{ .fd = fd },
        };

        std.posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_MOD, fd, &epoll_event) catch |err| switch (err) {
            error.FileDescriptorNotRegistered => return ReactorError.InvalidFileDescriptor,
            error.SystemResources => return ReactorError.EpollCtlFailed,
            else => return ReactorError.SystemError,
        };

        // Update registration
        try self.registrations.put(fd, FdRegistration{
            .events = events,
            .handler = handler,
            .data = data,
        });
    }

    /// Unregister file descriptor
    pub fn unregister(self: *Self, fd: posix.fd_t) ReactorError!void {
        // Remove from epoll
        std.posix.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, fd, null) catch |err| switch (err) {
            error.FileDescriptorNotRegistered => {}, // Already removed, ignore
            else => return ReactorError.SystemError,
        };

        // Remove registration
        _ = self.registrations.remove(fd);
    }

    /// Add timer
    pub fn addTimer(self: *Self, delay_ns: u64, handler: TimerHandler, data: ?*anyopaque) ReactorError!u64 {
        const now = @as(i64, @intCast(@min(@as(i128, @intCast(std.time.nanoTimestamp())), @as(i128, std.math.maxInt(i64)))));
        const timer_id = self.next_timer_id;
        self.next_timer_id += 1;

        const timer = Timer{
            .id = timer_id,
            .deadline = now + @as(i64, @intCast(@min(delay_ns, std.math.maxInt(i64)))),
            .handler = handler,
            .data = data,
        };

        try self.timers.append(timer);
        self.sortTimers();
        return timer_id;
    }

    /// Add repeating timer
    pub fn addRepeatingTimer(self: *Self, interval_ns: u64, handler: TimerHandler, data: ?*anyopaque) ReactorError!u64 {
        const now = @as(i64, @intCast(@min(@as(i128, @intCast(std.time.nanoTimestamp())), @as(i128, std.math.maxInt(i64)))));
        const timer_id = self.next_timer_id;
        self.next_timer_id += 1;

        const timer = Timer{
            .id = timer_id,
            .deadline = now + @as(i64, @intCast(@min(interval_ns, std.math.maxInt(i64)))),
            .interval = interval_ns,
            .handler = handler,
            .data = data,
        };

        try self.timers.append(timer);
        self.sortTimers();
        return timer_id;
    }

    /// Cancel timer
    pub fn cancelTimer(self: *Self, timer_id: u64) bool {
        for (self.timers.items, 0..) |timer, i| {
            if (timer.id == timer_id) {
                _ = self.timers.swapRemove(i);
                self.sortTimers();
                return true;
            }
        }
        return false;
    }

    /// Start event loop
    pub fn run(self: *Self) ReactorError!void {
        self.running = true;
        while (self.running) {
            try self.poll();
        }
    }

    /// Stop event loop
    pub fn stop(self: *Self) void {
        self.running = false;
    }

    /// Single poll iteration
    pub fn poll(self: *Self) ReactorError!void {
        const timeout_ms = self.calculateTimeout();

        // Wait for events
        const num_events = std.posix.epoll_wait(self.epoll_fd, self.event_buffer[0..self.max_events], timeout_ms);

        // Process timer events
        try self.processTimers();

        // Process I/O events
        for (self.event_buffer[0..num_events]) |epoll_event| {
            const fd = epoll_event.data.fd;
            const events = EventType.fromEpollEvents(epoll_event.events);

            if (self.registrations.get(fd)) |registration| {
                const event = Event{
                    .fd = fd,
                    .events = events,
                    .data = registration.data,
                };
                registration.handler(event);
            }
        }
    }

    /// Get number of registered file descriptors
    pub fn getRegistrationCount(self: *const Self) u32 {
        return @intCast(self.registrations.count());
    }

    /// Get number of active timers
    pub fn getTimerCount(self: *const Self) u32 {
        return @intCast(self.timers.items.len);
    }

    /// Check if reactor is running
    pub fn isRunning(self: *const Self) bool {
        return self.running;
    }

    // Private helper methods

    fn calculateTimeout(self: *const Self) i32 {
        if (self.timers.items.len == 0) {
            return -1; // Block indefinitely
        }

        const now = @as(i64, @intCast(@min(@as(i128, @intCast(std.time.nanoTimestamp())), @as(i128, std.math.maxInt(i64)))));
        const next_deadline = self.timers.items[0].deadline;
        const timeout_ns = next_deadline - now;

        if (timeout_ns <= 0) {
            return 0; // Immediate timeout
        }

        const timeout_ms = @divTrunc(timeout_ns, std.time.ns_per_ms);
        return @intCast(@min(timeout_ms, std.math.maxInt(i32)));
    }

    fn processTimers(self: *Self) ReactorError!void {
        const now = @as(i64, @intCast(@min(@as(i128, @intCast(std.time.nanoTimestamp())), @as(i128, std.math.maxInt(i64)))));
        var i: usize = 0;

        while (i < self.timers.items.len) {
            const timer = &self.timers.items[i];
            if (timer.deadline > now) {
                break; // No more expired timers
            }

            // Execute timer
            timer.handler(timer.data);

            // Handle repeating timer
            if (timer.interval) |interval| {
                timer.deadline = now + @as(i64, @intCast(@min(interval, std.math.maxInt(i64))));
                i += 1;
            } else {
                // Remove one-shot timer
                _ = self.timers.swapRemove(i);
                // Don't increment i, as we just moved a different timer to this position
            }
        }

        // Re-sort timers if any were updated
        if (i > 0) {
            self.sortTimers();
        }
    }

    fn sortTimers(self: *Self) void {
        std.mem.sort(Timer, self.timers.items, {}, struct {
            fn lessThan(_: void, a: Timer, b: Timer) bool {
                return a.deadline < b.deadline;
            }
        }.lessThan);
    }
};

// Tests
test "Reactor - initialization and cleanup" {
    const allocator = std.testing.allocator;

    var reactor = try Reactor.init(allocator);
    defer reactor.deinit();

    try std.testing.expect(reactor.getRegistrationCount() == 0);
    try std.testing.expect(reactor.getTimerCount() == 0);
    try std.testing.expect(!reactor.isRunning());
}

test "Reactor - event type conversion" {
    const event_type = EventType{
        .read = true,
        .write = true,
        .edge_triggered = true,
    };

    const epoll_events = event_type.toEpollEvents();
    try std.testing.expect((epoll_events & linux.EPOLL.IN) != 0);
    try std.testing.expect((epoll_events & linux.EPOLL.OUT) != 0);
    try std.testing.expect((epoll_events & linux.EPOLL.ET) != 0);

    const converted_back = EventType.fromEpollEvents(epoll_events);
    try std.testing.expect(converted_back.read);
    try std.testing.expect(converted_back.write);
    try std.testing.expect(converted_back.edge_triggered);
}

test "Reactor - timer management" {
    const allocator = std.testing.allocator;

    var reactor = try Reactor.init(allocator);
    defer reactor.deinit();

    var called = false;
    const handler = struct {
        fn callback(data: ?*anyopaque) void {
            const ptr: *bool = @ptrCast(@alignCast(data.?));
            ptr.* = true;
        }
    }.callback;

    // Add timer
    const timer_id = try reactor.addTimer(1000000, handler, &called); // 1ms
    try std.testing.expect(reactor.getTimerCount() == 1);

    // Cancel timer
    try std.testing.expect(reactor.cancelTimer(timer_id));
    try std.testing.expect(reactor.getTimerCount() == 0);
    try std.testing.expect(!reactor.cancelTimer(timer_id)); // Already cancelled
}

test "Reactor - pipe registration and events" {
    const allocator = std.testing.allocator;

    var reactor = try Reactor.init(allocator);
    defer reactor.deinit();

    // Create pipe for testing
    const pipe_fds = try posix.pipe();
    defer posix.close(pipe_fds[0]);
    defer posix.close(pipe_fds[1]);

    // Make read end non-blocking
    const flags = try posix.fcntl(pipe_fds[0], posix.F.GETFL, 0);
    _ = try posix.fcntl(pipe_fds[0], posix.F.SETFL, flags | @as(u32, 0o4000)); // O_NONBLOCK

    var events_received: u32 = 0;
    const handler = struct {
        fn callback(event: Event) void {
            const ptr: *u32 = @ptrCast(@alignCast(event.data.?));
            ptr.* += 1;
        }
    }.callback;

    // Register read end
    try reactor.register(pipe_fds[0], EventType{ .read = true }, handler, &events_received);
    try std.testing.expect(reactor.getRegistrationCount() == 1);

    // Write data to trigger event
    _ = try posix.write(pipe_fds[1], "test");

    // Poll once to process the event
    try reactor.poll();

    // Should have received one event
    try std.testing.expect(events_received == 1);

    // Unregister
    try reactor.unregister(pipe_fds[0]);
    try std.testing.expect(reactor.getRegistrationCount() == 0);
}
