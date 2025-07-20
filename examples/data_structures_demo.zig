//! Demonstration of Ferret's data structures
//! 
//! This example shows how to use the Array, HashMap, and String
//! data structures implemented in Ferret.

const std = @import("std");
const ferret = @import("ferret");

// Use Ferret data structures
const Array = ferret.Array;
const HashMap = ferret.HashMap;
const String = ferret.String;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Ferret Data Structures Demo ===");

    // Array demonstration
    try demonstrateArray(allocator);
    
    // HashMap demonstration  
    try demonstrateHashMap(allocator);
    
    // String demonstration
    try demonstrateString(allocator);

    std.log.info("=== Demo completed successfully! ===");
}

fn demonstrateArray(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Array Demo ---");
    
    var numbers = Array(i32).init(allocator);
    defer numbers.deinit();
    
    // Add some numbers
    try numbers.append(10);
    try numbers.append(20);
    try numbers.append(30);
    
    std.log.info("Array length: {}", .{numbers.len()});
    std.log.info("First element: {}", .{numbers.first().?});
    std.log.info("Last element: {}", .{numbers.last().?});
    
    // Insert in the middle
    try numbers.insert(1, 15);
    std.log.info("After inserting 15 at index 1:");
    for (numbers.slice(), 0..) |num, i| {
        std.log.info("  [{}]: {}", .{ i, num });
    }
    
    // Sort the array
    numbers.sort(struct {
        fn lessThan(a: i32, b: i32) bool {
            return a < b;
        }
    }.lessThan);
    
    std.log.info("After sorting:");
    for (numbers.slice(), 0..) |num, i| {
        std.log.info("  [{}]: {}", .{ i, num });
    }
}

fn demonstrateHashMap(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- HashMap Demo ---");
    
    var ages = HashMap([]const u8, u32).init(allocator);
    defer ages.deinit();
    
    // Add some key-value pairs
    try ages.put("Alice", 30);
    try ages.put("Bob", 25);
    try ages.put("Charlie", 35);
    
    std.log.info("HashMap size: {}", .{ages.len()});
    
    // Lookup values
    if (ages.get("Alice")) |age| {
        std.log.info("Alice is {} years old", .{age});
    }
    
    if (ages.get("David")) |age| {
        std.log.info("David is {} years old", .{age});
    } else {
        std.log.info("David not found in the map");
    }
    
    // Iterate over all entries
    std.log.info("All entries:");
    var iter = ages.iterator();
    while (iter.next()) |entry| {
        std.log.info("  {s}: {}", .{ entry.key, entry.value });
    }
    
    // Update a value
    try ages.put("Alice", 31);
    std.log.info("Updated Alice's age to: {}", .{ages.get("Alice").?});
}

fn demonstrateString(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- String Demo ---");
    
    var message = String.init(allocator);
    defer message.deinit();
    
    // Build a string
    try message.appendSlice("Hello");
    try message.append(' ');
    try message.appendSlice("World!");
    
    std.log.info("Built string: '{s}'", .{message.slice()});
    std.log.info("String length: {}", .{message.length()});
    
    // Use formatting
    var formatted = String.init(allocator);
    defer formatted.deinit();
    
    try formatted.print("The answer is {} and pi is approximately {d:.2}", .{ 42, 3.14159 });
    std.log.info("Formatted string: '{s}'", .{formatted.slice()});
    
    // String manipulation
    var text = try String.initFromSlice(allocator, "Hello Zig World");
    defer text.deinit();
    
    std.log.info("Original: '{s}'", .{text.slice()});
    
    if (text.find("Zig")) |pos| {
        std.log.info("Found 'Zig' at position: {}", .{pos});
    }
    
    try text.replace("Zig", "Ferret");
    std.log.info("After replacement: '{s}'", .{text.slice()});
    
    text.toUpper();
    std.log.info("Uppercase: '{s}'", .{text.slice()});
}