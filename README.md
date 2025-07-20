# Ferret: A Zig Web Framework

Ferret is a high-performance web framework for Zig. It provides memory-safe, type-safe networking and web application capabilities with Zig's unique strengths.

## Project Status

Ferret is currently in early development. The following components have been implemented:

### Completed Components

#### Core Foundation
- **Memory Management**: Custom allocators including pool, tracking, arena, and fixed buffer allocators
- **Type System**: Generic types including `Ref<T>`, `Optional<T>`, `Result<T,E>`, and `Slice<T>`
- **Atomic Operations**: Lock-free primitives, spinlocks, RW locks, and atomic queues
- **Time Utilities**: High-precision timestamps, durations, timers, timeouts, and rate limiters

#### Data Structures
- **Array<T>**: Dynamic arrays with automatic resizing and comprehensive operations
- **HashMap<K,V>**: High-performance hash maps using robin hood hashing
- **String**: Binary-safe strings with efficient operations and formatting support

### Architecture Highlights

- **Explicit Memory Management**: All APIs require explicit allocator parameters
- **Compile-time Code Generation**: Leverages Zig's `comptime` for type-safe generics
- **Zero-Cost Abstractions**: Performance-critical code optimized at compile time
- **Error Handling**: Comprehensive error types with clear propagation
- **Cross-platform Compatibility**: Built on Zig's target system

### Project Structure

```
src/
├── core/              # Foundation modules
│   ├── allocator.zig  # Memory management utilities
│   ├── atomic.zig     # Atomic operations and synchronization
│   ├── time.zig       # High-precision timing utilities
│   └── types.zig      # Core type definitions
├── collections/       # Data structures
│   ├── array.zig      # Dynamic arrays
│   ├── hashmap.zig    # Hash maps
│   └── string.zig     # Binary-safe strings
├── io/                # I/O and networking (planned)
├── protocols/         # HTTP, WebSocket, JSON (planned)
├── crypto/            # Cryptographic functions (planned)
└── cli/               # Command-line utilities (planned)
```

### Testing

All implemented components have comprehensive test suites:

```bash
zig test src/ferret.zig
```

**Test Results**: 34/34 tests passing

### Roadmap

#### Next Phase (Medium Priority)
- [ ] I/O Reactor and Event Loop System
- [ ] HTTP/1.1 Parser and WebSocket Support  
- [ ] High-Performance JSON Parser and Generator
- [ ] Comprehensive Testing Suite and Benchmarks

#### Future (Low Priority)
- [ ] Cryptographic Functions (Hashing, Encryption)
- [ ] CLI Argument Parsing Framework
- [ ] Example Applications
- [ ] Complete Documentation and API Reference

### Design Philosophy

Ferret follows these core principles:

1. **Zig-First Design**: Leverages Zig's unique features rather than porting C patterns
2. **Performance Focus**: Zero-cost abstractions with compile-time optimizations
3. **Memory Safety**: Explicit allocator management with leak detection
4. **Developer Experience**: Type-safe APIs with clear error handling

### Contributing

This project is in early development. The foundation is solid and ready for the next phase of implementation.

### License

This project follows standard open source practices.

---

**Note**: This is a development version. The API may change as the project evolves.