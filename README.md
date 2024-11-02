# `dive` - a container debugging tool

A powerful container debugging tool that injects a full-featured shell into
any container - even minimal distroless images - making debugging seamless and
powerful. No need to modify your containers or add debugging tools at build
time.

## Features
- Inject a complete shell environment into running containers
- Works with any container, including minimal and distroless images
- Zero container modifications required
- No build-time dependencies

## Installation

### Prerequisites
- Rust toolchain (install via [rustup](https://rustup.rs/))

### Building from source

```bash
# Build the binary
cargo build --release

# Optional: Install system-wide
cargo install --path .
```

## Usage

```bash
# Debug a running container
dive <container-name>

# Or run directly through cargo
cargo run <container-name>
```

## Examples

```bash
# Debug a distroless container
dive my-distroless-app

# Debug a specific container by ID
dive 7d3f2c1b9e4a
```

## Contributing

Contributions are welcome! Feel free to open issues and pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Roadmap

### Short term
- 🔧 Add package manager for easy installation of additional debugging tools
- 📦 Provide static builds for easier distribution
- 🔄 Embed base image for offline debugging capabilities

### Coming later
- 🐳 Support for more container runtimes
- 🔍 Enhanced inspection tools
- ⚡ Performance optimizations

Want to contribute to any of these features? Check out our [Contributing](#contributing) section!

## Acknowledgments

This project was inspired by and builds upon ideas from:
- Christian Brauner's article on [Mounting into mount namespaces](https://people.kernel.org/brauner/mounting-into-mount-namespaces)
- Ivan Velichko's guide on [Docker: How To Debug Distroless And Slim Containers](https://iximiuz.com/en/posts/docker-debug-slim-containers/)
- The [Orbstack Debug](https://orbstack.dev/blog/debug-shell) feature and its approach to container debugging
