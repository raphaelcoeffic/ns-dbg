# `dive` - a container debugging tool

A powerful container debugging tool that injects a full-featured shell into
any container - even minimal distroless images - making debugging seamless and
powerful. No need to modify your containers or add debugging tools at build
time.

## Features

### Runtime Support
- 🐳 Docker
- 🦭 Podman
- 🐋 Nerdctl
- 🔧 systemd-nspawn

### Core Features
- Inject a complete shell environment into running containers
- Install additional debugging tools with the built-in [package manager](#package-tool)
- Works with any container, including minimal and distroless images
- Zero container modifications required
- No build-time dependencies

## Installation

### Installing from release binary

Download the latest release into `~/.local/bin`:
```bash
mkdir -p ~/.local/bin
curl -sL https://github.com/raphaelcoeffic/dive/releases/latest/download/dive-x86_64-unknown-linux-musl -o ~/.local/bin/dive
chmod +x ~/.local/bin/dive
```

### Building from source

Prerequisites:
- Rust toolchain (install via [rustup](https://rustup.rs/))

```bash
# Build the binary
cargo build --release

# Optional: Install system-wide
cargo install --path .

# Optional: Build x86_64 static binary
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-gnu-gcc
export CC=x86_64-linux-gnu-gcc
rustup target add x86_64-unknown-linux-musl
cargo build --target=x86_64-unknown-linux-musl

# Optional: Build arm64 static binary
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc
export CC=aarch64-linux-gnu-gcc
rustup target add aarch64-unknown-linux-musl
cargo build --target=aarch64-unknown-linux-musl
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

## Package Tool

Inside a `dive` session, you can add or remove packages:
```bash
# Add a package
pkg install iftop

# Or remove it
pkg remove iftop

# List installed packages
pkg list

# Search for packages
pkg search helix
```

## Contributing

Contributions are welcome! Feel free to open issues and pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Roadmap

### Short term
- 🗑️ Add a clean-up command to remove local files

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
