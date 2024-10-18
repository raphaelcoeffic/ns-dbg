# Container Debug Shell

Requirement:
- base image from [here](https://github.com/raphaelcoeffic/ns-dbg-img)
- a Rust toolchain (use [rustup](https://rustup.rs/))

Setup the base image:
```
mkdir -p ./base
tar xf base.tar.xz --directory=./base
```

Compile with:
```
cargo build
```

And run with:
```
sudo ./target/debug/ns-dbg -i ./base [container lead PID]
```

## Kudos

- [Mounting into mount namespaces](https://people.kernel.org/brauner/mounting-into-mount-namespaces)
- [Docker: How To Debug Distroless And Slim Containers](https://iximiuz.com/en/posts/docker-debug-slim-containers/)
- [Orbstack Debug](https://orbstack.dev/blog/debug-shell)
