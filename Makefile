#
# Helper Makefile to build base image
#
# - local build / debug:
#    make base-image
#
# - release packaging:
#    make base-image package=yes compress=yes build_profile=release
#
# - cross build:
#    make base-image build_arch={aarch64 | x86_64}
#
# When building without packaging, dive can then be run with:
#    dive -i nix/ [container name]
#

native_arch = $(shell uname -m)

# aarch64 | x86_64
build_arch ?= $(native_arch)

# debug | release
build_profile ?= debug

# yes | no
package ?= no

# yes | no
compress ?= no

cargo_target ?= $(build_arch)-unknown-linux-musl

ifeq ($(build_profile),debug)
	cargo_profile = dev
else ifeq ($(build_profile),release)
    cargo_profile = release
else
	$(error unknown cargo build profile "$(build_profile)")
endif

pkg_bin = target/$(cargo_target)/$(build_profile)/pkg

build_img = cargo run --bin build-img --
build_img_args = -a $(build_arch) -b $(pkg_bin)

ifeq ($(package),no)
	build_img_args += -p nix --unpackaged
else ifeq ($(compress),no)
	build_img_args += --uncompressed
endif

cargo_build = cargo build --profile $(cargo_profile) --target $(cargo_target)

.PHONY: clean dist-clean base-image pkg-bin $(pkg_bin)

base_files = base.sha256 base.tar base.tar.xz

clean:
	@echo "Removing base files"
	@rm -f $(base_files)
	@echo "Removing nix directory"
	@chmod -R +w nix/* 2>/dev/null ; rm -rf ./nix

dist-clean: clean
	@echo "Removing rust builds"
	@rm -rf target

base-image: pkg-bin
	@echo "Building base image"
	$(build_img) $(build_img_args)

pkg-bin: $(pkg_bin)

$(pkg_bin):
	@echo "Building pkg tool"
	$(cargo_build) --bin pkg
	@echo "Stripping debug info"
	strip $@
