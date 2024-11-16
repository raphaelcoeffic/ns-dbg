{
  description = "A debug shell";
  inputs = {
    nixpkgs.url = "flake:nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
      flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; };
      in with pkgs; {
        packages = {
          default = pkgs.buildEnv {
            name = "debug-shell";
            paths = with pkgs; [
              bash
              cacert
              coreutils
              curl
              diffutils
              dig
              findutils
              # fzf + zsh plugin
              gnugrep
              gnused
              gnutar
              gzip
              helix
              htop
              iproute2
              iputils
              jq
              kitty.terminfo
              less
              lsof
              man
              nano
              netcat-openbsd
              procps
              sngrep
              sqlite
              strace
              tcpdump
              util-linux
              vim
              xz
              zsh
              zsh-prezto
              zsh-autosuggestions
              zsh-completions
              zsh-fast-syntax-highlighting
            ];
          };
        };
      }
    );
}
