{
  description = "A debug shell";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/347cbac9859f2023856b6e595570adb72e5c3f69";
    flake-utils.url = "github:numtide/flake-utils/c1dfcf08411b08f6b8615f7d8971a2bfa81d5e8a";
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
