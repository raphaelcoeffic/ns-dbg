{
  description = "{{ description }}";
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
            name = "{{ name }}";
            paths = with pkgs; [ {{ packages }} ];
          };
        };
      }
    );
}
