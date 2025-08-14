{
  description = "Flake for developing graffiti-rs";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
  };

  outputs = { nixpkgs, flake-utils, naersk, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # system = "x86_64-linux";
        pkgs = import nixpkgs { inherit system; };
        naerskLib = pkgs.callPackage naersk { };
      in {
        # packages.default = arcanaPackage;
        packages.default = pkgs.callPackage ./default.nix {
          naerskLib = naerskLib;
          pkg-config = pkgs.pkg-config;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ cargo rustc rustfmt clippy ];
          env.RUST_SRC_PATH =
            "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
        };
      });
}
