{
  description = "graffiti-rs is a graffiti server implementation handling communication between graffiti clients and other graffiti servers";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    naersk,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [rust-overlay.overlays.default];
      };

      toolchain = pkgs.rust-bin.stable.latest.default;

      naerskLib = (pkgs.callPackage naersk {}).override {
        cargo = toolchain;
        rustc = toolchain;
      };

      graffitiPackage = {release}:
        import ./default.nix {
          src = self;
          naersk = naerskLib;
          pkgConfig = pkgs.pkg-config;
          inherit release;
        };
      checks = import ./checks.nix {
        src = self;
        naersk = naerskLib;
        pkgs = pkgs;
      };
      apps = import ./apps.nix {
        pkgs = pkgs;
      };
    in {
      packages = rec {
        default = debug;
        debug = graffitiPackage {release = false;};
        release = graffitiPackage {release = true;};
      };

      devShells.default = pkgs.mkShell {
        packages = [toolchain];
        env.RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
      };

      checks = checks;

      apps = apps;

      formatter = pkgs.writeShellApplication {
        name = "fmt";
        runtimeInputs = [pkgs.rustfmt pkgs.cargo];
        text = "cargo fmt --all";
      };
    });
}
