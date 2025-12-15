{
  description = "graffiti-rs is a graffiti server implementation handling communication between graffiti clients and other graffiti servers";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    naersk,
    fenix,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
      };

      fenixLib = fenix.packages.${system};
      toolchain = with fenixLib;
        combine [
          (stable.withComponents [
            "rustc"
            "cargo"
            "rustfmt"
            "clippy"
            "rust-src"
            "rust-docs"
            "rust-std"
            "rust-analyzer"
          ])
        ];

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
        packages = with pkgs; [
          toolchain
          alejandra
          nil
        ];
        env.RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
        LD_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [openssl];
        shellHook = ''
          DIR="$(pwd)/result/bin"
          if test -e "$DIR"; then
              PATH="$DIR:$PATH"
          fi
        '';
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
