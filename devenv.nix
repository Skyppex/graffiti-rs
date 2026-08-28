{
  pkgs,
  lib,
  config,
  inputs,
  ...
}: {
  env.LD_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [openssl];

  # https://devenv.sh/packages/
  packages = with pkgs; [
    tombi
    yaml-language-server
    pkg-config
    alejandra
    nixd
  ];

  languages.rust.enable = true;

  # https://devenv.sh/basics/
  enterShell = ''
    DIR="$(pwd)/result/bin"
    if test -e "$DIR"; then
        PATH="$DIR:$PATH"
    fi
  '';
}
