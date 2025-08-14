{ naerskLib, pkg-config }:

naerskLib.buildPackage {
  name = "graffiti-rs";
  src = ./.;
  nativeBuildInputs = [ pkg-config ];
}
