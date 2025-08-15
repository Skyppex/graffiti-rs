{ src, naerskLib, pkg-config }:

naerskLib.buildPackage {
  name = "graffiti-rs";
  src = src;
  nativeBuildInputs = [ pkg-config ];
}
