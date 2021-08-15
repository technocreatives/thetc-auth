let
  fenix = (import "${
      fetchTarball "https://github.com/nix-community/fenix/archive/main.tar.gz"
    }/packages.nix");
  pkgs = import <nixpkgs> {};
in
  pkgs.mkShell {
    buildInputs = [ fenix.stable.rustc fenix.stable.cargo fenix.stable.rustfmt-preview fenix.stable.rust-src fenix.stable.rust-std fenix.stable.clippy-preview ];
  }
