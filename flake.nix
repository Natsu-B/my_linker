{
  description = "Development shell for my_linker integration tests";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          cargo
          rustc
          rustfmt
          binutils
          gcc
        ];

        # Static glibc pieces live in separate store paths; expose them so
        # tests can pass full paths to my_linker (which has no -L/-l support).
        # glibc.static is deliberately not in `packages`: that would inject it
        # into NIX_LDFLAGS and break cargo's host builds.
        GLIBC_STATIC_LIB_DIR = "${pkgs.glibc.static}/lib";
        GLIBC_CRT_DIR = "${pkgs.glibc}/lib";
        GLIBC_INCLUDE_DIR = "${pkgs.glibc.dev}/include";

        shellHook = ''
          export LIBGCC_DIR="$(dirname "$(gcc -print-libgcc-file-name)")"
        '';
      };
    };
}
