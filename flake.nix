{
  description = "cplt";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    inputs.flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [ (import inputs.rust-overlay) ];
        };
        inherit (pkgs) lib;
        cargoToml = lib.fromTOML (lib.readFile ./Cargo.toml);

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "clippy"
            "rust-analyzer"
            "rust-src"
            "rustfmt"
          ];
        };

        cplt =
          let
            rustPlatform = pkgs.makeRustPlatform {
              cargo = rustToolchain;
              rustc = rustToolchain;
            };
          in
          rustPlatform.buildRustPackage {
            pname = cargoToml.package.name;
            version = "${cargoToml.package.version}-${
              if lib.hasAttr "rev" inputs.self then
                "${lib.toString inputs.self.revCount}-${inputs.self.shortRev}"
              else
                "gitDirty"
            }";

            src = lib.cleanSource ./.;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "--bin"
              "cplt"
            ];

            nativeBuildInputs = [ pkgs.makeWrapper ];
            nativeCheckInputs = with pkgs; [
              coreutils
              git
              which
            ];

            postInstall = ''
              wrapProgram $out/bin/cplt --suffix PATH : ${lib.makeBinPath [ pkgs.git ]}
            '';

            meta = {
              description = cargoToml.package.description;
              homepage = "https://github.com/navikt/cplt";
              license = lib.licenses.mit;
              mainProgram = "cplt";
              platforms = lib.platforms.darwin ++ lib.platforms.linux;
            };
          };
      in
      {
        checks = { inherit cplt; };
        devShells.default = pkgs.mkShell {
          inputsFrom = [ cplt ];
          packages = with pkgs; [
            cargo-nextest
            cargo-watch
          ];
        };
        packages = rec {
          inherit cplt;
          default = cplt;
        };
      }
    );
}
