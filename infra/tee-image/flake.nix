{
  description = "Reproducible TEE image for the Ultimate Private LLM Layer.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable."1.78.0".default.override {
          extensions = [ "rustfmt" "clippy" ];
          targets = [ "x86_64-unknown-linux-gnu" "wasm32-unknown-unknown" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
        src = craneLib.cleanCargoSource ../..;

        commonArgs = {
          inherit src;
          pname = "ullm-tee";
          version = "0.2.0-rc1";
          buildInputs = with pkgs; [ openssl pkg-config nasm ];
          nativeBuildInputs = with pkgs; [ pkg-config ];

          # Bit-reproducibility: clamp SOURCE_DATE_EPOCH and disable network access.
          CARGO_NET_OFFLINE = "true";
          SOURCE_DATE_EPOCH = "1715000000"; # 2024-05-06; bump per release
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        ullmTee = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          cargoExtraArgs = "-p ullm-tee --bin ullm-tee --release";
        });

        ullmGateway = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          cargoExtraArgs = "-p ullm-gateway --bin ullm-gateway --release";
        });

        # OCI image targeted at Confidential VMs. Pin every component for
        # reproducibility. The image's MRTD is the SHA-256 over the entire
        # contents — recorded in `manifest.json` at the workspace root.
        teeImage = pkgs.dockerTools.buildLayeredImage {
          name = "ullm-tee";
          tag = "0.2.0-rc1";
          contents = [
            ullmTee
            ullmGateway
            pkgs.cacert
          ];
          config = {
            Entrypoint = [ "${ullmTee}/bin/ullm-tee" ];
            ExposedPorts = { "9001/tcp" = { }; };
            # P9-FIX-C: only the protocol port (9001) is exposed to the
            # container network — the gateway dials it via the
            # confidential-VM-internal interface. `/metrics` lives on
            # `ULLM_TEE_METRICS_ADDR` (default `127.0.0.1:9101`), which
            # is intentionally NOT in `ExposedPorts` so a misconfigured
            # docker-run/k8s-svc can't surface operator-internal gauges
            # to the public network.
            Env = [
              "ULLM_TEE_ADDR=0.0.0.0:9001"
              "ULLM_TEE_METRICS_ADDR=127.0.0.1:9101"
              "RUST_LOG=ullm_tee=info"
            ];
            Labels = {
              "org.ullm.flake.rev" = self.rev or "dirty";
              "org.ullm.flake.lastModified" = toString (self.lastModified or 0);
            };
          };
        };
      in {
        packages = {
          default = ullmTee;
          ullm-tee = ullmTee;
          ullm-gateway = ullmGateway;
          tee-image = teeImage;
        };

        apps.default = flake-utils.lib.mkApp { drv = ullmTee; };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            pkg-config
            openssl
            nasm
            git
          ];
        };
      });
}
