{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/c639fb82ba5469120ef88ad7e81ab83a5a0e614a";

  outputs =
    { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      pythonRuntime = python: [
        python.flask
        python.requests
        python.google-auth
        python.joserfc
        python.gunicorn
        python.qrcode
      ];

      qualityPython = pkgs.python3.withPackages (
        python:
        pythonRuntime python
        ++ (with python; [
          hypothesis
          pytest
          mypy
          vulture
          bandit
          pylint
          radon
          coverage
          types-requests
          tomli
        ])
      );

      qualityTools = import ./nix/quality.nix {
        inherit pkgs;
        python = qualityPython;
      };

      qualityShell = pkgs.mkShell {
        IDENTITY_BOOTSTRAP_CSS = "${pkgs.kanidm_1_11}/ui/hpkg/external/bootstrap.min.css";
        IDENTITY_BOOTSTRAP_JS = "${pkgs.kanidm_1_11}/ui/hpkg/external/bootstrap.bundle.min.js";
        packages = [
          pkgs.kanidm_1_11
          pkgs.age
          pkgs.openssl
          pkgs.curl
          pkgs.ruff
          pkgs.pyright
          pkgs.nixfmt
          pkgs.deadnix
          pkgs.statix
          qualityPython
        ]
        ++ builtins.attrValues qualityTools;
      };

      productionPackages =
        target:
        let
          targetPkgs = import nixpkgs { system = target; };
          targetConsent = import ./nix/kanidm-consent.nix { pkgs = targetPkgs; };
          production = import ./deploy/images.nix { pkgs = targetPkgs; };
        in
        {
          kanidm = targetPkgs.kanidm_1_11;
          kanidm-consent = targetConsent.package;
          kanidm-consent-image = targetConsent.image;
          kanidm-production-image = production.server;
          enrollment-production-image = production.portal;
        };

      armCross = import ./deploy/images.nix { pkgs = pkgs.pkgsCross.aarch64-multiplatform; };
    in
    {
      nixosModules = {
        identity = import ./nix/identity.nix;
        monitoring = import ./nix/monitoring.nix;
      };

      formatter.${system} = qualityTools.format;

      checks.${system}.quality =
        pkgs.runCommand "identity-quality"
          {
            nativeBuildInputs = [
              qualityTools.check
              pkgs.gitMinimal
            ];
          }
          ''
            cp -r --no-preserve=mode ${./.} source
            cd source
            git init --quiet
            git add .
            check
            touch "$out"
          '';

      apps.${system} = builtins.mapAttrs (name: package: {
        type = "app";
        program = "${package}/bin/${name}";
      }) qualityTools;

      packages = {
        ${system} = productionPackages system // {
          kanidm-production-arm-cross-image = armCross.server;
          enrollment-production-arm-cross-image = armCross.portal;
        };
        aarch64-linux = productionPackages "aarch64-linux";
      };

      devShells.${system} = {
        default = qualityShell;
        quality = qualityShell;
      };
    };
}
