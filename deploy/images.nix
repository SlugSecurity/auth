{ pkgs }:
let
  portalUrl = "https://my.slugsec.club";

  native = import ../nix/kanidm-consent.nix {
    inherit pkgs portalUrl;
    uiVersion = brandingHash;
  };

  python = pkgs.python3.withPackages (p: [
    p.flask
    p.requests
    p.google-auth
    p.joserfc
    p.gunicorn
    p.qrcode
  ]);

  assets = ../service/branding/kanidm-1.11.2;
  nativeImageNames = [
    "favicon.png"
    "apple-touch-icon.png"
    "logo-180.png"
    "logo-192.png"
    "logo-256.png"
    "logo-512.png"
    "logo-square.svg"
    "logo.svg"
    "kani-waving.svg"
  ];

  script = pkgs.runCommand "identity-native-interface.js" { } ''
    mkdir -p branding/kanidm-1.11.2 enrollment-ui
    cp ${../service/branding_config.py} branding_config.py
    cp ${assets}/enrollment-notice.js branding/kanidm-1.11.2/
    cp ${../service/enrollment-ui/registration-notice.html} enrollment-ui/registration-notice.html
    ${pkgs.buildPackages.python3}/bin/python branding_config.py \
      ${pkgs.lib.escapeShellArg portalUrl} auth.slugsec.club > "$out"
  '';

  brandingHash = builtins.hashString "sha256" (
    builtins.readFile (assets + "/upstream-style.js")
    + builtins.readFile (assets + "/enrollment-notice.js")
    + builtins.readFile ../service/enrollment-ui/registration-notice.html
    + builtins.readFile ../service/branding_config.py
    + builtins.readFile ../service/enrollment-ui/style.css
    + builtins.readFile (assets + "/page-load.patch")
    + pkgs.lib.concatMapStrings (path: builtins.hashFile "sha256" path) (
      [
        ../service/branding/background.webp
        ../service/branding/slugsec-logo.png
      ]
      ++ map (name: assets + "/${name}") nativeImageNames
    )
  );

  server = native.image.override {
    name = "identity/kanidm";

    extraCommands = ''
      mkdir -p sbin data
      ln -s ${native.package}/bin/kanidmd sbin/kanidmd
      cp -r ${native.package}/ui/hpkg hpkg
      chmod -R u+w hpkg
      cp ${assets}/upstream-style.js hpkg/style.js
      cp ${script} hpkg/interface.js
      cat ${native.package}/ui/hpkg/style.css \
        ${../service/enrollment-ui/style.css} > hpkg/style.css
      : > hpkg/override.css
      cp ${../service/branding/background.webp} hpkg/background.webp
      for name in ${pkgs.lib.escapeShellArgs nativeImageNames}; do
        cp ${assets}/"$name" hpkg/img/"$name"
      done
    '';

    config = {
      Cmd = [
        "/sbin/kanidmd"
        "server"
      ];

      WorkingDir = "/data";
      Env = [
        "RUST_BACKTRACE=1"
        "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
      ];
      ExposedPorts."443/tcp" = { };

      Labels = {
        "com.kanidm.version" = native.package.version;
        "identity.consent-recipient.patch-sha256" = builtins.hashFile "sha256" (
          assets + "/consent-recipient.patch"
        );
        "identity.credential-conflict.patch-sha256" = builtins.hashFile "sha256" (
          assets + "/credential-conflict.patch"
        );
        "identity.page-load.patch-sha256" = builtins.hashFile "sha256" (assets + "/page-load.patch");
        "identity.usage-events.patch-sha256" = builtins.hashFile "sha256" (assets + "/usage-events.patch");
        "identity.usage-events.version" = "1";
        "identity.credential-update-compare.version" = "1";
        "identity.production.origin" = "https://auth.slugsec.club";
        "identity.production.branding-sha256" = brandingHash;
        "org.opencontainers.image.version" = native.package.version;
        "org.opencontainers.image.source" = "https://github.com/kanidm/kanidm";
        "org.opencontainers.image.revision" = "547933867e87da737e79d26942dc9261adaa5ee9";
        "org.opencontainers.image.licenses" = "MPL-2.0";
      };
    };
  };

  applicationFiles = [
    "service/access.py"
    "service/access_portal.py"
    "service/access_runtime.py"
    "service/backup.py"
    "service/branding_config.py"
    "service/contracts.py"
    "service/directory.py"
    "service/enrollment.py"
    "service/enrollment_google.py"
    "service/enrollment_kanidm.py"
    "service/membership.py"
    "service/membership_portal.py"
    "service/native_names.py"
    "service/observability.py"
    "service/usage.py"
    "service/unix_usage.py"
    "service/operations.py"
    "service/posix_defaults.py"
    "service/runtime_view.py"
    "service/enrollment-ui/flow.js"
    "service/enrollment-ui/page.html"
    "service/enrollment-ui/registration-notice.html"
    "service/enrollment-ui/style.css"
    "monitoring/dashboards/identity.json"
    "monitoring/dashboards/demographics.json"
    "monitoring/dashboards/usage.json"
    "monitoring/templates/directory.json"
    "monitoring/templates/referrals.json"
    "monitoring/templates/unix.json"
    "monitoring/provisioning/dashboards.yaml"
    "monitoring/provisioning/datasources.yaml"
    "monitoring/prometheus/alerts.yml"
    "monitoring/prometheus/prometheus.yml"
    "service/branding/background.webp"
    "service/branding/slugsec-logo.png"
    "service/branding/kanidm-1.11.2/LICENSE"
    "service/branding/kanidm-1.11.2/upstream-style.js"
    "service/branding/kanidm-1.11.2/enrollment-notice.js"
    "service/branding/kanidm-1.11.2/consent-recipient.patch"
    "service/branding/kanidm-1.11.2/credential-conflict.patch"
    "service/branding/kanidm-1.11.2/page-load.patch"
    "service/branding/kanidm-1.11.2/usage-events.patch"
    "deploy/bootstrap.py"
    "deploy/certificates.py"
    "deploy/launcher.py"
    "deploy/manage.py"
    "deploy/runtime.py"
    "deploy/oci/compose.yaml"
    "deploy/oci/runtime.json"
    "deploy/oci/server.toml"
  ]
  ++ map (name: "service/branding/kanidm-1.11.2/${name}") nativeImageNames;

  app = pkgs.runCommand "identity-portal-source" { } (
    pkgs.lib.concatMapStringsSep "\n" (relative: ''
      install -D -m 0644 ${../. + "/${relative}"} "$out/app/${relative}"
    '') applicationFiles
    + ''
      install -m 0644 ${pkgs.kanidm_1_11}/ui/hpkg/external/bootstrap.min.css "$out/app/service/enrollment-ui/bootstrap.min.css"
      install -m 0644 ${pkgs.kanidm_1_11}/ui/hpkg/external/bootstrap.bundle.min.js "$out/app/service/enrollment-ui/bootstrap.bundle.min.js"
      chmod +x "$out/app/deploy/launcher.py"
    ''
  );

  portal = pkgs.dockerTools.buildLayeredImage {
    name = "identity/enrollment";
    tag = "1.11.2";
    contents = [
      python
      pkgs.kanidm_1_11
      pkgs.cacert
      pkgs.tzdata
      app
    ];

    extraCommands = ''
      mkdir -p state observe tmp
      chmod 1777 tmp
    '';

    config = {
      Entrypoint = [
        "${python}/bin/python3"
        "/app/deploy/launcher.py"
      ];
      Cmd = [ "web" ];

      WorkingDir = "/app/deploy";
      Env = [
        "PATH=${python}/bin:${pkgs.kanidm_1_11}/bin:/bin"
        "PYTHONDONTWRITEBYTECODE=1"
        "PYTHONUNBUFFERED=1"
        "PYTHONTZPATH=${pkgs.tzdata}/share/zoneinfo"
        "IDENTITY_RUNTIME_CONFIG=/run/identity/runtime.json"
        "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
      ];
      ExposedPorts = {
        "443/tcp" = { };
        "9443/tcp" = { };
      };

      Labels = {
        "com.kanidm.version" = "1.11.2";
        "identity.production.origin" = "https://my.slugsec.club";
        "identity.credential-update-compare.version" = "1";
      };
    };
  };

in
{
  inherit server portal;
}
