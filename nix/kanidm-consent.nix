{
  pkgs,
  container ? true,
  uiVersion ? null,
  portalUrl ? "https://my.slugsec.club",
}:
assert pkgs.kanidm_1_11.version == "1.11.2";
let
  consentPatch = ../service/branding/kanidm-1.11.2/consent-recipient.patch;
  credentialPatch = ../service/branding/kanidm-1.11.2/credential-conflict.patch;
  pageLoadPatch = ../service/branding/kanidm-1.11.2/page-load.patch;
  usageEventsPatch = ../service/branding/kanidm-1.11.2/usage-events.patch;
  themeScript = ../service/branding/kanidm-1.11.2/upstream-style.js;
  genericUiVersion = builtins.hashString "sha256" (
    builtins.readFile pageLoadPatch + builtins.readFile themeScript
  );
  interfaceScript = "<script\n\t\t\tsrc=\"/pkg/interface.js?v=((crate::https::cache_buster::get_cache_buster_key()))\"\n\t\t\tdefer></script>";

  package = pkgs.kanidm_1_11.overrideAttrs (old: {
    patches = (old.patches or [ ]) ++ [
      consentPatch
      credentialPatch
      pageLoadPatch
      usageEventsPatch
    ];

    env =
      old.env
      // pkgs.lib.optionalAttrs container {
        KANIDM_BUILD_PROFILE = "container_generic";
      };

    postPatch =
      (if container then "" else old.postPatch)
      + ''
        substituteInPlace server/core/templates/navbar.html \
          --replace-fail '__IDENTITY_PORTAL_URL__' ${pkgs.lib.escapeShellArg portalUrl}
      ''
      + pkgs.lib.optionalString (uiVersion == null) ''
        cp ${themeScript} server/core/static/style.js
        substituteInPlace server/core/templates/base.html server/core/templates/base_htmx.html \
          --replace-fail ${pkgs.lib.escapeShellArg interfaceScript} ""
        substituteInPlace server/core/src/https/cache_buster.rs \
          --replace-fail 'option_env!("KANIDM_PKG_VERSION_HASH")' \
          ${pkgs.lib.escapeShellArg "Some(\"${genericUiVersion}\")"}
      ''
      + pkgs.lib.optionalString (uiVersion != null) ''
        substituteInPlace server/core/src/https/cache_buster.rs \
          --replace-fail 'option_env!("KANIDM_PKG_VERSION_HASH")' \
          ${pkgs.lib.escapeShellArg "Some(\"${uiVersion}\")"}
      '';
    cargoBuildFlags = [
      "--package"
      "daemon"
    ];
    preFixup = "";
    doCheck = false;
  });

  image = pkgs.dockerTools.buildLayeredImage {
    name = "identity/kanidm-consent";
    tag = package.version;

    contents = [
      package
      pkgs.cacert
    ];

    extraCommands = ''
      mkdir -p sbin data
      ln -s ${package}/bin/kanidmd sbin/kanidmd
      cp -r ${package}/ui/hpkg hpkg
      chmod 755 hpkg
      touch hpkg/override.css hpkg/background.webp
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
      ExposedPorts = {
        "8443/tcp" = { };
        "3636/tcp" = { };
      };

      Healthcheck = {
        Test = [
          "CMD"
          "/sbin/kanidmd"
          "scripting"
          "healthcheck"
        ];
        Interval = 60000000000;
        Timeout = 10000000000;
        StartPeriod = 60000000000;
        StartInterval = 5000000000;
        Retries = 3;
      };

      Labels = {
        "com.kanidm.version" = package.version;
        "identity.consent-recipient.patch-sha256" = builtins.hashFile "sha256" consentPatch;
        "identity.credential-conflict.patch-sha256" = builtins.hashFile "sha256" credentialPatch;
        "identity.page-load.patch-sha256" = builtins.hashFile "sha256" pageLoadPatch;
        "identity.usage-events.patch-sha256" = builtins.hashFile "sha256" usageEventsPatch;
        "identity.usage-events.version" = "1";
        "identity.credential-update-compare.version" = "1";
        "org.opencontainers.image.version" = package.version;
        "org.opencontainers.image.source" = "https://github.com/kanidm/kanidm";
        "org.opencontainers.image.revision" = "547933867e87da737e79d26942dc9261adaa5ee9";
        "org.opencontainers.image.licenses" = "MPL-2.0";
      };
    };
  };
in
{
  inherit package image;
}
