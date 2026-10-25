{ pkgs, ... }:
let
  native =
    (import ./kanidm-consent.nix {
      inherit pkgs;
      container = false;
    }).package;

  package = pkgs.symlinkJoin {
    name = "kanidm-identity-${native.version}";
    inherit (native) version;
    inherit (pkgs.kanidm_1_11) meta;
    paths = [
      native
      pkgs.kanidm_1_11
    ];

    postBuild = ''
      ln -sfn ${native}/bin/kanidmd "$out/bin/kanidmd"
    '';

    passthru = {
      inherit (native) eolMessage enableSecretProvisioning;
    };
  };
in
{
  services.kanidm = {
    inherit package;

    server = {
      enable = true;
      settings = {
        domain = "auth.slugsec.club";
        origin = "https://auth.slugsec.club";

        bindaddress = "127.0.0.1:8443";
        tls_chain = "/run/secrets/kanidm-tls-chain";
        tls_key = "/run/secrets/kanidm-tls-key";

        online_backup = {
          versions = 14;
          schedule = "0 2 * * *";
        };
      };
    };

    client = {
      enable = true;
      settings.uri = "https://auth.slugsec.club";
    };

    provision = {
      enable = true;
      instanceUrl = "https://auth.slugsec.club";
      acceptInvalidCerts = false;
      autoRemove = false;

      groups = {
        idm_people_self_name_write = {
          members = [ ];
          overwriteMembers = true;
        };
        idm_people_self_mail_write = {
          members = [ ];
          overwriteMembers = true;
        };
      };
    };
  };

  systemd.services.kanidm = {
    unitConfig = {
      StartLimitIntervalSec = "10min";
      StartLimitBurst = 3;
    };

    serviceConfig = {
      Restart = "on-failure";
      RestartSec = "15s";
    };
  };
}
