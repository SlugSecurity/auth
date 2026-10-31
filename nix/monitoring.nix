{
  config,
  lib,
  pkgs,
  ...
}:
let
  nativeEnabled = config.services.kanidm.server.enable;

  nativeCA =
    config.services.kanidm.client.settings.ca_path or "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

  usageHosts = pkgs.writeText "identity-usage-hosts" ''
    127.0.0.1 localhost auth.slugsec.club
    ::1 localhost ip6-localhost ip6-loopback
  '';
in
{
  assertions = lib.optional nativeEnabled {
    assertion =
      config.services.kanidm.server.settings.origin == "https://auth.slugsec.club"
      && config.services.kanidm.server.settings.bindaddress == "127.0.0.1:8443";
    message = "The SSO collector requires the configured native loopback endpoint";
  };

  services.prometheus = {
    enable = true;
    listenAddress = "127.0.0.1";
    retentionTime = "400d";
    extraFlags = [ "--storage.tsdb.retention.size=512MB" ];

    ruleFiles = [ ../monitoring/prometheus/alerts.yml ];
    globalConfig = {
      scrape_interval = "15s";
      evaluation_interval = "15s";
    };

    exporters.node = {
      enable = true;
      listenAddress = "127.0.0.1";
      enabledCollectors = [ "systemd" ];
    };

    scrapeConfigs = [
      {
        job_name = "node";
        scrape_interval = "60s";
        static_configs = [ { targets = [ "127.0.0.1:9100" ]; } ];
      }

      {
        job_name = "kanidm-observer";
        scrape_interval = "15s";
        static_configs = [ { targets = [ "127.0.0.1:19101" ]; } ];

        metric_relabel_configs = [
          {
            source_labels = [ "__name__" ];
            regex = "identity_(sso|auth)_(month_.+|week_.+|app_.+|day_.+|weekday_.+|period_.+)";
            action = "drop";
          }
        ];
      }

      {
        job_name = "kanidm-activity";
        scrape_interval = "60s";
        static_configs = [ { targets = [ "127.0.0.1:19101" ]; } ];

        metric_relabel_configs = [
          {
            source_labels = [ "__name__" ];
            regex = "identity_(sso|auth)_(month_.+|week_.+|app_.+|day_.+|weekday_.+|period_.+)";
            action = "keep";
          }
        ];
      }
    ];
  };

  systemd = {
    services = {
      kanidm = lib.mkIf nativeEnabled {
        serviceConfig.LogRateLimitIntervalSec = 0;
      };

      identity-usage = lib.mkIf nativeEnabled {
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [
          "kanidm.service"
          "network-online.target"
        ];
        requires = [ "kanidm.service" ];

        path = [ pkgs.systemd ];
        environment = {
          PYTHONUNBUFFERED = "1";
          PYTHONDONTWRITEBYTECODE = "1";
          PYTHONTZPATH = "${pkgs.tzdata}/share/zoneinfo";
        };

        serviceConfig = {
          ExecStart = lib.escapeShellArgs [
            "${pkgs.python3}/bin/python3"
            "${../service/usage.py}"
            "--state"
            "/var/lib/identity-usage"
            "--output"
            "/var/lib/identity/usage-export/usage.prom"
            "--native-url"
            "https://auth.slugsec.club:8443"
            "--ca"
            "%d/native-ca"
            "--probe-client"
            "account_portal"
            "--journal-unit"
            "kanidm.service"
          ];

          User = "identity-usage";
          Group = "identity-metrics";
          SupplementaryGroups = [ "systemd-journal" ];
          StateDirectory = "identity-usage";
          StateDirectoryMode = "0700";
          LoadCredential = [ "native-ca:${nativeCA}" ];

          Restart = "always";
          RestartSec = "5s";
          TimeoutStopSec = "30s";

          MemoryMax = "128M";
          TasksMax = 32;

          UMask = "0077";
          NoNewPrivileges = true;
          CapabilityBoundingSet = "";

          ProtectSystem = "strict";
          BindReadOnlyPaths = [ "${usageHosts}:/etc/hosts" ];
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          RestrictAddressFamilies = [
            "AF_UNIX"
            "AF_INET"
            "AF_INET6"
          ];
          ReadWritePaths = [
            "/var/lib/identity-usage"
            "/var/lib/identity/usage-export"
          ];
        };
      };
    };

    tmpfiles.rules = [
      "d /var/lib/identity/metrics 0755 root root -"
      "d /var/lib/identity/metrics/dashboards 2750 10002 identity-metrics -"
      "d /var/lib/identity/metrics/member-dashboards 2750 10002 identity-metrics -"
    ]
    ++ lib.optionals nativeEnabled [
      "d /var/lib/identity/usage-export 0750 identity-usage identity-metrics -"
    ];
  };

  users = {
    groups.identity-metrics.gid = 10005;
    users = {
      identity-usage = lib.mkIf nativeEnabled {
        isSystemUser = true;
        group = "identity-metrics";
      };
    };
  };
}
