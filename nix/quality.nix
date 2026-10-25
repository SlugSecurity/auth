{ pkgs, python }:
let
  tool =
    name: text:
    pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = [
        pkgs.gitMinimal
        pkgs.ruff
        pkgs.nixfmt
        pkgs.deadnix
        pkgs.statix
        pkgs.pyright
        python
      ];
      text = ''
        cd "$(git rev-parse --show-toplevel)"
        export PYTHONPATH="$PWD/service:$PWD/deploy''${PYTHONPATH:+:$PYTHONPATH}"

        source_files() {
          local path

          while IFS= read -r -d "" path; do
            if [[ -f "$path" ]]; then
              printf './%s\0' "$path"
            fi
          done < <(git ls-files -z --cached --others --exclude-standard --deduplicate -- "$@")
        }

        ${text}
      '';
    };

  format = tool "format" ''
    mapfile -d "" -t python_files < <(source_files '*.py' '*.pyi')
    mapfile -d "" -t nix_files < <(source_files '*.nix')

    ruff format "$@" "''${python_files[@]}"
    nixfmt "$@" "''${nix_files[@]}"
  '';

  lint = tool "lint" ''
    mapfile -d "" -t python_files < <(source_files '*.py')
    mapfile -d "" -t typed_files < <(source_files '*.py' '*.pyi')
    mapfile -d "" -t nix_files < <(source_files '*.nix')

    ruff check "''${typed_files[@]}"
    pylint --errors-only --persistent=no "''${python_files[@]}"
    bandit --quiet --severity-level medium "''${python_files[@]}"

    deadnix --fail "''${nix_files[@]}"
    for file in "''${nix_files[@]}"; do
      statix check "$file"
    done
  '';

  typecheck = tool "typecheck" ''
    mypy
    pyright --pythonpath ${python}/bin/python3
  '';

  deadcode = tool "deadcode" ''
    mapfile -d "" -t python_files < <(source_files '*.py')

    vulture "''${python_files[@]}" "$@"
  '';

  audit = tool "audit" ''
    ${deadcode}/bin/deadcode --min-confidence 60 "$@"
  '';

  check = tool "check" ''
    ${format}/bin/format --check
    ${lint}/bin/lint
    ${typecheck}/bin/typecheck
    ${deadcode}/bin/deadcode
  '';
in
{
  inherit
    format
    lint
    typecheck
    deadcode
    audit
    check
    ;
}
