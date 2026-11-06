{
  description = "osintz-mcps: independently installable OSINT MCP servers";

  # Pinned to nixos-unstable rev 3ec636362e1816bc2f0888fa0fa2c69f1bc9e504.
  # A branch URL needs the GitHub commits API; this rev is fetched as a tarball.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/3ec636362e1816bc2f0888fa0fa2c69f1bc9e504";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      ...
    }:
    let
      inherit (nixpkgs) lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      eachSystem = f: lib.genAttrs systems (system: f system);

      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };

      overlay = workspace.mkPyprojectOverlay {
        sourcePreference = "wheel";
      };

      # Add build-system / package overrides here only when a locked dep needs them.
      pyprojectOverrides = _final: _prev: { };

      mkPythonSet =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python312;
        in
        (pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        }).overrideScope
          (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.wheel
              overlay
              pyprojectOverrides
            ]
          );

      # Runtime closures. Dev groups stay out of the installed servers.
      snusbaseRuntime = {
        osintz-snusbase-mcp = [ ];
      };
      dehashedRuntime = {
        osintz-dehashed-mcp = [ ];
      };

      # Same package plus the lockfile's `dev` group (pytest, ruff, ty, respx).
      snusbaseCheck = {
        osintz-snusbase-mcp = [ "dev" ];
      };
      dehashedCheck = {
        osintz-dehashed-mcp = [ "dev" ];
      };
      commonCheck = {
        osintz-common = [ "dev" ];
      };

      mkChecks =
        system: name: source: relative: groups: copyRepo:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pythonSet = mkPythonSet system;
          checkEnv = pythonSet.mkVirtualEnv "${name}-check-env" groups;
          prepare =
            if copyRepo then
              ''
                # The whole tree: test_agent_contract.py walks up to the repo root.
                cp -a ${./.} src-tree
                chmod -R u+w src-tree
                cd src-tree/${relative}
              ''
            else
              ''
                cp -a ${source} src-tree
                chmod -R u+w src-tree
                cd src-tree
              '';
        in
        {
          "${name}-ruff" =
            pkgs.runCommand "${name}-ruff" { nativeBuildInputs = [ checkEnv ]; }
              ''
                cd ${source}
                ruff check --no-cache src tests
                ruff format --check --no-cache src tests
                touch $out
              '';

          "${name}-ty" =
            pkgs.runCommand "${name}-ty" { nativeBuildInputs = [ checkEnv ]; }
              ''
                cd ${source}
                export XDG_CACHE_HOME=$(mktemp -d)
                ty check
                touch $out
              '';

          "${name}-pytest" =
            pkgs.runCommand "${name}-pytest"
              {
                nativeBuildInputs = [
                  checkEnv
                  pkgs.cacert
                ];
              }
              ''
                set -euo pipefail
                # The stdenv points SSL_CERT_FILE at a missing placeholder. httpx
                # loads it when a client is constructed, including under respx.
                export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                export NIX_SSL_CERT_FILE="$SSL_CERT_FILE"
                ${prepare}
                export PYTHONDONTWRITEBYTECODE=1
                # Import the installed package from checkEnv (not PYTHONPATH=src).
                pytest -q -p no:cacheprovider
                touch $out
              '';
        };
    in
    {
      # Impure uv shell: `uv run` syncs from uv.lock. Keeps UV_PYTHON_DOWNLOADS=never
      # and pins the interpreter to nixpkgs python312. An editable uv2nix shell would
      # conflict with `uv run` (UV_NO_SYNC), which we still want for local/CI parity.
      devShells = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.python312
              pkgs.uv
              pkgs.cacert
            ];
            env = {
              UV_PYTHON = "${pkgs.python312}/bin/python";
              UV_PYTHON_DOWNLOADS = "never";
              SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            };
          };
        }
      );

      # `nix build` installs osintz-snusbase-mcp with bin/snusbase-mcp (stdio).
      # DeHashed is `nix build .#osintz-dehashed-mcp`.
      packages = eachSystem (
        system:
        let
          pythonSet = mkPythonSet system;
          snusbase = pythonSet.mkVirtualEnv "osintz-snusbase-mcp" snusbaseRuntime;
          dehashed = pythonSet.mkVirtualEnv "osintz-dehashed-mcp" dehashedRuntime;
        in
        {
          default = snusbase;
          osintz-snusbase-mcp = snusbase;
          osintz-dehashed-mcp = dehashed;
        }
      );

      # Lockfile-faithful checks. pytest, ruff, and ty come from the uv.lock
      # virtualenv, not from nixpkgs Python packages.
      checks = eachSystem (
        system:
        mkChecks system "osintz-snusbase-mcp" ./osint-sources/snusbase "osint-sources/snusbase" snusbaseCheck true
        // mkChecks system "osintz-dehashed-mcp" ./osint-sources/dehashed "osint-sources/dehashed" dehashedCheck false
        // mkChecks system "osintz-common" ./osint-common "osint-common" commonCheck false
      );
    };
}
