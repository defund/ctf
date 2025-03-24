{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = lib.systems.flakeExposed;
      eachDefaultSystem = f: builtins.foldl' lib.attrsets.recursiveUpdate { }
        (map f systems);
    in
    eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.${system}.default = pkgs.mkShellNoCC {
          packages = [
            pkgs.python312
            pkgs.python312Packages.aiohttp
            pkgs.python312Packages.fastecdsa
            pkgs.python312Packages.pycryptodome
            pkgs.python312Packages.requests
          ];
        };
      }
    );
}
