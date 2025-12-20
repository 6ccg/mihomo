# Repository Guidelines

## Project Structure & Module Organization
- Entry point: `main.go`.
- Core packages: `adapter/`, `component/`, `transport/`, `tunnel/`, `rules/`, `dns/`, `config/`, `listener/`, `hub/`.
- OpenVPN outbound lives in `adapter/outbound/openvpn*.go` and is documented in `docs/openvpn.md`.
- OpenVPN client is `minivpn` as a Git submodule in `third_party/minivpn/` (this repo pins a specific revision).
- Docs and notes: `docs/` and `about.md`. Test fixtures live under `test/`.

## Build, Test, and Development Commands
- Init submodules: `git submodule update --init --recursive`
- Run tests: `go test ./...`
- Build (OpenVPN requires gVisor): `go build -tags with_gvisor`
- Validate a config file: `go run -tags with_gvisor . -t -d <home> -f <config.yaml>`
- Cross-build examples (see `Makefile` for full target list):
  - `make windows-amd64-v3` → `bin/mihomo-windows-amd64-v3.exe`
  - `make linux-amd64-v3` → `bin/mihomo-linux-amd64-v3`

## Coding Style & Naming Conventions
- Format with `gofmt`; CI/linting also enforces `gofumpt` and import order via `gci` (configured in `.golangci.yaml`).
- Lint locally with `golangci-lint run` (install it if missing).
- Follow standard Go naming: exported `CamelCase`, unexported `camelCase`, package names lowercase.

## Testing Guidelines
- Use Go’s standard testing (`*_test.go`), keep tests deterministic, and add regressions near the code you touched.
- If you change `third_party/minivpn`, run its tests too: `pushd third_party/minivpn; go test ./...`.

## Commit & Pull Request Guidelines
- Commit messages follow Conventional Commits (examples: `feat: ...`, `fix(openvpn): ...`, `chore: ...`, `docs: ...`).
- Submodule workflow: commit changes inside `third_party/minivpn/`, then bump the submodule pointer in the main repo.
- PRs should include: intent + scope, reproduction steps, config/log snippets (redact keys), and test/build notes (especially whether `-tags with_gvisor` was used for OpenVPN).
