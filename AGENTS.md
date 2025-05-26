# AGENTS

## Overview
SwarmUI is a modular AI image generation web UI written in C# for .NET 8. It exposes a web server with HTTP and WebSocket APIs and can drive multiple backends such as ComfyUI or other SwarmUI instances. The repository includes built-in extensions, a rich documentation set and launch scripts for Windows, Linux and Mac.

## Repository structure
- `src/` contains all C# source code. `SwarmUI.csproj` is the main project file. Subfolders include:
  - `Core/` – program entry point and core services.
  - `Backends/` – backend implementations.
  - `BuiltinExtensions/` – optional features packaged as extensions.
  - `Pages/` – Razor views for the UI.
  - `wwwroot/` – static web assets.
- `docs/` provides user and developer documentation including API reference.
- `languages/` holds JSON language files used for localization.
- `launch-*.sh` / `launch-windows*.ps1` are scripts to build and run SwarmUI.
- `colab/` contains a minimal Google Colab notebook.

## Building
Run `dotnet build src/SwarmUI.csproj --configuration Release` to compile. The launch scripts will build automatically when needed. No dedicated test suite exists.

## Data storage and database
Persistent data lives under the `Data` directory (override via `--data_dir`).
User accounts, sessions and presets are saved in `Data/Users.ldb` using the
embedded LiteDB engine. Image metadata is recorded in `image_metadata.ldb`
within each output folder (or directly under `Data` when
`Metadata.ImageMetadataPerFolder` is disabled). Additional configuration files
such as `Settings.fds`, `Backends.fds` and `Roles.fds` are plain text in
[Frenetic Data Syntax](https://github.com/mcmonkeyprojects/FreneticDataSyntax).
Generated images are written to `Data/Output` by default.

## API overview
The web server exposes JSON HTTP and WebSocket routes at `/API/*`. A new session
is acquired via `GetNewSession`, after which the returned `session_id` must be
supplied in API calls. See `/docs/API.md` for introduction and `/docs/APIRoutes`
for per-route reference such as `T2IAPI.md` for image generation. Example usage
is also shown in the docs and in comments inside the code.

## Additional documentation
The repo has extensive guides inside the `docs/` folder:
- `/docs/README.md` – entry point listing all guides.
- `/docs/Command Line Arguments.md` – CLI options like `--data_dir`.
- `/docs/Features/README.md` – descriptions of optional features and how to use
  them.
- `/docs/Image Metadata Format.md` – explains the metadata saved with images.
- `/docs/Docker.md` – instructions for containerized usage.
- `/docs/Privacy.md` – notes regarding privacy concerns.
The built‑in extensions under `src/BuiltinExtensions` each have their own
README with usage details.

## Contributing
See `CONTRIBUTING.md` for details on adding extensions, languages and themes. The project follows typical C# code style with four-space indentation and XML documentation comments for public members.
