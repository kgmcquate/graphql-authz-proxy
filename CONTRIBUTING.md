# Release Workflow

This project uses a branching and release strategy with automation:

## Branching Model
- `main`: Active development
- `release/x.y`: Stable release branches

## Versioning & Tags
- Semantic versioning (e.g., `v1.2.0`)
- Tags are created automatically by semantic-release

## GitHub Releases
- Releases are created automatically from tags
- Changelog is generated from conventional commit messages

## How to Release
1. Merge changes to `main` or a `release/x.y` branch using conventional commits.
2. Push to GitHub.
3. GitHub Actions will:
   - Bump the version
   - Tag the release
   - Generate/update the changelog
   - Create a GitHub Release
   - Upload assets from `dist/` if present

## Conventional Commits
- Use commit messages like:
  - `feat: add new feature`
  - `fix: correct bug`
  - `chore: update dependencies`

## Manual Release
- You can trigger a release manually via the GitHub Actions workflow dispatch.

See `.github/workflows/release.yml` and `.python-semantic-release` for details.
