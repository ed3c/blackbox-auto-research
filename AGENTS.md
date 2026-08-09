# AGENTS.md

- Keep changes incremental and runnable.
- Reuse the repository's existing tools and test patterns.
- Never commit credentials, personal identifiers, private corpus data, device identifiers, signing material, or absolute home-directory paths.
- Fail loudly with actionable errors; do not silently skip missing dependencies.
- Run the documented test command and inspect the staged diff before every commit.
- Do not bypass hooks or weaken tests to make a change pass.
