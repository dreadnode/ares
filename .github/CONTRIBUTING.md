# Contributing to Ares

We want to make contributing to this project as easy and transparent as
possible.

## Development Setup

### Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- [pre-commit](https://pre-commit.com/)
- [Task](https://taskfile.dev/installation/) (recommended, not required)

### Getting Started

```bash
# Clone and build
git clone https://github.com/dreadnode/ares.git && cd ares
cargo build

# Install pre-commit hooks
pre-commit install

# Run tests
cargo test --workspace

# Run the full check suite
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

### Project Structure

Ares is a Cargo workspace with six crates:

| Crate | Type | Purpose |
|-------|------|---------|
| `ares-cli` | Binary | Unified CLI for ops, blue, history, config |
| `ares-orchestrator` | Binary | LLM-powered coordination loop |
| `ares-worker` | Binary | Task execution agents |
| `ares-core` | Library | Shared models, state, Redis schema, telemetry |
| `ares-llm` | Library | Model-agnostic LLM provider abstraction |
| `ares-tools` | Library | Tool dispatch and execution framework |

## Pull Request Guidelines

We actively welcome your pull requests.

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes (`cargo test --workspace`).
5. Make sure your code passes `cargo clippy` and `cargo fmt`.

### PR Description Format

We use a standardized format for pull request descriptions to ensure
consistency and clarity:

1. **Title**: Use a clear, concise title that summarizes the changes
2. **Key Changes**: List the most important updates
3. **Added**: Document new features or files
4. **Changed**: Highlight modifications to existing code
5. **Removed**: Note any deletions or removals

Example:

```markdown
### Add device configuration automation

**Key Changes:**

- Implement dynamic device configuration
- Add automated setup scripts
- Update documentation

**Added:**

- New device setup module
- Configuration templates
- Setup guide

**Changed:**

- Refactored device initialization
- Updated configuration format
- Modified setup process

**Removed:**

- Legacy device configs
- Deprecated setup scripts
```

## Issues

We use GitHub issues to track public bugs. Please ensure your description is
clear and has sufficient instructions to be able to reproduce the issue.

## License

By contributing to this project, you agree that your contributions will be licensed
under the LICENSE file in the root directory of this source tree.
