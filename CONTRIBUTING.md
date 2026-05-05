# Contributing to SynVoid

We welcome contributions from the community! Whether you're reporting bugs, suggesting features, or submitting pull requests, here's how you can help.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** to your local machine
3. **Create a feature branch** for your changes
4. **Make your changes** and test thoroughly
5. **Submit a pull request** with clear description of your changes

## Development Setup

### Prerequisites
- Rust (stable) - latest stable version recommended
- Cargo - Rust package manager
- Git - version control system

### Building the Project

```bash
# Clone the repository
git clone https://github.com/synvoid/synvoid.git
cd synvoid

# Build in release mode
cargo build --release

# Run tests
cargo test

# Run with default configuration
./target/release/synvoid
```

### Code Style

We follow Rust standard conventions:
- Use `rustfmt` for code formatting
- Use `clippy` for linting
- Follow Rust naming conventions
- Keep lines under 100 characters when possible

### Testing

All contributions should include appropriate tests:
- Unit tests for new functionality
- Integration tests for major features
- Performance tests for critical paths

### Documentation

- Update relevant documentation files when making changes
- Add code comments for complex logic
- Ensure all public APIs are documented

## Pull Request Guidelines

1. **Before submitting**:
   - Ensure all tests pass
   - Run `cargo fmt` and `cargo clippy`
   - Update documentation if needed
   - Add meaningful commit messages

2. **Pull request should include**:
   - Description of changes
   - Reasoning for changes
   - Any breaking changes
   - Performance impact (if applicable)

## Issue Reporting

When reporting issues:

1. **Search existing issues** first to avoid duplicates
2. **Provide detailed information**:
   - Rust version and platform
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages or logs
   - Configuration files (if relevant)

3. **Include**:
   - Version of SynVoid being used
   - Operating system details
   - Any relevant configuration snippets

## Code Review Process

1. Maintainers will review all pull requests
2. Feedback will be provided for improvements
3. Changes may be requested before merging
4. All contributors must follow the code of conduct

## Release Process

Releases are handled by maintainers:
- Major releases: breaking changes and new features
- Minor releases: new features and improvements
- Patch releases: bug fixes and security updates

## Community Guidelines

- Be respectful and constructive
- Help others in the community
- Follow open source best practices
- Credit original authors when appropriate

## Security Issues

For security vulnerabilities, please email security@synvoid.com directly instead of using the public issue tracker.

## License

All contributions are made under the MIT License. See LICENSE file for details.