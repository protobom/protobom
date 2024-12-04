# Contributing To Protobom

We welcome contributions to the protobom project! By participating in this project, you agree to abide by the [Code of Conduct](code-of-conduct.md).

## Getting Started

To contribute to the protobom repository, follow these steps:

1. Fork the repository.
2. Create a new branch for your contribution:
   ```
   git checkout -b feature/new-feature
   ```
3. Make your desired changes to the codebase.
4. Commit your changes with a descriptive commit message.
5. Push your branch to your forked repository:
   ```
   git push origin feature/new-feature
   ```
6. Open a pull request against the `main` branch of the protobom repository.


## Development Guide

For detailed information on setting up your development environment and contributing to the protobom repository, please refer to the [Development Guide](/docs/development.md).

## Code Style

We strive to maintain a consistent code style throughout the project. When contributing to the Go library, please ensure your code follows the following guidelines:

- Use meaningful variable and function names following the camel case convention (`myVariable`, `myFunction`).
- Write clear and concise comments to describe your code's purpose and functionality.
- Adhere to Go formatting guidelines by running using gofumpt and can be ran using `golangci-lint run` or by using recommit hooks. 
- Follow the best practices and idiomatic style described in [Effective Go](https://golang.org/doc/effective_go.html).

## Testing

We highly encourage writing tests for new features and bug fixes. This ensures the stability and reliability of the codebase. There is unit/integration testing and conformance testing. 

### Conformance Testing
The purpose of conformance testing is to ensure that the system or software meets the requirements set forth by the relevant standards or specifications. Reference [README.md](test/conformance/README.md) for more details about conformance testing.

### Unit & Integration Testing
 we strive to keep our test coverage high so please add tests to any functions you introduce by your contributions. 

## Issue Tracker

If you encounter any issues or have suggestions for improvements, please open an issue on the [issue tracker](https://github.com/protobom/protobom/issues).

## Join our Community

- [#protobom on OpenSSF Slack](https://openssf.slack.com/archives/C06ED97EQ4B)
- [OpenSSF Security Tooling Working Group Meeting](https://zoom-lfx.platform.linuxfoundation.org/meeting/94897563315?password=7f03d8e7-7bc9-454e-95bd-6e1e09cb3b0b) - Every other Friday at 8am Pacific
- [SBOM Tooling Working Meeting](https://zoom-lfx.platform.linuxfoundation.org/meeting/92103679564?password=c351279a-5cec-44a4-ab5b-e4342da0e43f) - Every Monday, 2pm Pacific

## License

When contributing to the protobom project, it is important to understand and agree to the licensing terms. All contributions to the project will be licensed under the Apache 2.0 License. By submitting a pull request, you are agreeing to these terms.

To ensure a clear licensing history and proper attribution, code commits in the project require a signoff. The signoff indicates that you have read and agree to the Developer Certificate of Origin (DCO), which states that you have the right to contribute the code and that it does not infringe on any copyright or intellectual property rights. The DCO signoff helps protect the project and its contributors.

Thank you for contributing to protobom! We appreciate your help in making our project better.