# Contributing

Thanks for contributing to `mvnet`.

## Before you start

Search the existing issues before opening a new one. For significant API or
behavior changes, open an issue first so the design and compatibility impact
can be discussed before implementation.

## Development

You need Go 1.24 or newer. Clone your fork, create a focused branch, and make
the smallest change that solves the issue. This module intentionally uses only
the Go standard library; discuss any proposed third-party dependency in an
issue before adding it.

Run the required checks before submitting a pull request:

```sh
test -z "$(gofmt -l .)"
go vet ./...
go test -race ./...
```

Add or update tests for behavior changes. Keep exported APIs documented and
avoid unrelated refactoring in the same pull request.

## Pull requests

Reference the issue number in your branch name (`fix/NNN-slug`,
`feat/NNN-slug`, `chore/NNN-slug`) and in commits. Open a pull request with a
clear summary, the testing you performed, and `Closes #NNN` in the body.