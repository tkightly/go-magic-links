# Changelog

## [0.2.0](https://github.com/tkightly/go-magic-links/compare/v0.1.0...v0.2.0) (2026-11-22)


### ⚠ BREAKING CHANGES

* SignIn returns (string, error) instead of (int64, error); Session.UserID is a string and SignOutUser takes a string. Apps with integer IDs convert with strconv.FormatInt / strconv.ParseInt.

### Features

* make user IDs opaque strings ([237ec7c](https://github.com/tkightly/go-magic-links/commit/237ec7cec885c8c4812026b0d607dc00e29dd6d7))

## 0.1.0 (2026-11-22)


### Bug Fixes

* **ci:** run tests inline instead of via private shared workflow ([439478c](https://github.com/tkightly/go-magic-links/commit/439478cf7a79a43191e88a185987f5809fe86506))
* require go 1.27.4 to pick up the net/url fix ([ca41d76](https://github.com/tkightly/go-magic-links/commit/ca41d76f94908e037e58a9445e394e029e2bef94))


### Continuous Integration

* release with release-please and lint with shared go-lint ([6238ddc](https://github.com/tkightly/go-magic-links/commit/6238ddc49ba4058a2daf02e1d7211b9e753463ab))
