# Changelog

## [0.1.5](https://github.com/BjornMelin/oidc-jwt-verifier/compare/v0.1.4...v0.1.5) (2026-02-12)


### Features

* **integrations:** add fastapi and starlette auth helpers ([cdbae89](https://github.com/BjornMelin/oidc-jwt-verifier/commit/cdbae89f2b66bb346e371695e42489812944b691))
* **verifier:** add async support and framework integrations ([e69dbcd](https://github.com/BjornMelin/oidc-jwt-verifier/commit/e69dbcd1914c8607a351b97161a2dd10bd0152ee))
* **verifier:** add native async verifier and shared policy core ([a8e6f40](https://github.com/BjornMelin/oidc-jwt-verifier/commit/a8e6f403a2eaec8ed4b80c7d77c234300ddc6fb6))


### Bug Fixes

* **async:** address PR [#10](https://github.com/BjornMelin/oidc-jwt-verifier/issues/10) review feedback ([b77433c](https://github.com/BjornMelin/oidc-jwt-verifier/commit/b77433c9c2d33e64cd5277626747d52ab7c21eb5))
* commit all pending changes ([aaa743c](https://github.com/BjornMelin/oidc-jwt-verifier/commit/aaa743c37cebde3f77f19c21260b5dba5a360f20))
* harden mypy Any checks and align CI extras install ([25c8a6e](https://github.com/BjornMelin/oidc-jwt-verifier/commit/25c8a6e8a9b10264c3638906440db6562c9ba52d))
* **integrations:** resolve PR [#10](https://github.com/BjornMelin/oidc-jwt-verifier/issues/10) review threads ([b506f98](https://github.com/BjornMelin/oidc-jwt-verifier/commit/b506f9836cc7b45af099989d7b1361e7553ced78))

## [0.1.4](https://github.com/BjornMelin/oidc-jwt-verifier/compare/v0.1.3...v0.1.4) (2026-02-12)


### Features

* **jwt:** enforce minimum cryptographic key length ([459c160](https://github.com/BjornMelin/oidc-jwt-verifier/commit/459c16097941ccee194752deee559171dc18afeb))
* **verifier:** align with PyJWT 2.11 typing and key checks ([7bcd8bf](https://github.com/BjornMelin/oidc-jwt-verifier/commit/7bcd8bfff1ab60b5e940b662cdb04fc0df9047a7))

## [0.1.3](https://github.com/BjornMelin/oidc-jwt-verifier/compare/v0.1.2...v0.1.3) (2025-12-18)


### Bug Fixes

* **docs:** add missing Documentation badge to docs/index.md ([dfdf6ae](https://github.com/BjornMelin/oidc-jwt-verifier/commit/dfdf6ae2f9c96ca1a1974c9af6d204241b6e1c69))

## [0.1.2](https://github.com/BjornMelin/oidc-jwt-verifier/compare/v0.1.1...v0.1.2) (2025-12-18)


### Bug Fixes

* **docs:** resolve MkDocs Material rendering issues and modernize deployment ([89fefb0](https://github.com/BjornMelin/oidc-jwt-verifier/commit/89fefb02c1e5d5b56428a79c90aacec0c72e3574))
* **docs:** resolve MkDocs Material rendering issues and modernize deployment ([2018920](https://github.com/BjornMelin/oidc-jwt-verifier/commit/201892060a9ee52d508bd0da2b5a50dca7b103f7))

## [0.1.1](https://github.com/BjornMelin/oidc-jwt-verifier/compare/v0.1.0...v0.1.1) (2025-12-18)


### Features

* add core JWT verification library with automated release pipeline ([61862b5](https://github.com/BjornMelin/oidc-jwt-verifier/commit/61862b5c86e5eb4bcaa30ee42ea10c9240f3d582))
* **jwt-verifier:** add core JWT verification library ([cf67629](https://github.com/BjornMelin/oidc-jwt-verifier/commit/cf676291eb18400e52424b7efe6d63ef343ace20))


### Bug Fixes

* address additional PR review comments ([f8132f8](https://github.com/BjornMelin/oidc-jwt-verifier/commit/f8132f8f86eb6e3a1a12baaf32f485eb6a85436a))
* address PR review comments ([b12bf0a](https://github.com/BjornMelin/oidc-jwt-verifier/commit/b12bf0a4db21d0647e95139d32b1641812beebf4))
* persist stripped scope_claim and permissions_claim values ([c8290c5](https://github.com/BjornMelin/oidc-jwt-verifier/commit/c8290c50315a0eec5911185f0fffe07b62f806a1))
* update PyJWT to &gt;=2.10.1 to address CVE-2024-53861 ([3fe5e8f](https://github.com/BjornMelin/oidc-jwt-verifier/commit/3fe5e8f21dbece09c66d4b9128e8ac0f87145b88))
* **verifier:** catch DecodeError in header parse ([df76b3c](https://github.com/BjornMelin/oidc-jwt-verifier/commit/df76b3c808c1e0d170e0bb645a440c084d10e431))
* **verifier:** narrow decode exceptions in audience loop ([d2a9fd5](https://github.com/BjornMelin/oidc-jwt-verifier/commit/d2a9fd5bdc3bed88d83f5841dbdd771cb9c1bda0))

## 0.1.0

- Initial release of the shared JWT verification core.
