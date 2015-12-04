# Java ACME Client

Java ACME Client is a ACME (Automated Certificate Management Environment) implementation.
See RFC Draft for more details: https://tools.ietf.org/html/draft-ietf-acme-acme-01
This protocol is currently used to automate X509 Certificates by [Let's Encrypt CA](https://letsencrypt.org).

## Download release

There is currently no binary release available, we are planning to release it to Maven Central as soon as we get some feedback for users.

## Release note

The current version supports ONLY certificate creation. Credential recovery and certificate revocation are currently not supported.

### Version 0.1.1
- Added support for new http-01 challenge

### Version 0.1.0
- First Public Release

## Contributions

Contributions are welcome, but there are no guarantees that they are accepted as such. Process for contributing is the following:
- Fork this project
- Create an issue to this project about the contribution (bug or feature) if there is no such issue about it already. Try to keep the scope minimal.
- Develop and test the fix or functionality carefully. Only include minimum amount of code needed to fix the issue.
- Refer to the fixed issue in commit
- Send a pull request for the original project
- Comment on the original issue that you have implemented a fix for it

## License & Author

Java ACME Client is distributed under Apache License 2.0. For license terms, see LICENSE.txt.

Java ACME Client is written by Zero11

# Developer Guide

## Getting started

- Checkout git repository and build with maven.
- Add a dependency to your project
- Include a JAX-RS Client to your project (the code has been tested with jersey-client 2.18)

Check out [here](https://github.com/zero11it/acme-client-letsencrypt-demo) an example that generate a signed certificate verifying the CA challenge by uploading required file using FTP  