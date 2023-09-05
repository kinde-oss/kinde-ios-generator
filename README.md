# Kinde iOS generator

The generator for the [Kinde iOS SDK](<[link-to-sdk-repo](https://github.com/kinde-oss/kinde-auth-nextjs)>).

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com) [![Kinde Docs](https://img.shields.io/badge/Kinde-Docs-eee?style=flat-square)](https://kinde.com/docs/developer-tools) [![Kinde Community](https://img.shields.io/badge/Kinde-Community-eee?style=flat-square)](https://thekindecommunity.slack.com)

## Overview

This generator creates an SDK in iOS that can authenticate to Kinde using the Authorization Code grant or the Authorization Code with PKCE grant via the [OAuth 2.0 protocol](https://oauth.net/2/).

Also, see the SDKs section in Kinde’s [contributing guidelines](https://github.com/kinde-oss/.github/blob/main/.github/CONTRIBUTING.md).

## Usage

### Requirements
- NodeJS v16+. [Link to download](https://nodejs.org/en/download)

### Initial set up

1. Clone the repository to your machine:

   ```bash
   git clone git@github.com:kinde-oss/kinde-ios-generator.git
   ```

2. Go into the project:

   ```bash
   cd kinde-ios-generator
   ```

3. Install the dependencies:

   ```bash
   npm install
   ```
### SDK generation

Run the following command to generate the SDK:

```bash
npm run generate-api
```

The SDK gets outputted to: `./KindeManagementAPI`, which you can enter via:

```bash
cd KindeManagementAPI
```

## SDK documentation

[iOS SDK](https://kinde.com/docs/developer-tools/ios-sdk/)

## Development

- To add the SDK to an existing project, update the `Podfile` with the following code snippet:
    ```swift
    ...
    pod 'KindeSDK', :path => '<path-to-generator-folder>/KindeManagementAPI/KindeSDK.podspec'
    ...
    ```
- When you make changes to the SDK, it is necessary to update the template files in order to regenerate the SDK. You can find the templates configured in the `config.yaml` file.
    
## Contributing

Please refer to Kinde’s [contributing guidelines](https://github.com/kinde-oss/.github/blob/489e2ca9c3307c2b2e098a885e22f2239116394a/CONTRIBUTING.md).

## License

By contributing to Kinde, you agree that your contributions will be licensed under its MIT License.