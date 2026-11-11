# setup-keychain

Create a temporary macOS keychain once, import multiple signing identities, and let the action clean up at the end of the job.

This repository contains two JavaScript GitHub Actions, implemented in TypeScript. The root action owns the keychain lifecycle. The `import` action adds one PKCS12 certificate and private key to an existing managed keychain. Bundled JavaScript is committed under `dist/`; workflows do not install this project's dependencies.

## Usage

The examples use the `v1` major release tag. Use `v1.0.0` for the initial release, or pin both actions to the same full commit SHA for reproducible builds. The `v1` tag may advance to compatible fixes; versioned release tags remain fixed.

Store PKCS12 content and its password in GitHub Actions secrets. Base64 is an encoding, **not encryption**. To encode a file on macOS:

```sh
base64 -i signing.p12 | pbcopy
```

### One setup, two imports, then sign

```yaml
jobs:
  sign:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v6
      - id: signing
        uses: opnay/setup-keychain@v1
      - name: Import application identity
        uses: opnay/setup-keychain/import@v1
        with:
          keychain-path: ${{ steps.signing.outputs.keychain-path }}
          certificate-base64: ${{ secrets.APP_CERTIFICATE_BASE64 }}
          certificate-password: ${{ secrets.APP_CERTIFICATE_PASSWORD }}
      - name: Import installer identity
        uses: opnay/setup-keychain/import@v1
        with:
          keychain-path: ${{ steps.signing.outputs.keychain-path }}
          certificate-base64: ${{ secrets.INSTALLER_CERTIFICATE_BASE64 }}
          certificate-password: ${{ secrets.INSTALLER_CERTIFICATE_PASSWORD }}
      - name: Build and sign
        run: ./scripts/build-and-sign.sh
```

Replace the build command with your project's command. No separate cleanup step is needed. The action does not create provisioning profiles, select signing identities, configure Xcode, or notarize applications. Those remain your build's responsibility.

### Import from a file

Download or create the PKCS12 file in a preceding step. The action preserves that original file; your workflow owns its cleanup.

```yaml
- id: signing
  uses: opnay/setup-keychain@v1
- uses: opnay/setup-keychain/import@v1
  with:
    keychain-path: ${{ steps.signing.outputs.keychain-path }}
    certificate-path: ${{ runner.temp }}/application.p12
    certificate-password: ${{ secrets.APP_CERTIFICATE_PASSWORD }}
```

### Import from a job environment variable

Explicitly connect the environment variable to the action input:

```yaml
- uses: opnay/setup-keychain/import@v1
  with:
    keychain-path: ${{ steps.signing.outputs.keychain-path }}
    certificate-base64: ${{ env.SIGNING_CERTIFICATE_BASE64 }}
    certificate-password: ${{ secrets.APP_CERTIFICATE_PASSWORD }}
```

Do not specify both certificate sources. Standard padded Base64 is accepted, including line breaks and whitespace. Empty content and malformed encoding fail before import.

## Inputs and outputs

### Root action

| Name | Kind | Default | Meaning |
| --- | --- | --- | --- |
| `set-default` | Input | `false` | Accepts `true` or `false`. Temporarily sets the user default keychain when true. |
| `keychain-path` | Output | — | Absolute path to this invocation's keychain. |
| `SETUP_KEYCHAIN_PATH` | Job environment | — | Same path, available to later steps. The last setup invocation wins. |

Use explicit step outputs when creating more than one keychain. The environment variable is a convenience, not the import action's default input.

### Import action

| Input | Required | Meaning |
| --- | --- | --- |
| `keychain-path` | Yes | Path returned by a setup invocation in the same job. |
| `certificate-path` | Exactly one source | Path to a PKCS12 file containing a certificate and private key. |
| `certificate-base64` | Exactly one source | Base64-encoded PKCS12 content. |
| `certificate-password` | Yes | Nonempty PKCS12 password. Whitespace is preserved. |

The import action has no outputs. Use a GitHub secret for each certificate password. Empty passwords are not supported: empty-password PKCS12 interoperability varies by exporter and macOS import behavior. Re-export with a nonempty password. Missing or empty passwords fail before any import command. An incorrect password, invalid PKCS12 file, or failed partition-list update fails the step. Import failure does not delete the keychain or roll back other certificates. If the import succeeds but partition configuration fails, the newly imported identity may remain.

## Lifecycle and design

1. Setup requires macOS, `RUNNER_TEMP`, GitHub run/job identifiers, and one existing user default keychain. It reads the user search list and default before changing anything.
2. Setup creates a unique `setup-keychain-*` directory under the canonical runner temporary directory with mode `0700`. A `0600` state file stores the snapshot, managed keychain path, job identity, and a cryptographically random keychain password.
3. Setup creates and unlocks the keychain, configures a six-hour lock timeout, preserves existing search-list entries, and appends the new keychain. Only `set-default: true` changes the default.
4. Import validates the managed directory, state, job identity, file ownership, permissions, path structure, and absence of symlinks. It copies or decodes the certificate to a private temporary file, unlocks the keychain, imports the PKCS12 identity, and sets signing-key partitions to `apple-tool:,apple:,codesign:` for noninteractive `codesign` use. The temporary certificate copy is removed even on failure.
5. Setup's post action restores its captured search list, restores the original default if it changed it, deletes its keychain, and removes its state directory. Multiple setup posts run in reverse order, restoring each previous snapshot.

Setup registers its cleanup path through `GITHUB_STATE` before creating the keychain. That state only connects this setup invocation's main and post processes. Independent `uses` invocations cannot share `GITHUB_STATE`; import finds the restricted state file through the explicit keychain path instead.

Setup failures attempt immediate cleanup. If an OS cleanup operation fails, the action attempts the other cleanup operations, retains state for retry, and reports failure. The post action retries retained setup state. Post cleanup also removes private, owned files matching the action's exact temporary certificate filename format after an interrupted import. Unexpected files, symlinks, and hard links are preserved and reported; directories are never recursively deleted during post cleanup. Do not remove or alter the managed directory during the job. If it is missing, post warns that the saved snapshot is unavailable and automatic restoration cannot be verified. A hard runner termination can prevent cleanup entirely; operators of self-hosted runners must handle abandoned resources.

## Security and boundaries

- The keychain password is generated internally and differs from the certificate password. It is never an action output or job environment variable. Only the managed state file contains it.
- File modes and validation prevent accidental use of arbitrary keychains. They **do not isolate the state from other processes or steps running as the same runner user**. All steps in the job must be trusted. Do not run untrusted pull-request code with signing secrets.
- macOS `security` requires passwords as command arguments for these operations. The action uses argument arrays without a shell, suppresses command output/errors that could expose credentials, and masks certificate inputs. Processes with sufficient access may still observe arguments or read the state file.
- Partition configuration applies to signing keys in this managed keychain, including previously imported keys. Import does not change the default or search list, or delete any keychain.
- Only keychains created by this action in the same job are supported. Existing user keychains, general password items, and batch certificate inputs are out of scope. Repeat the import step for multiple identities.
- Setup changes the **user** search list and optionally default. Use a dedicated runner user and serial steps. Concurrent jobs sharing one macOS user, out-of-order cleanup, or other tools modifying keychain settings during the job are unsupported. Cleanup restores the captured snapshot, so intervening changes may be overwritten.
- The action does not clean up your original certificate files, install Apple trust chains, or grant platform signing entitlements. Valid identities and provisioning remain prerequisites for your build.
- The keychain uses a six-hour idle timeout and may lock on sleep. Import unlocks it before use; a later signing step after a long idle period can fail. Schedule setup/import close to signing. There is no public password output or standalone unlock action.
- Keep both action refs aligned. Self-hosted runners must support JavaScript actions using Node.js 24 and have `/usr/bin/security` and `/usr/bin/codesign` available.

## Development and verification

Use Node.js 24 or later and npm:

```sh
npm ci --ignore-scripts
npm run check
```

`check` type-checks TypeScript, runs tests, and regenerates the three committed bundles. Commit bundle changes alongside source changes. CI rejects bundle drift. Dependencies are locked in `package-lock.json`.

Unit tests use a security-command adapter and temporary files. They cover reverse lifecycle restoration, setup failures at each mutation, partial cleanup/retry for each OS operation, missing state, interrupted-import residues, secret-safe command errors, repeated imports, rejection of empty passwords, source preservation, import/partition failures, and invalid or unsafe managed state. They do not prove macOS cryptographic behavior and do not change your local user keychain settings.

The macOS CI job uses an ephemeral GitHub-hosted runner. It generates two disposable self-signed identities, runs the actual bundled actions through file and Base64 inputs, tests an incorrect password, verifies both identities can sign a compiled binary without interaction, and creates a second keychain. A separate post verifier runs after setup posts and checks exact search/default restoration and managed-directory removal, including a simulated interrupted-import residue. A disposable-runner integration check also covers nested keychains under a non-ASCII path containing spaces. No real Apple credentials are required. This proves keychain mechanics, not distribution signing, notarization, or provisioning.

Do not run the CI lifecycle manually against your everyday macOS account. Use an isolated disposable runner or dedicated user with a known baseline.

## References

- [GitHub workflow commands and action state](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands)
- [GitHub action metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax)
- [GitHub macOS signing guide](https://docs.github.com/en/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications)

## License

MIT. See [LICENSE](LICENSE).
