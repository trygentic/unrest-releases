# Unrest releases

Downloads for the Unrest Launcher and GameGen.

Get the latest build from the [Releases](https://github.com/trygentic/unrest-releases/releases) page.
Each release lists a `SHA256SUMS` file; check a download against it before running it.

These are beta builds:

- **macOS (Apple Silicon):** check the release notes for Apple signing and notarization status. Signed and notarized releases open with a double-click.
- **Windows (x64):** SmartScreen may warn about an unrecognized app; choose **More info**, then **Run anyway**.

This repository holds release packages and the workflow that builds them. The source lives elsewhere.

## Checking Apple signing settings

After changing Apple signing credentials or accepting a new developer agreement,
run **Check Apple signing** before starting a full release:

```sh
gh workflow run apple-preflight.yml --repo trygentic/unrest-releases
```

It uses the release's existing signing script to import the Developer ID
certificate and ask Apple whether notarization access works. It does not build,
sign, upload, or publish an app. Its temporary keychain and key file are removed
even if a check fails.
