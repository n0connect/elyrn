# Verifying the Client

All of elyrn.'s cryptography runs in JavaScript that the server sends to the browser. A
compromised or coerced server could send a different script and read everything, so "the
server never sees plaintext" holds only if the served client is the released one. Every
release lets anyone check that, without trusting the server or its operator.

## What a release carries

The release workflow (`.github/workflows/release.yml`) runs on each `elyrn-*-vX.Y.Z` tag and,
only when the tagged commit is an ancestor of `main` (checked by `make check-release-commit`
from a separate checkout of `main`, before anything is signed), attaches two files. It never
replaces an asset: a re-run on a release that already carries them, or a moved tag, fails.

| File | Contents |
|---|---|
| `frontend.sha256` | SHA-256 of every file the frontend serves (`make manifest`: tracked files only) |
| `frontend.sha256.sigstore.json` | Sigstore keyless signature of that list, issued to this repository's release workflow for that tag |

There is no signing key to steal or lose: the signature is bound to the GitHub workflow
identity and recorded in Sigstore's public transparency log.

## Checking an instance

1. Download both files from the release you expect the instance to run.
2. In your own clone of the repository, find the tag's commit and check that it is on `main`:

   ```bash
   git fetch origin main --tags
   TAG=elyrn-openssl-v1.2.3                       # the release you expect
   SHA=$(git rev-parse "refs/tags/$TAG^{commit}")
   git merge-base --is-ancestor "$SHA" origin/main && echo "on main"
   ```

3. Check the list is the one the release workflow signed, for exactly that tag and that commit:

   ```bash
   cosign verify-blob --bundle frontend.sha256.sigstore.json \
     --certificate-identity "https://github.com/n0connect/elyrn/.github/workflows/release.yml@refs/tags/$TAG" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-github-workflow-repository n0connect/elyrn \
     --certificate-github-workflow-ref "refs/tags/$TAG" \
     --certificate-github-workflow-sha "$SHA" \
     --certificate-github-workflow-trigger push \
     frontend.sha256
   ```

   The flags are those of `cosign verify-blob` (cosign's `doc/cosign_verify-blob.md`): the
   identity is the exact workflow file at the exact tag, and `--certificate-github-workflow-sha`
   binds the signature to the commit step 2 found on `main`. The certificate cannot name
   `refs/heads/main` itself: the workflow runs on the tag push, so its ref is the tag. "On
   `main`" is proven by step 2 against the signed SHA; skip step 2 and a signature made for a
   commit that never reached `main` passes step 3 (see below).

4. Check the instance serves exactly those bytes:

   ```bash
   make verify-frontend URL=https://chat.example MANIFEST=frontend.sha256
   # an onion service, through Tor Browser's SOCKS proxy:
   make verify-frontend URL=http://<address>.onion CURL_OPTS="--socks5-hostname 127.0.0.1:9150"
   ```

   Any file that differs is printed as `[MISMATCH] /path` and the command fails.

## What this does and does not prove

It proves what the instance served to **this** request. A targeted server could serve the
released client to verifiers and a modified one to a chosen user. Closing that gap needs a
client the browser does not fetch from the server each time (a packaged client or a
verifying extension), which this project does not have. A compromised server is outside what
the project can change ([threat model](threat-model.md#conditions-of-the-design)); this check is
how a user or auditor can find one out.

### What rests on the hosted repository's rules

GitHub runs the release workflow as the **tagged commit** holds it. The ancestry check in the
workflow therefore binds an honest tag only: anyone who may push an `elyrn-*-v*` tag may tag an
unmerged commit whose own `release.yml` skips the check, and that run signs with the same
identity form. Nothing inside the repository can stop that run; what stands against it is:

- **your step 2**: the signed commit is not on `main`, so the check fails whatever the workflow
  did. This rests on `main` itself: whoever may push to `main` (or force-push it) decides what
  is "on `main`", which is the hosted branch protection of `main`;
- **hosted tag rules**: a repository ruleset that restricts creating, moving and deleting
  `refs/tags/elyrn-*-v*` to the release owner closes it for verifiers who skip step 2 too, and
  keeps a published tag from being moved (the workflow refuses to sign once the release carries
  a manifest, but whoever may delete the release and move the tag gets a second signature under
  the same tag name; your step 2 and the pinned SHA tell the two apart);
- **who may run the workflow at all** (writers, apps and tokens with `contents: write`, re-run
  permissions, environment approvals): hosted settings, not in the repository.

The `frontend.sha256` committed in the repository is not the reference: the release workflow
writes a fresh one with `make manifest` from the tagged tree and signs that. Always take the
manifest from the release.
