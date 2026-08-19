# kubelab

## Cursor Cloud specific instructions

This repository currently contains only `README.md` (a one-line title). There is
no application code, no dependency manifests (`package.json`, `requirements.txt`,
`go.mod`, etc.), no Dockerfiles, and no services to run yet.

- There is nothing to install, build, lint, test, or run at this time. Any
  environment "setup" is effectively a no-op until real code is added.
- The VM already provides base toolchains: Node.js, Python 3, and Go.
- Once source code and a dependency manifest are added, update the Cloud Agent
  update script accordingly (e.g. `npm install`, `pip install -r requirements.txt`,
  `go mod download`) and document how to run/lint/test the resulting service(s) here.
