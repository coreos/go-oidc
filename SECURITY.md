# Security Policy

This document defines the security policy for go-oidc.

## Supported versions

This project supports both the v2 and v3 branches. Do not open issues for the
v1 or master branches.

## Scope

This project prioritizes issues that can cause confusion, DoS, or bypasses in
real-world consumers of go-oidc. Reports should generally point to specific
importers of go-oidc and a Service Provider whose implementation can cause a
negative outcome for the importing project.

This project does not consider validation that could be more stringent a
vulnerability on its own, even if the code doesn't align with recommendations
in the OpenID Connect specification. See the
_["Verify azp claim"][azp-issue]_ issue for an example.

If you aren't sure if your finding qualifies, don't hesitate to reach out
through one of the channels below!

While go-oidc does not run a bug bounty, there are projects that depend on this
repo that do (given the issue impacts that project's use of go-oidc).

- https://kubernetes.io/docs/reference/issues-security/security/
- https://hackerone.com/gitlab
- See: https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc?tab=importedby

[azp-issue]: https://github.com/coreos/go-oidc/issues/355

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them via [GitHub's private vulnerability reporting][report-bug],
or email a maintainer directly (e.g. eric.chiang.m@gmail.com).

Please include as much of the following as you can:

- Type of issue (auth bypass, audience confusion, DoS)
- Affected branch and component
- A reproducer or instructions for the issue
- Project importing go-oidc that could be affected, if relevant
- OpenID Connect Provider (Google, Auth0, Azure, etc.) that could cause the
  issue, if relevant

[report-bug]: https://github.com/coreos/go-oidc/security/advisories/new

## Disclosure steps

This project will take the following steps:

- Acknowledge receipt of the report
- Determine severity
- Prepare a fix, commit it to the affected branch, tag a new release
- Publish the GitHub advisory and request a CVE

Note that if the issue is severe, it may require coordination with downstream
projects (e.g. Kubernetes). In these cases, go-oidc reserves the right to adhere
to that project's processes rather than these steps.
