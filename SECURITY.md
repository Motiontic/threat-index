# Security policy

## Reporting a vulnerability in Threat Index

**Please do not open a public issue.** Use GitHub's private vulnerability reporting instead: the repository's **Security** tab → **Report a vulnerability**.

Please include:

- what is affected (app or package, version or commit);
- how to reproduce it;
- the impact you expect;
- any suggested fix.

We aim to acknowledge reports within 3 working days and to share a fix plan within 10 working days. We will credit you in the release notes unless you ask us not to.

## Scope

In scope: the code in this repository, including the API's access rules (for example, a visitor receiving full-record fields), webhook verification, internal job callbacks, and handling of secrets.

Out of scope:

- vulnerabilities in the public sources we read from; report those to their owners;
- reports that rely on someone else's misconfigured deployment;
- denial of service through high request volume.

## About the data

Threat Index lists publicly disclosed vulnerabilities and incidents and does not hold undisclosed vulnerability details. If an entry needs correcting, open a normal issue with the source link.
