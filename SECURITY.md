<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Security Policy

LinuxDoctor is maintained by one person, on a voluntary basis. This page explains how to report a security problem and what you can expect in return.

## Supported versions

Only the **latest release** receives security fixes. If you use an older version, please update first: the packages are on the [Releases page](https://github.com/gillesmagneville/linuxdoctor/releases) and the changes are listed in the [CHANGELOG](CHANGELOG.md).

## Reporting a vulnerability

**Please do not report a vulnerability in a public issue, pull request or discussion**: anyone could read it before a fix exists.

Report it privately, in one of these two ways:

1. **On GitHub**: open the [Security tab](https://github.com/gillesmagneville/linuxdoctor/security) of the repository and click **Report a vulnerability**. Only you and the maintainer can see the report.
2. **By email**: write to [gilles@magneville.fr](mailto:gilles@magneville.fr) with the subject "LinuxDoctor security".

Please include, as far as you can:

- the version (`linuxdoctor --version`), the package format (`.deb` or `.rpm`), your distribution and kernel version;
- the command you ran, with or without root privileges;
- a description of the problem and the steps to reproduce it;
- what you think the impact is.

A LinuxDoctor report describes the machine it was made on (host names, addresses, users…): remove what is sensitive before attaching one, even to a private report.

## What to expect

These are goals, not guarantees, since there is only one maintainer:

- an acknowledgement of your report within **7 days**;
- an answer on whether it is considered a vulnerability, then news at least every few weeks until it is settled;
- a fix published in a **new release**, mentioned in the CHANGELOG; for a serious problem, a GitHub security advisory too;
- you are credited in the release notes, unless you prefer to stay anonymous.

Please keep the details private until a fixed version is available, so that users have the time to update.

## What is covered

LinuxDoctor runs on the machine it examines and makes no network connection of its own. It is meant to be **read-only**, and it is often run with root privileges, on data that other people can influence: log lines, file names, mount points, container or virtual machine names, configuration files. A report is relevant, for example, if:

- LinuxDoctor changes something on the machine (a file, a setting, a service, a package), or runs a command it was not meant to run;
- data coming from the examined machine makes it run code or crash in an exploitable way, or reaches your terminal, or a JSON, Markdown or HTML report, in a harmful way (terminal escape sequences, a script in the HTML report…);
- LinuxDoctor, or its configuration file, can be used to gain privileges;
- the `.deb` or `.rpm` package, or the packaging scripts, can be abused;
- a file of a release does not match its published `.sha256` fingerprint.

## What is not covered

- A **finding of an audit** about your system (a weak SSH setting, an old kernel…) is not a vulnerability of LinuxDoctor. A finding that is wrong or misleading is an ordinary bug: please open an [issue](https://github.com/gillesmagneville/linuxdoctor/issues).
- A vulnerability in a **tool that LinuxDoctor uses when it is installed** (`smartctl`, `virsh`, `docker`, `podman`, `journalctl`, `dmesg`…): please report it to that project.
- A vulnerability in a **Rust library built into the program**: please report it to that project, and tell me as well, since the fix needs a new release.
- Problems that need a computer which is already compromised, or physical access to it.
- Ordinary bugs without security consequences: please open an [issue](https://github.com/gillesmagneville/linuxdoctor/issues) instead.

## Checking what you download

Download the packages only from the [Releases page](https://github.com/gillesmagneville/linuxdoctor/releases) of this repository. Each package is published with its own `.sha256` file. To check a download, put the package and its `.sha256` file in the same folder:

```bash
sha256sum -c <package>.sha256
```
