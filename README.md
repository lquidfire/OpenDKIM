_Please note: This is a work in progress, attempting to bring
OpenDKIM up-to-date, to develop it further, and maintain it.
Please be patient as changes are made - the documentation might
not always be 100% up-to-date._


# OpenDKIM

OpenDKIM is a community effort to develop and maintain both an open
source library for adding DomainKeys Identified Mail (DKIM) support
to applications and an example filter application using the milter
protocol for providing a DKIM service.

## Introduction

DKIM (Domain Keys Identified Mail) is an email authentication method,
defined in [RFC6376](https://datatracker.ietf.org/doc/rfc6376/), that uses cryptographic signatures to verify
that an email was sent by an authorized domain and hasn't been
tampered with in transit.

The DKIM sender authentication system was originally created by the E-mail
Signing Technology Group (ESTG) and is now a Standard of the
IETF (RFC6376).  DKIM is an amalgamation of the DomainKeys (DK) proposal by
Yahoo!, Inc. and the Internet Identified Mail (IIM) proposal by Cisco.

"milter" is a portmanteau of "mail filter" and refers to a protocol and API
for communicating mail traffic information between MTAs and mail filtering
plug-in applications.  It was originally invented at Sendmail, Inc. but
has also been adapted to other MTAs.

This package consists of a library that implements the DKIM service and a
milter-based filter application that can plug in to any milter-aware MTA to
provide that service to sufficiently recent sendmail, Postfix or other MTAs
that support the milter protocol.

An optional asynchronous resolver library is also provided to work around
limitations of the basic BIND resolver which comes installed on most
systems.

This code continues the effort by the Trusted Domain Project, which
started as a code fork of version 2.8.3 of the open source
`dkim-milter` package developed and maintained by Sendmail, Inc.

This project takes much inspiration from the efforts of @flowerysong,
who brought the OpenARC project up to date.

The license used by OpenDKIM and OpenARC is found in the `LICENSE`
file. Portions of this project are also covered by the Sendmail
Open Source License, which can be found in the `LICENSE.Sendmail`
file. See the copyright notice(s) in each source file to determine
which license(s) are applicable to that file.

## Dependencies

In order to build OpenDKIM, you will need:

* A C compiler. Compilation has been tested with [GCC](https://gcc.gnu.org/)
  and [clang](https://clang.llvm.org/), and other modern compilers should also
  work.
* make
* pkg-config or a compatible replacement.
* [OpenSSL](https://openssl.org/) >= 1.0.0
  OpenSSL >= 1.1.1 is required for ED25519 support.
* Native implementations of `strlcat()` and `strlcpy()`,
  [libbsd](https://libbsd.freedesktop.org/), or some other library that
  provides them.

If you are building the filter, you will also need:

* [libmilter](https://sendmail.org/)
* (optional) [Jansson](https://github.com/akheron/jansson) >= 2.2.1 ?

If you are building from a git checkout instead of a release tarball,
you will also need:

* [Autoconf](https://www.gnu.org/software/autoconf/) >= 2.61
* [Automake](https://www.gnu.org/software/automake/) >= 1.11.1
* [libtool](https://www.gnu.org/software/libtool/) >= 2.2.6

The core OpenDKIM software will function without it, but tools distributed
alongside OpenDKIM (such as `opendkim-keygen`) may require:

* Python >= 3.8

Compatibility with older versions of Python 3 has not been
deliberately broken, but this is the oldest version we test against.

If you wish to interface the filter with SQL databases, or store statistical
information in a database, a database will be required.

If you wish to use the Lua interpreter hooks for filter policy control, or
statistical extensions (--enable-statsext), Lua v5.1 or later is required.

If you wish to interface the filter with LDAP servers, OpenLDAP v2.1.3
or later is required.

For local hash or btree database support in either the filter or the
library, Oracle's BerkeleyDB is required.  All versions are supported.

### DNF-based systems

```
dnf install autoconf automake gcc jansson-devel libbsd-devel libidn2-devel libtool openssl-devel sendmail-milter-devel
```

### Ubuntu

```
apt install build-essential libbsd-dev libidn2-dev libjansson-dev libmilter-dev libssl-dev
```

### FreeBSD

```
pkg install autoconf autoconf-archive automake jansson libidn2 libtool pkgconf
```

### Alpine
```
apk add autoconf automake bsd-compat-headers gcc jansson-dev libidn2-dev libmilter-dev libtool make musl-dev openssl-dev
```

## Installation

Installation follows the standard Autotools process.

If you're building from a git checkout, you first need to generate the
build system:

```
$ autoreconf -fiv
```

Once that's done (or if you're building from a release tarball):

```
$ ./configure
$ make
$ make install
```

You can get a list of available flags and environment variables to
influence the build by running `./configure --help`.

## Additional Documentation

The man page for opendkim (the actual filter program) is present in the
opendkim directory of this source distribution.  There is additional
information in the INSTALL and FEATURES files, and in the README file in the
opendkim directory.  Changes are documented in the RELEASE_NOTES file.

HTML-style documentation for libopendkim is available in libopendkim/docs in
this source distribution.

General information about DKIM can be found at http://www.dkim.org

Bug tracking is done via the GitHub, 
[https://github.com/lquidfire/opendkim](https://github.com/lquidfire/opendkim). You can enter new bug
reports there, but please check first for older bugs already open,
or even already closed, before opening a new issue.


+---------------------+
| DIRECTORY STRUCTURE |
+---------------------+

contrib		A collection of user contributed scripts that may be useful.

docs		A collection of RFCs and drafts related to opendkim.

libar		An optional thread-safe asynchronous resolver library.

libopendkim	A library that implements the proposed DKIM standard.

libopendkim/docs HTML documentation describing the API provided by libopendkim.

libvbr		An optional library that implements Vouch By Reference
		(VBR, RFC5518).

opendkim	A milter-based filter application which uses libopenkim (and
		optionally libar) to provide DKIM service via an MTA using
		the milter protocol.

## Legality

A number of legal regimes restrict the use or export of cryptography.
If you are potentially subject to such restrictions you should seek
legal advice before using, developing, or distributing cryptographic
code.

## Known Runtime Issues

### WARNING: symbol 'X' not available

The filter attempted to get some information from the MTA that the MTA
did not provide.

At various points in the interaction between the MTA and the filter,
macros containing information about the job in progress or the
connection being handled are passed from the MTA to the filter.

In the case of Sendmail, the names of the macros the MTA should
pass to the filter are defined by the `Milter.macros` settings in
`sendmail.cf`, e.g. `Milter.macros.connect`, `Milter.macros.envfrom`,
etc. This message indicates that the filter needed the contents of
macro `X`, but that macro was not passed down from the MTA.

Typically the values needed by this filter are passed from the MTA if
the `sendmail.cf` was generated by the usual M4 method. If you do not
have those options defined in your `sendmail.cf`, try rebuilding it
and then restarting Sendmail.

### MTA Timeouts

Querying nameservers for key data can take longer than the default MTA
timeouts for communication with the filter. This can cause messages to
be rejected, tempfailed, or delivered without processing by the filter,
depending on the MTA configuration.

The only way to address this issue if you encounter it is to increase
the time the MTA waits for replies. Consult your MTA's documentation
to find out how to do so, but note that increasing timeouts too much
can cause other problems.

### `d2i_PUBKEY_bio()` failed

After retrieving and decoding a public key to perform a message
verification, the OpenSSL library attempted to make use of that key
but failed. The known possible causes are:

* Memory exhaustion
* Key corruption

If you're set to tempfail messages in these cases the remote end
will probably retry the message. If the same message fails again
later, the key is probably corrupted or otherwise invalid.
