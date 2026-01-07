# NAME

**certspotter-authorize** - Authorize certificates to suppress certspotter notifications

# SYNOPSIS

**certspotter-authorize** `-cert` *PATH* [`-state_dir` *PATH*]

# DESCRIPTION

**certspotter-authorize** is a utility for preemptively authorizing certificates so
that **certspotter(8)** will not send notifications when those certificates are
discovered in Certificate Transparency logs.

When **certspotter-authorize** is run with a certificate, it computes the SHA-256
hash of the certificate's TBSCertificate (the "to be signed" portion of the
certificate) and creates a `.notified` marker file in the certspotter state
directory. When certspotter later discovers a certificate with the same
TBSCertificate in a CT log, it will skip sending notifications because the marker
file indicates that you've already been notified (or in this case, preemptively
authorized the certificate).

This is useful for preventing false alarms when you know in advance that a
certificate will be issued. For example, you might run **certspotter-authorize**
immediately after requesting a certificate from your certificate authority, or as
part of your certificate issuance pipeline.

**certspotter-authorize** operates on the TBSCertificate hash, which is the same
for a certificate and its corresponding precertificate. This means authorizing
either the precertificate or the final certificate will suppress notifications
for both.

# OPTIONS

-cert *PATH*

:   Path to a PEM or DER encoded certificate. Use `-` to read from stdin.
    This option is required.

-state\_dir *PATH*

:   Directory where certspotter stores state. Defaults to
    `$CERTSPOTTER_STATE_DIR` if set, or `~/.certspotter` otherwise.
    This should be the same directory used by **certspotter(8)**.

-version

:   Print version information and exit.

# EXAMPLES

Authorize a certificate from a file:

    $ certspotter-authorize -cert /path/to/cert.pem

Authorize a certificate from stdin:

    $ cat cert.pem | certspotter-authorize -cert -

Authorize a certificate in a custom state directory:

    $ certspotter-authorize -cert cert.pem -state_dir /var/lib/certspotter

# FILES

`$STATE_DIR/certs/XX/.HASH.notified`

:   Marker files indicating that a certificate with TBSCertificate hash `HASH`
    has been authorized. `XX` is the first two hex digits of the hash.
    The file is empty; only its existence is checked.

# EXIT STATUS

**certspotter-authorize** exits with status 0 on success, 1 on error, or 2 on
invalid usage.

# CAVEATS

**certspotter-authorize** only affects notification behavior when certspotter is
saving certificates (the default). If certspotter is run with the `-no_save`
option, it will not check for `.notified` marker files and will send duplicate
notifications even for authorized certificates.

The authorization is based on the TBSCertificate hash, so it will only suppress
notifications for certificates with the exact same TBSCertificate. Certificates
issued with different serial numbers, validity periods, or other changes to the
TBSCertificate will not be covered by the authorization and will trigger
notifications.

# SEE ALSO

**certspotter(8)**, **certspotter-script(8)**

# AUTHORS

**Cert Spotter** is developed by SSLMate <<https://sslmate.com>>.
