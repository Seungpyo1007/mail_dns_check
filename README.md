<p align="center">
  <img src="https://raw.githubusercontent.com/Seungpyo1007/mail_dns_check/main/assets/mail_dns_check-logo.png" alt="mail_dns_check logo: an envelope with a check badge" width="128">
</p>

<h1 align="center">mail_dns_check</h1>

<p align="center">
  <a href="https://pub.dev/packages/mail_dns_check"><img src="https://img.shields.io/pub/v/mail_dns_check" alt="pub version"></a>
  <a href="https://pub.dev/packages/mail_dns_check/score"><img src="https://img.shields.io/pub/points/mail_dns_check" alt="pub points"></a>
  <a href="https://github.com/Seungpyo1007/mail_dns_check/actions/workflows/ci.yml"><img src="https://github.com/Seungpyo1007/mail_dns_check/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Seungpyo1007/mail_dns_check/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
</p>

Check whether a domain's email DNS is set up correctly: SPF, DMARC, DKIM, and
MX records, with a stable issue code for every problem. Queries go through
public DNS-over-HTTPS, so there is no API key and no paid service in between.

```dart
final checker = MailDnsChecker();
final report = await checker.check('github.com', dkimSelectors: ['google']);

print(report.dmarc?.policy); // quarantine
print(report.spfLookups);    // DNS lookups SPF evaluation needs
for (final issue in report.issues) {
  print('${issue.severity.name} ${issue.code}: ${issue.message}');
}

checker.close();
```

## Platform support

Pure Dart on top of `package:http`: Dart VM, Flutter on Android, iOS, Windows,
macOS, Linux, and the web. The default resolver, Cloudflare DNS, and Google
Public DNS (`https://dns.google/resolve`) both send
`Access-Control-Allow-Origin: *`, so checks also run in the browser.

## Features

- **MX**: records sorted by priority, missing MX, and null MX (RFC 7505).
- **SPF**: parsed terms, duplicate records, unknown mechanisms, `+all`, a
  missing `all`, deprecated `ptr`, includes without SPF, and the RFC 7208
  limits of 10 DNS lookups and two void lookups, counted through includes and
  redirects. A `redirect` next to `all` is ignored, as the RFC requires.
- **DMARC**: parsed tags, duplicate records, a missing or invalid policy,
  `p=none`, partial `pct`, and missing aggregate reports.
- **DKIM**: keys for the selectors you pass, followed through CNAMEs, and
  revoked keys.
- DNS failures become `lookup_failed` issues instead of exceptions or false
  "missing record" reports.
- Parsers (`SpfRecord.parse`, `DmarcRecord.parse`, `DkimRecord.parse`,
  `MxRecord.tryParse`) work on plain strings without any network.

## Installation

```yaml
dependencies:
  mail_dns_check: ^0.0.3
```

## Issue codes

| Code | Severity | Meaning |
| --- | --- | --- |
| `mx_missing` | warning | No MX record |
| `mx_null` | info | Null MX: the domain accepts no mail |
| `spf_missing` | warning | No SPF record |
| `spf_multiple` | error | More than one SPF record |
| `spf_invalid` | error | Unknown SPF mechanism |
| `spf_plus_all` | error | `+all` allows every sender |
| `spf_no_all` | warning | No `all` mechanism or `redirect` |
| `spf_ptr` | warning | Deprecated `ptr` mechanism |
| `spf_include_missing` | error | An include or redirect target has no SPF record |
| `spf_too_many_lookups` | error | More than 10 DNS lookups |
| `spf_too_many_void_lookups` | error | More than two include or redirect targets with no records |
| `dmarc_missing` | warning | No DMARC record |
| `dmarc_multiple` | error | More than one DMARC record |
| `dmarc_invalid` | error | Missing or unknown `p=` policy |
| `dmarc_policy_none` | info | `p=none` only monitors |
| `dmarc_pct_partial` | info | `pct` below 100 |
| `dmarc_no_rua` | info | No aggregate report address |
| `dkim_missing` | warning | No key for a selector |
| `dkim_revoked` | warning | Empty `p=` key |
| `lookup_failed` | error | A DNS query failed or timed out |

`report.isHealthy` is `true` when every issue is `info`.

## Usage

Use another resolver, a shorter timeout, or your own `http.Client`:

```dart
final checker = MailDnsChecker(
  endpoint: Uri.parse('https://dns.google/resolve'),
  timeout: const Duration(seconds: 5),
);
```

An injected client is not closed by `close()`.

## Limitations

- DKIM selectors are not discoverable through DNS. Pass the ones your mail
  provider uses, such as `google` for Google Workspace or `selector1` and
  `selector2` for Microsoft 365.
- A subdomain without its own DMARC record is reported as `dmarc_missing`,
  even when the organizational domain's record covers it.
- SPF macros such as `%{i}` are not expanded, and the targets of `a:`, `mx:`,
  and `exists:` are not resolved: they count toward the limit of 10 lookups but
  not toward the void lookup limit.
- Every queried name is sent to the DNS-over-HTTPS resolver.

## Flutter example

```dart
FutureBuilder<MailDnsReport>(
  future: checker.check('seungpyo.online'),
  builder: (context, snapshot) {
    final report = snapshot.data;
    if (report == null) return const LinearProgressIndicator();
    return Column(
      children: [
        for (final issue in report.issues)
          ListTile(title: Text(issue.code), subtitle: Text(issue.message)),
      ],
    );
  },
)
```
