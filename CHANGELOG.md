## 0.0.2

* Fix SPF lookup counting following `redirect` in a record that also has an
  `all` mechanism. RFC 7208 ignores the redirect in that case.
* Report `spf_too_many_void_lookups` when more than two include or redirect
  targets return no records, and add `MailDnsReport.spfVoidLookups`.
* Add pub.dev and CI badges to the README.

## 0.0.1

* Initial release.
* `MailDnsChecker.check` inspects MX, SPF, DMARC, and DKIM records over
  DNS-over-HTTPS and returns a `MailDnsReport` with stable issue codes.
* SPF lookups are counted through includes and redirects against the RFC 7208
  limit of 10.
* `SpfRecord`, `DmarcRecord`, `DkimRecord`, and `MxRecord` parse record text
  without any network.
