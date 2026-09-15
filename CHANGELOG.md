## 0.0.1

* Initial release.
* `MailDnsChecker.check` inspects MX, SPF, DMARC, and DKIM records over
  DNS-over-HTTPS and returns a `MailDnsReport` with stable issue codes.
* SPF lookups are counted through includes and redirects against the RFC 7208
  limit of 10.
* `SpfRecord`, `DmarcRecord`, `DkimRecord`, and `MxRecord` parse record text
  without any network.
