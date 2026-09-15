import 'package:mail_dns_check/mail_dns_check.dart';

/// Checks a domain, optionally with DKIM selectors:
///
///     dart run example/main.dart github.com google
Future<void> main(List<String> args) async {
  final domain = args.isEmpty ? 'github.com' : args.first;
  final checker = MailDnsChecker();
  try {
    final report = await checker.check(domain, dkimSelectors: args.skip(1));
    print('${report.domain}: ${report.isHealthy ? 'healthy' : 'needs work'}');
    print(
      '  MX:    ${report.mx.map((mx) => '${mx.priority} ${mx.exchange}').join(', ')}',
    );
    print(
      '  SPF:   ${report.spf?.text ?? '-'} (${report.spfLookups ?? '?'} lookups)',
    );
    print('  DMARC: ${report.dmarc?.text ?? '-'}');
    for (final MapEntry(key: selector, value: key) in report.dkim.entries) {
      final state = key == null
          ? 'missing'
          : key.isRevoked
          ? 'revoked'
          : '${key.keyType} key';
      print('  DKIM $selector: $state');
    }
    for (final issue in report.issues) {
      print('  [${issue.severity.name}] $issue');
    }
  } finally {
    checker.close();
  }
}
