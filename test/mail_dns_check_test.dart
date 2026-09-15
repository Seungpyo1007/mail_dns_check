import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:mail_dns_check/mail_dns_check.dart';
import 'package:test/test.dart';

/// Answers DoH queries from [zone], keyed by `name TYPE`. A value is either a
/// list of answers or an [http.Response]; a missing key is NXDOMAIN.
MockClientHandler _zone(Map<String, Object> zone, [List<String>? log]) {
  return (request) async {
    final query = request.url.queryParameters;
    final key = '${query['name']} ${query['type']}';
    log?.add(key);
    final value = zone[key];
    if (value is http.Response) return value;
    if (value == null) return http.Response(jsonEncode({'Status': 3}), 200);
    return http.Response(jsonEncode({'Status': 0, 'Answer': value}), 200);
  };
}

List<Map<String, Object>> _txt(List<String> texts) => [
  for (final text in texts) {'type': 16, 'data': '"$text"'},
];

List<String> _codes(MailDnsReport report) => [
  for (final issue in report.issues) issue.code,
];

Future<MailDnsReport> _check(
  Map<String, Object> zone, {
  List<String> selectors = const [],
}) => MailDnsChecker(
  client: MockClient(_zone(zone)),
).check('example.com', dkimSelectors: selectors);

final _healthy = <String, Object>{
  'example.com MX': [
    {'type': 15, 'data': '20 backup.example.com.'},
    {'type': 15, 'data': '10 mx.example.com.'},
  ],
  'example.com TXT': _txt([
    'google-site-verification=abc',
    'v=spf1 ip4:192.0.2.0/24 include:_spf.mail.test -all',
  ]),
  '_spf.mail.test TXT': _txt(['v=spf1 ip4:198.51.100.0/24 ~all']),
  '_dmarc.example.com TXT': _txt([
    'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
  ]),
  'mail._domainkey.example.com TXT': _txt([
    'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB',
  ]),
};

void main() {
  group('parsers', () {
    test('SPF terms, qualifiers, and modifiers', () {
      final spf = SpfRecord.parse(
        'v=spf1 include:_spf.google.com ip6:2001:db8::/32 a/24 ?mx '
        'redirect=_spf.example.com ~all',
      )!;

      expect(spf.includes, ['_spf.google.com']);
      expect(spf.allQualifier, '~');
      expect(spf.redirect, '_spf.example.com');
      expect(spf.terms[1].name, 'ip6');
      expect(spf.terms[1].value, '2001:db8::/32');
      expect(spf.terms[2].value, '/24');
      expect(spf.terms[3].qualifier, '?');
      expect(spf.terms.every((term) => term.isKnown), isTrue);

      expect(SpfRecord.parse('google-site-verification=abc'), isNull);
      expect(SpfRecord.parse('v=spf10 -all'), isNull);
      expect(SpfRecord.parse('V=SPF1 -all')!.allQualifier, '-');
      expect(
        SpfRecord.parse('v=spf1 ip5:192.0.2.1')!.terms.single.isKnown,
        isFalse,
      );
    });

    test('DMARC tags from the live github.com record', () {
      final dmarc = DmarcRecord.parse(
        'v=DMARC1; p=quarantine; sp=reject; pct=100; '
        'rua=mailto:dmarc@github.com; ruf=mailto:dmarc@github.com; fo=1',
      )!;

      expect(dmarc.policy, 'quarantine');
      expect(dmarc.subdomainPolicy, 'reject');
      expect(dmarc.percent, 100);
      expect(dmarc.aggregateReportUris, ['mailto:dmarc@github.com']);
      expect(dmarc.tags['fo'], '1');
      expect(DmarcRecord.parse('p=reject; v=DMARC1'), isNull);
    });

    test('DKIM keys, including a revoked one', () {
      expect(DkimRecord.parse('v=DKIM1; k=rsa; p=')!.isRevoked, isTrue);

      final key = DkimRecord.parse('k=rsa; t=s; p=MIGf MA0G')!;
      expect(key.isRevoked, isFalse);
      expect(key.publicKey, 'MIGfMA0G');
      expect(key.keyType, 'rsa');

      expect(DkimRecord.parse('v=spf1 -all'), isNull);
      expect(DkimRecord.parse('v=DKIM2; p=abc'), isNull);
    });

    test('MX records, including a null MX', () {
      final mx = MxRecord.tryParse('10 smtp.google.com.')!;
      expect(mx.priority, 10);
      expect(mx.exchange, 'smtp.google.com');
      expect(MxRecord.tryParse('0 .')!.isNull, isTrue);
      expect(MxRecord.tryParse('smtp.google.com'), isNull);
    });
  });

  group('MailDnsChecker', () {
    test('reports a well-configured domain as healthy', () async {
      final log = <String>[];
      final report = await MailDnsChecker(
        client: MockClient(_zone(_healthy, log)),
      ).check(' Example.COM. ', dkimSelectors: ['mail']);

      expect(report.domain, 'example.com');
      expect(report.issues, isEmpty);
      expect(report.isHealthy, isTrue);
      expect(
        [for (final mx in report.mx) mx.exchange],
        ['mx.example.com', 'backup.example.com'],
      );
      expect(
        report.spf!.text,
        'v=spf1 ip4:192.0.2.0/24 include:_spf.mail.test -all',
      );
      expect(report.spfLookups, 1);
      expect(report.dmarc!.policy, 'reject');
      expect(report.dkim['mail']!.isRevoked, isFalse);
      expect(log, contains('_spf.mail.test TXT'));
    });

    test('reports missing records', () async {
      final report = await _check({}, selectors: ['mail']);

      expect(_codes(report), [
        'mx_missing',
        'spf_missing',
        'dmarc_missing',
        'dkim_missing',
      ]);
      expect(report.isHealthy, isFalse);
      expect(report.spf, isNull);
      expect(report.dkim, {'mail': null});
    });

    test('flags duplicate, unknown, ptr, and +all SPF terms', () async {
      final report = await _check({
        ..._healthy,
        'example.com TXT': _txt([
          'v=spf1 ptr ip5:192.0.2.1 +all',
          'v=spf1 -all',
        ]),
      });

      expect(
        _codes(report),
        containsAll(['spf_multiple', 'spf_invalid', 'spf_ptr', 'spf_plus_all']),
      );
      expect(report.spfLookups, 1);
      expect(report.isHealthy, isFalse);
    });

    test('counts SPF lookups through includes and survives loops', () async {
      final tooMany = await _check({
        ..._healthy,
        'example.com TXT': _txt([
          'v=spf1 include:a.test include:b.test include:c.test include:d.test -all',
        ]),
        for (final host in ['a', 'b', 'c', 'd'])
          '$host.test TXT': _txt(['v=spf1 a mx -all']),
      });
      expect(tooMany.spfLookups, greaterThan(10));
      expect(_codes(tooMany), contains('spf_too_many_lookups'));

      final loop = await _check({
        ..._healthy,
        'example.com TXT': _txt(['v=spf1 include:loop.test -all']),
        'loop.test TXT': _txt([
          'v=spf1 include:example.com include:loop.test -all',
        ]),
      });
      expect(loop.spfLookups, 3);
      expect(loop.issues, isEmpty);
    });

    test('counts a record included twice every time', () async {
      final report = await _check({
        ..._healthy,
        'example.com TXT': _txt(['v=spf1 include:a.test include:b.test -all']),
        'a.test TXT': _txt(['v=spf1 include:shared.test -all']),
        'b.test TXT': _txt(['v=spf1 include:shared.test -all']),
        'shared.test TXT': _txt(['v=spf1 a mx -all']),
      });

      // a.test, shared.test, a, mx, then b.test, shared.test, a, mx.
      expect(report.spfLookups, 8);
      expect(report.issues, isEmpty);
    });

    test('flags an include without SPF and a record without all', () async {
      final report = await _check({
        ..._healthy,
        'example.com TXT': _txt(['v=spf1 include:gone.test']),
      });

      expect(_codes(report), ['spf_no_all', 'spf_include_missing']);
    });

    test('reports weak DMARC settings as information', () async {
      final report = await _check({
        ..._healthy,
        '_dmarc.example.com TXT': _txt(['v=DMARC1; p=none; pct=50']),
      });

      expect(_codes(report), [
        'dmarc_policy_none',
        'dmarc_pct_partial',
        'dmarc_no_rua',
      ]);
      expect(report.isHealthy, isTrue);
    });

    test('flags duplicate and invalid DMARC records', () async {
      final report = await _check({
        ..._healthy,
        '_dmarc.example.com TXT': _txt([
          'v=DMARC1; sp=reject; rua=mailto:d@example.com',
          'v=DMARC1; p=reject',
        ]),
      });

      expect(_codes(report), ['dmarc_multiple', 'dmarc_invalid']);
    });

    test('follows CNAME answers to DKIM keys and flags revoked keys', () async {
      final report = await _check(
        {
          ..._healthy,
          's1._domainkey.example.com TXT': [
            {'type': 5, 'data': 's1.domainkey.u1.wl.sendgrid.net.'},
            {'type': 16, 'data': '"k=rsa; t=s; p=MIGfMA0G"'},
          ],
          'old._domainkey.example.com TXT': _txt(['v=DKIM1; k=rsa; p=']),
        },
        selectors: ['s1', 'old', 'S1'],
      );

      expect(report.dkim.keys, ['s1', 'old']);
      expect(report.dkim['s1']!.publicKey, 'MIGfMA0G');
      expect(_codes(report), ['dkim_revoked']);
    });

    test('joins split TXT strings and decodes escapes', () async {
      final report = await _check({
        ..._healthy,
        'example.com TXT': [
          {'type': 16, 'data': '"v=spf1 ip4:192.0.2.1 " "-all"'},
        ],
        '_dmarc.example.com TXT': [
          {
            'type': 16,
            'data': r'"v=DMARC1\059 p=reject\059 rua=mailto:d@x.test"',
          },
        ],
      });

      expect(report.spf!.text, 'v=spf1 ip4:192.0.2.1 -all');
      expect(report.dmarc!.policy, 'reject');
      expect(report.issues, isEmpty);
    });

    test(
      'turns DNS failures into lookup_failed without false alarms',
      () async {
        final report = await _check({
          ..._healthy,
          'example.com TXT': http.Response('', 500),
          '_dmarc.example.com TXT': http.Response(
            jsonEncode({'Status': 2}),
            200,
          ),
          'example.com MX': http.Response('<html>', 200),
        });

        expect(_codes(report), [
          'lookup_failed',
          'lookup_failed',
          'lookup_failed',
        ]);
        expect(report.spf, isNull);
        expect(report.isHealthy, isFalse);
      },
    );

    test('retries a query once when the connection drops', () async {
      var dropped = 0;
      final handler = _zone(_healthy);
      final report = await MailDnsChecker(
        client: MockClient((request) async {
          if (request.url.queryParameters['type'] == 'MX' && dropped++ == 0) {
            throw http.ClientException('Connection closed', request.url);
          }
          return handler(request);
        }),
      ).check('example.com');

      expect(dropped, 2);
      expect(report.mx, hasLength(2));
      expect(report.issues, isEmpty);
    });

    test('ignores redirect when the record has all', () async {
      final log = <String>[];
      final report = await MailDnsChecker(
        client: MockClient(
          _zone({
            ..._healthy,
            'example.com TXT': _txt(['v=spf1 -all redirect=gone.test']),
          }, log),
        ),
      ).check('example.com');

      expect(report.spfLookups, 0);
      expect(report.spfVoidLookups, 0);
      expect(report.issues, isEmpty);
      expect(log, isNot(contains('gone.test TXT')));
    });

    test('flags more than two void lookups', () async {
      final report = await _check({
        ..._healthy,
        'example.com TXT': _txt([
          'v=spf1 include:a.test include:b.test include:c.test -all',
        ]),
      });

      expect(report.spfLookups, 3);
      expect(report.spfVoidLookups, 3);
      expect(
        _codes(report),
        containsAll(['spf_include_missing', 'spf_too_many_void_lookups']),
      );
    });

    test('reports a null MX as information', () async {
      final report = await _check({
        ..._healthy,
        'example.com MX': [
          {'type': 15, 'data': '0 .'},
        ],
      });

      expect(_codes(report), ['mx_null']);
    });

    test('rejects malformed domains and selectors', () async {
      final checker = MailDnsChecker(client: MockClient(_zone({})));

      expect(() => checker.check('not a domain'), throwsFormatException);
      expect(() => checker.check('localhost'), throwsFormatException);
      expect(
        () => checker.check('example.com', dkimSelectors: ['bad selector']),
        throwsFormatException,
      );
    });
  });
}
