import 'package:http/http.dart' as http;

import 'doh.dart';
import 'records.dart';

/// Checks the MX, SPF, DMARC, and DKIM records of a domain through public
/// DNS-over-HTTPS.
class MailDnsChecker {
  /// Creates a checker that queries [endpoint], Cloudflare DNS by default.
  ///
  /// A DNS query that takes longer than [timeout] is reported as a
  /// `lookup_failed` issue.
  MailDnsChecker({
    http.Client? client,
    Uri? endpoint,
    this.timeout = const Duration(seconds: 10),
  }) : _client = client ?? http.Client(),
       _ownsClient = client == null,
       endpoint = endpoint ?? Uri.parse('https://cloudflare-dns.com/dns-query');

  final http.Client _client;
  final bool _ownsClient;
  late final DohResolver _doh = DohResolver(_client, endpoint, timeout);

  /// DNS-over-HTTPS JSON endpoint.
  final Uri endpoint;

  /// Time limit for each DNS query.
  final Duration timeout;

  /// Closes the HTTP client this instance created. An injected client is left
  /// open for its owner.
  void close() {
    if (_ownsClient) _client.close();
  }

  /// Checks [domain] and the DKIM keys of [dkimSelectors].
  ///
  /// DNS failures become `lookup_failed` issues instead of exceptions. Throws a
  /// [FormatException] when [domain] or a selector is malformed.
  Future<MailDnsReport> check(
    String domain, {
    Iterable<String> dkimSelectors = const <String>[],
  }) async {
    final name = _normalize(domain, isDomain: true);
    final selectors = {
      for (final selector in dkimSelectors)
        _normalize(selector, isDomain: false),
    }.toList(growable: false);

    final (mx, spf, dmarc, dkim) = await (
      _checkMx(name),
      _checkSpf(name),
      _checkDmarc(name),
      _checkDkim(name, selectors),
    ).wait;

    return MailDnsReport(
      domain: name,
      checkedAt: DateTime.now().toUtc(),
      mx: mx.records,
      spf: spf.record,
      spfLookups: spf.lookups,
      spfVoidLookups: spf.voidLookups,
      dmarc: dmarc.record,
      dkim: dkim.records,
      issues: [...mx.issues, ...spf.issues, ...dmarc.issues, ...dkim.issues],
    );
  }

  Future<({List<MxRecord> records, List<MailDnsIssue> issues})> _checkMx(
    String domain,
  ) async {
    final issues = <MailDnsIssue>[];
    final answers = await _lookup(domain, 'MX', issues);
    final records = [...?answers?.map(MxRecord.tryParse).nonNulls]
      ..sort((a, b) => a.priority.compareTo(b.priority));
    if (answers != null && records.isEmpty) {
      issues.add(
        MailDnsIssue(
          code: 'mx_missing',
          message:
              '$domain has no MX record, so senders fall back to its A record.',
        ),
      );
    } else if (records.length == 1 && records.single.isNull) {
      issues.add(
        MailDnsIssue(
          code: 'mx_null',
          message: '$domain publishes a null MX and accepts no mail.',
          severity: MailDnsSeverity.info,
        ),
      );
    }
    return (records: records, issues: issues);
  }

  Future<
    ({
      SpfRecord? record,
      int? lookups,
      int? voidLookups,
      List<MailDnsIssue> issues,
    })
  >
  _checkSpf(String domain) async {
    final issues = <MailDnsIssue>[];
    final answers = await _lookup(domain, 'TXT', issues);
    final records = [...?answers?.map(SpfRecord.parse).nonNulls];
    if (answers == null || records.isEmpty) {
      if (answers != null) {
        issues.add(
          MailDnsIssue(
            code: 'spf_missing',
            message:
                '$domain has no SPF record, so receivers cannot tell which '
                'servers may send its mail.',
          ),
        );
      }
      return (record: null, lookups: null, voidLookups: null, issues: issues);
    }

    if (records.length > 1) {
      issues.add(
        MailDnsIssue(
          code: 'spf_multiple',
          message:
              '$domain has ${records.length} SPF records; receivers treat '
              'this as a permanent error.',
          severity: MailDnsSeverity.error,
        ),
      );
    }
    final spf = records.first;
    for (final term in spf.terms.where((term) => !term.isKnown)) {
      issues.add(
        MailDnsIssue(
          code: 'spf_invalid',
          message: 'Unknown SPF mechanism "${term.name}".',
          severity: MailDnsSeverity.error,
        ),
      );
    }
    if (spf.terms.any((term) => !term.isModifier && term.name == 'ptr')) {
      issues.add(
        const MailDnsIssue(
          code: 'spf_ptr',
          message: 'The ptr mechanism is slow and deprecated by RFC 7208.',
        ),
      );
    }
    final all = spf.allQualifier;
    if (all == '+') {
      issues.add(
        MailDnsIssue(
          code: 'spf_plus_all',
          message: '+all lets any server send mail as $domain.',
          severity: MailDnsSeverity.error,
        ),
      );
    } else if (all == null && spf.redirect == null) {
      issues.add(
        const MailDnsIssue(
          code: 'spf_no_all',
          message:
              'The SPF record has no all mechanism, so unlisted servers get a '
              'neutral result.',
        ),
      );
    }

    var lookups = 0;
    var voidLookups = 0;
    // Receivers evaluate an include every time it appears, so only records on
    // the current include path are skipped (to break loops), and counting stops
    // once the limit is exceeded.
    Future<void> count(SpfRecord record, Set<String> path) async {
      final hasAll = record.allQualifier != null;
      for (final term in record.terms) {
        if (lookups > _maxSpfLookups) return;
        // RFC 7208 section 6.1: redirect is ignored when all is present.
        if (term.isModifier && term.name == 'redirect' && hasAll) continue;
        final queriesDns = term.isModifier
            ? term.name == 'redirect'
            : const {'include', 'a', 'mx', 'ptr', 'exists'}.contains(term.name);
        if (!queriesDns) continue;
        lookups++;
        if (term.name != 'include' && term.name != 'redirect') continue;

        final target = term.value?.toLowerCase().replaceFirst(
          RegExp(r'\.$'),
          '',
        );
        // Macro targets such as %{i}._spf.example.com depend on the sender.
        if (target == null || target.isEmpty || target.contains('%')) continue;
        if (path.contains(target)) continue;
        final answers = await _lookup(target, 'TXT', issues);
        if (answers == null) continue;
        // An empty answer or NXDOMAIN is a void lookup (RFC 7208 4.6.4).
        if (answers.isEmpty) voidLookups++;
        final nested = answers.map(SpfRecord.parse).nonNulls.firstOrNull;
        if (nested == null) {
          issues.add(
            MailDnsIssue(
              code: 'spf_include_missing',
              message:
                  '${term.name} target $target has no SPF record; receivers '
                  'treat this as a permanent error.',
              severity: MailDnsSeverity.error,
            ),
          );
          continue;
        }
        await count(nested, {...path, target});
      }
    }

    await count(spf, {domain});
    if (lookups > _maxSpfLookups) {
      issues.add(
        MailDnsIssue(
          code: 'spf_too_many_lookups',
          message:
              'SPF evaluation needs at least $lookups DNS lookups; receivers '
              'stop with a permanent error after $_maxSpfLookups.',
          severity: MailDnsSeverity.error,
        ),
      );
    }
    if (voidLookups > _maxVoidLookups) {
      issues.add(
        MailDnsIssue(
          code: 'spf_too_many_void_lookups',
          message:
              'SPF evaluation hits $voidLookups lookups with no answer; '
              'receivers stop with a permanent error after $_maxVoidLookups.',
          severity: MailDnsSeverity.error,
        ),
      );
    }
    return (
      record: spf,
      lookups: lookups,
      voidLookups: voidLookups,
      issues: issues,
    );
  }

  Future<({DmarcRecord? record, List<MailDnsIssue> issues})> _checkDmarc(
    String domain,
  ) async {
    final issues = <MailDnsIssue>[];
    final name = '_dmarc.$domain';
    final answers = await _lookup(name, 'TXT', issues);
    final records = [...?answers?.map(DmarcRecord.parse).nonNulls];
    if (answers == null || records.isEmpty) {
      if (answers != null) {
        issues.add(
          MailDnsIssue(
            code: 'dmarc_missing',
            message:
                '$domain has no DMARC record at $name, so receivers decide '
                'alone what to do with spoofed mail.',
          ),
        );
      }
      return (record: null, issues: issues);
    }

    if (records.length > 1) {
      issues.add(
        MailDnsIssue(
          code: 'dmarc_multiple',
          message:
              '$name has ${records.length} DMARC records; receivers ignore '
              'all of them.',
          severity: MailDnsSeverity.error,
        ),
      );
    }
    final dmarc = records.first;
    final policy = dmarc.policy;
    if (!const {'none', 'quarantine', 'reject'}.contains(policy)) {
      issues.add(
        const MailDnsIssue(
          code: 'dmarc_invalid',
          message: 'The DMARC record needs p=none, p=quarantine, or p=reject.',
          severity: MailDnsSeverity.error,
        ),
      );
    } else if (policy == 'none') {
      issues.add(
        const MailDnsIssue(
          code: 'dmarc_policy_none',
          message: 'p=none only monitors; spoofed mail is still delivered.',
          severity: MailDnsSeverity.info,
        ),
      );
    }
    if (dmarc.percent < 100) {
      issues.add(
        MailDnsIssue(
          code: 'dmarc_pct_partial',
          message:
              'pct=${dmarc.percent} applies the policy to only part of the '
              'mail.',
          severity: MailDnsSeverity.info,
        ),
      );
    }
    if (dmarc.aggregateReportUris.isEmpty) {
      issues.add(
        const MailDnsIssue(
          code: 'dmarc_no_rua',
          message: 'No rua address is set, so no aggregate reports are sent.',
          severity: MailDnsSeverity.info,
        ),
      );
    }
    return (record: dmarc, issues: issues);
  }

  Future<({Map<String, DkimRecord?> records, List<MailDnsIssue> issues})>
  _checkDkim(String domain, List<String> selectors) async {
    final results = await Future.wait([
      for (final selector in selectors) _checkSelector(domain, selector),
    ]);
    return (
      records: {
        for (var i = 0; i < selectors.length; i++)
          selectors[i]: results[i].record,
      },
      issues: [for (final result in results) ...result.issues],
    );
  }

  Future<({DkimRecord? record, List<MailDnsIssue> issues})> _checkSelector(
    String domain,
    String selector,
  ) async {
    final issues = <MailDnsIssue>[];
    final name = '$selector._domainkey.$domain';
    final answers = await _lookup(name, 'TXT', issues);
    final record = answers?.map(DkimRecord.parse).nonNulls.firstOrNull;
    if (answers != null && record == null) {
      issues.add(
        MailDnsIssue(code: 'dkim_missing', message: 'No DKIM key at $name.'),
      );
    } else if (record != null && record.isRevoked) {
      issues.add(
        MailDnsIssue(
          code: 'dkim_revoked',
          message: 'The DKIM key at $name is revoked (empty p=).',
        ),
      );
    }
    return (record: record, issues: issues);
  }

  /// Returns the answers, or `null` after recording a `lookup_failed` issue.
  Future<List<String>?> _lookup(
    String name,
    String type,
    List<MailDnsIssue> issues,
  ) async {
    try {
      return await _doh.query(name, type);
    } on DohException catch (error) {
      issues.add(
        MailDnsIssue(
          code: 'lookup_failed',
          message: '$name $type: ${error.message}',
          severity: MailDnsSeverity.error,
        ),
      );
      return null;
    }
  }
}

/// How serious a [MailDnsIssue] is.
enum MailDnsSeverity {
  /// Worth knowing, no action needed.
  info,

  /// Weakens delivery or spoofing protection.
  warning,

  /// Breaks SPF or DMARC evaluation, or allows spoofing.
  error,
}

/// One finding from a mail DNS check.
class MailDnsIssue {
  /// Creates an issue.
  const MailDnsIssue({
    required this.code,
    required this.message,
    this.severity = MailDnsSeverity.warning,
  });

  /// Stable machine-readable code, such as `spf_missing`.
  final String code;

  /// Human-readable explanation.
  final String message;

  /// Severity.
  final MailDnsSeverity severity;

  @override
  String toString() => '$code: $message';
}

/// The result of [MailDnsChecker.check].
class MailDnsReport {
  /// Creates a report.
  const MailDnsReport({
    required this.domain,
    required this.checkedAt,
    this.mx = const <MxRecord>[],
    this.spf,
    this.spfLookups,
    this.spfVoidLookups,
    this.dmarc,
    this.dkim = const <String, DkimRecord?>{},
    this.issues = const <MailDnsIssue>[],
  });

  /// Checked domain in lowercase.
  final String domain;

  /// When the check finished, in UTC.
  final DateTime checkedAt;

  /// MX records, lowest priority value first.
  final List<MxRecord> mx;

  /// The SPF record, or the first one when there are several.
  final SpfRecord? spf;

  /// DNS lookups SPF evaluation needs, counted through includes and
  /// redirects. Counting stops just past the limit of 10.
  final int? spfLookups;

  /// Include and redirect targets that returned no records, which receivers
  /// limit to two.
  final int? spfVoidLookups;

  /// The DMARC record, or the first one when there are several.
  final DmarcRecord? dmarc;

  /// DKIM key per requested selector; `null` when a selector has no key or its
  /// lookup failed.
  final Map<String, DkimRecord?> dkim;

  /// Findings in order: MX, SPF, DMARC, DKIM.
  final List<MailDnsIssue> issues;

  /// Whether every issue is only informational.
  bool get isHealthy =>
      issues.every((issue) => issue.severity == MailDnsSeverity.info);
}

const _maxSpfLookups = 10;
const _maxVoidLookups = 2;

String _normalize(String value, {required bool isDomain}) {
  final name = value.trim().toLowerCase().replaceFirst(RegExp(r'\.$'), '');
  final pattern = isDomain
      ? RegExp(r'^[a-z0-9_-]+(\.[a-z0-9_-]+)+$')
      : RegExp(r'^[a-z0-9_-]+(\.[a-z0-9_-]+)*$');
  if (!pattern.hasMatch(name)) {
    throw FormatException(
      isDomain ? 'Not an ASCII domain name.' : 'Not a valid DKIM selector.',
      value,
    );
  }
  return name;
}
