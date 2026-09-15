/// One MX record.
class MxRecord {
  /// Creates an MX record.
  const MxRecord({required this.priority, required this.exchange});

  /// Parses presentation data such as `10 smtp.google.com.`, or returns
  /// `null` when [data] is not an MX record.
  static MxRecord? tryParse(String data) {
    final parts = data.trim().split(RegExp(r'\s+'));
    if (parts.length != 2) return null;
    final priority = int.tryParse(parts[0]);
    if (priority == null) return null;
    return MxRecord(
      priority: priority,
      exchange: parts[1].toLowerCase().replaceFirst(RegExp(r'\.$'), ''),
    );
  }

  /// Preference; lower values are tried first.
  final int priority;

  /// Mail server host name, or empty for a null MX.
  final String exchange;

  /// Whether this is a null MX (RFC 7505): the domain accepts no mail.
  bool get isNull => exchange.isEmpty;
}

/// One SPF mechanism or modifier, such as `~all` or `redirect=example.com`.
class SpfTerm {
  /// Creates a term.
  const SpfTerm({
    required this.name,
    this.qualifier = '+',
    this.value,
    this.isModifier = false,
  });

  /// Parses one whitespace-separated SPF term.
  factory SpfTerm.parse(String token) {
    final modifier = RegExp(r'^([a-zA-Z][\w.-]*)=(.*)$').firstMatch(token);
    if (modifier != null) {
      return SpfTerm(
        name: modifier[1]!.toLowerCase(),
        value: modifier[2],
        isModifier: true,
      );
    }
    var qualifier = '+';
    var rest = token;
    if ('+-~?'.contains(token[0])) {
      qualifier = token[0];
      rest = token.substring(1);
    }
    final split = rest.indexOf(RegExp('[:/]'));
    if (split < 0) {
      return SpfTerm(name: rest.toLowerCase(), qualifier: qualifier);
    }
    return SpfTerm(
      name: rest.substring(0, split).toLowerCase(),
      qualifier: qualifier,
      value: rest[split] == ':'
          ? rest.substring(split + 1)
          : rest.substring(split),
    );
  }

  /// Lowercase mechanism or modifier name, such as `include` or `redirect`.
  final String name;

  /// `+` pass, `-` fail, `~` softfail, or `?` neutral. Always `+` for
  /// modifiers.
  final String qualifier;

  /// Text after `:` or `=`, or a CIDR suffix such as `/24`.
  final String? value;

  /// Whether this is a `name=value` modifier rather than a mechanism.
  final bool isModifier;

  /// Whether the term is valid SPF. Unknown modifiers are allowed and ignored
  /// by receivers; unknown mechanisms are a permanent error.
  bool get isKnown => isModifier || _mechanisms.contains(name);
}

const _mechanisms = {
  'all',
  'include',
  'a',
  'mx',
  'ptr',
  'ip4',
  'ip6',
  'exists',
};

/// A parsed SPF record.
class SpfRecord {
  /// Creates an SPF record.
  const SpfRecord({required this.text, required this.terms});

  /// Parses [text], or returns `null` when it is not an SPF record.
  static SpfRecord? parse(String text) {
    final tokens = text.trim().split(RegExp(r'\s+'));
    if (tokens.first.toLowerCase() != 'v=spf1') return null;
    return SpfRecord(
      text: text.trim(),
      terms: [for (final token in tokens.skip(1)) SpfTerm.parse(token)],
    );
  }

  /// The record text.
  final String text;

  /// Terms after `v=spf1`, in order.
  final List<SpfTerm> terms;

  /// Qualifier of the `all` mechanism, or `null` when there is none.
  String? get allQualifier => terms
      .where((term) => !term.isModifier && term.name == 'all')
      .firstOrNull
      ?.qualifier;

  /// Target of the `redirect` modifier, when present.
  String? get redirect => terms
      .where((term) => term.isModifier && term.name == 'redirect')
      .firstOrNull
      ?.value;

  /// Targets of `include` mechanisms.
  List<String> get includes => [
    for (final term in terms)
      if (!term.isModifier && term.name == 'include' && term.value != null)
        term.value!,
  ];
}

/// A parsed DMARC record.
class DmarcRecord {
  /// Creates a DMARC record.
  const DmarcRecord({required this.text, required this.tags});

  /// Parses [text], or returns `null` unless its first tag is `v=DMARC1`.
  static DmarcRecord? parse(String text) {
    final first = text.split(';').first.trim();
    if (!RegExp(r'^v\s*=\s*DMARC1$', caseSensitive: false).hasMatch(first)) {
      return null;
    }
    return DmarcRecord(text: text.trim(), tags: _tags(text));
  }

  /// The record text.
  final String text;

  /// Tags by lowercase name.
  final Map<String, String> tags;

  /// `none`, `quarantine`, or `reject`, when set.
  String? get policy => tags['p']?.toLowerCase();

  /// Policy for subdomains, when set.
  String? get subdomainPolicy => tags['sp']?.toLowerCase();

  /// Percentage of mail the policy applies to; 100 when not set.
  int get percent => int.tryParse(tags['pct'] ?? '') ?? 100;

  /// Aggregate report destinations from `rua`.
  List<String> get aggregateReportUris => [
    for (final uri in (tags['rua'] ?? '').split(','))
      if (uri.trim().isNotEmpty) uri.trim(),
  ];
}

/// A parsed DKIM public key record.
class DkimRecord {
  /// Creates a DKIM record.
  const DkimRecord({required this.text, required this.tags});

  /// Parses [text], or returns `null` when it has no `p=` tag or a version
  /// other than `DKIM1`.
  static DkimRecord? parse(String text) {
    final tags = _tags(text);
    final version = tags['v'];
    if (!tags.containsKey('p') || (version != null && version != 'DKIM1')) {
      return null;
    }
    return DkimRecord(text: text.trim(), tags: tags);
  }

  /// The record text.
  final String text;

  /// Tags by lowercase name.
  final Map<String, String> tags;

  /// Key type; `rsa` when not set.
  String get keyType => tags['k'] ?? 'rsa';

  /// Base64 public key with whitespace removed; empty when revoked.
  String get publicKey => (tags['p'] ?? '').replaceAll(RegExp(r'\s'), '');

  /// Whether the key is revoked with an empty `p=`.
  bool get isRevoked => publicKey.isEmpty;
}

Map<String, String> _tags(String text) {
  final tags = <String, String>{};
  for (final part in text.split(';')) {
    final equals = part.indexOf('=');
    if (equals <= 0) continue;
    tags.putIfAbsent(
      part.substring(0, equals).trim().toLowerCase(),
      () => part.substring(equals + 1).trim(),
    );
  }
  return tags;
}
