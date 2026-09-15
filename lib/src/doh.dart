import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

/// Minimal DNS-over-HTTPS JSON client for TXT and MX lookups.
class DohResolver {
  /// Creates a resolver that sends queries to [endpoint].
  const DohResolver(this._client, this._endpoint, this._timeout);

  final http.Client _client;
  final Uri _endpoint;
  final Duration _timeout;

  /// Returns the data of every [type] answer for [name], or an empty list when
  /// the name does not exist. TXT strings are unquoted and joined.
  Future<List<String>> query(String name, String type) async {
    final uri = _endpoint.replace(
      queryParameters: <String, String>{'name': name, 'type': type},
    );
    Future<http.Response> get() => _client
        .get(uri, headers: const {'accept': 'application/dns-json'})
        .timeout(_timeout);

    final http.Response response;
    try {
      // A server can close a reused keep-alive connection before answering.
      // GET is idempotent: retry once on a fresh connection.
      response = await get().onError<http.ClientException>((_, _) => get());
    } on TimeoutException {
      throw const DohException('DNS query timed out.');
    } on http.ClientException catch (error) {
      throw DohException('DNS query failed: ${error.message}');
    }
    if (response.statusCode != 200) {
      throw DohException('DNS query failed with HTTP ${response.statusCode}.');
    }

    final Object? json;
    try {
      json = jsonDecode(utf8.decode(response.bodyBytes));
    } on FormatException {
      throw const DohException('Invalid DNS response.');
    }
    if (json is! Map) throw const DohException('Invalid DNS response.');
    final status = json['Status'];
    if (status == 3) return const <String>[];
    if (status != 0) throw DohException('DNS returned status $status.');

    final code = _typeCodes[type];
    final answers = json['Answer'];
    if (answers is! List) return const <String>[];
    // Answers can include the CNAME chain, so keep only the requested type.
    return <String>[
      for (final answer in answers)
        if (answer case {
          'type': final int answerType,
          'data': final String data,
        } when answerType == code)
          type == 'TXT' ? _txtData(data) : data,
    ];
  }
}

/// DNS-over-HTTPS failure.
class DohException implements Exception {
  /// Creates a failure.
  const DohException(this.message);

  /// Safe error description.
  final String message;

  @override
  String toString() => message;
}

const _typeCodes = <String, int>{'TXT': 16, 'MX': 15};

/// Joins the quoted character-strings of a TXT answer such as `"a" "b"` and
/// decodes `\"`, `\\`, and `\DDD` escapes.
String _txtData(String data) {
  final strings = RegExp(r'"((?:[^"\\]|\\.)*)"').allMatches(data);
  if (strings.isEmpty) return data;
  return strings.map((match) => match[1]!).join().replaceAllMapped(
    RegExp(r'\\(\d{3}|.)'),
    (match) {
      final escaped = match[1]!;
      return escaped.length == 3
          ? String.fromCharCode(int.parse(escaped))
          : escaped;
    },
  );
}
