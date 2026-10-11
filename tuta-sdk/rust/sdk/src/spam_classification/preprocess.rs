use super::farmhash::hash_bucket;
use super::html_entities::HTML_ENTITIES;
use regex::{NoExpand, Regex};
use std::collections::HashMap;
use std::sync::LazyLock;

pub const VECTOR_DIMENSION: usize = 2048;
const MAX_WORD_FREQUENCY: u8 = 31;
pub const SERVER_CLASSIFICATION_DIMENSION: usize = 256;

/// The JS `\s` character set (WhiteSpace + LineTerminator)
const JS_WS: &str = r"\t\n\x0B\x0C\r \u{A0}\u{1680}\u{2000}-\u{200A}\u{2028}\u{2029}\u{202F}\u{205F}\u{3000}\u{FEFF}";

const DATE_TOKEN: &str = " TDATE ";
const URL_TOKEN: &str = " TURL${1} ";
const EMAIL_TOKEN: &str = " TEMAIL ";
const BITCOIN_TOKEN: &str = " TBITCOIN ";
const CREDIT_CARD_TOKEN: &str = " TCREDITCARD ";
const NUMBER_TOKEN: &str = " TNUMBER ";
const SPECIAL_CHARACTER_TOKEN: &str = " TSPECIALCHAR ";
const SPACE_BEFORE_NEW_LINE_TOKEN: &str = "\n";

/// The `regex` crate has no lookarounds, so `(?<!x)` / `(?!x)` are checked on the adjacent chars
struct Pattern {
	re: Regex,
	not_preceded_by: Option<fn(char) -> bool>,
	not_followed_by: Option<fn(char) -> bool>,
}

impl Pattern {
	fn plain(pattern: &str) -> Self {
		Self::guarded(pattern, None, None)
	}

	fn guarded(
		pattern: &str,
		not_preceded_by: Option<fn(char) -> bool>,
		not_followed_by: Option<fn(char) -> bool>,
	) -> Self {
		Pattern {
			re: Regex::new(pattern).expect("invalid spam preprocessing regex"),
			not_preceded_by,
			not_followed_by,
		}
	}

	fn accepts(&self, text: &str, start: usize, end: usize) -> bool {
		let before_ok = match (self.not_preceded_by, text[..start].chars().next_back()) {
			(Some(rejects), Some(c)) => !rejects(c),
			_ => true,
		};
		let after_ok = match (self.not_followed_by, text[end..].chars().next()) {
			(Some(rejects), Some(c)) => !rejects(c),
			_ => true,
		};
		before_ok && after_ok
	}

	fn replace_all(&self, text: &str, replacement: &str) -> String {
		let expand = replacement.contains('$');
		if self.not_preceded_by.is_none() && self.not_followed_by.is_none() {
			return if expand {
				self.re.replace_all(text, replacement).into_owned()
			} else {
				self.re
					.replace_all(text, NoExpand(replacement))
					.into_owned()
			};
		}
		// JS retries a rejected match at the next start position; no other match at the same start
		// could pass the check for these patterns, so this is equivalent
		let mut out = String::with_capacity(text.len());
		let mut last = 0;
		let mut pos = 0;
		while let Some(captures) = self.re.captures_at(text, pos) {
			let whole = captures.get(0).expect("group 0 always exists");
			if !self.accepts(text, whole.start(), whole.end()) {
				pos = whole.start()
					+ text[whole.start()..]
						.chars()
						.next()
						.map_or(1, char::len_utf8);
				continue;
			}
			out.push_str(&text[last..whole.start()]);
			if expand {
				captures.expand(replacement, &mut out);
			} else {
				out.push_str(replacement);
			}
			last = whole.end();
			pos = whole.end().max(whole.start() + 1);
		}
		out.push_str(&text[last..]);
		out
	}
}

fn is_ascii_word_char_dot_or_dash(c: char) -> bool {
	c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

struct Patterns {
	dates: Vec<Pattern>,
	url: Pattern,
	email: Pattern,
	bitcoin: Pattern,
	credit_card: Pattern,
	number: Pattern,
	special_character: Pattern,
	space_before_new_line: Pattern,
	html_tag: Regex,
	html_entity: Regex,
}

static PATTERNS: LazyLock<Patterns> = LazyLock::new(|| {
	// JS regexes without the u flag: ASCII \b, \d and \w
	let b = r"(?-u:\b)";
	Patterns {
		dates: vec![
			// \b(?<!-)(?:\d{1,2}-){2}(?:\d\d|\d{4})(?!-)\b
			Pattern::guarded(
				&format!(r"{b}(?:[0-9]{{1,2}}-){{2}}(?:[0-9][0-9]|[0-9]{{4}}){b}"),
				Some(|c| c == '-'),
				Some(|c| c == '-'),
			),
			// \b(?<!\.)(?:\d{1,2}\.){2}(?:\d\d|\d{4})(?!\.)\b
			Pattern::guarded(
				&format!(r"{b}(?:[0-9]{{1,2}}\.){{2}}(?:[0-9][0-9]|[0-9]{{4}}){b}"),
				Some(|c| c == '.'),
				Some(|c| c == '.'),
			),
			Pattern::plain(&format!(
				r"{b}(?:[0-9]{{1,2}}/){{2}}(?:[0-9][0-9]|[0-9]{{4}}){b}"
			)),
			Pattern::plain(&format!(r"{b}[0-9]{{4}}(?:/[0-9]{{1,2}}){{2}}{b}")),
			// \b(?<!-)\d{4}(?:-\d{1,2}){2}(?!-)\b
			Pattern::guarded(
				&format!(r"{b}[0-9]{{4}}(?:-[0-9]{{1,2}}){{2}}{b}"),
				Some(|c| c == '-'),
				Some(|c| c == '-'),
			),
		],
		url: Pattern::plain(&format!(
			r"(?:https?|ftp)://([0-9A-Za-z_.\-]+)(?:/[^{JS_WS}]*)?"
		)),
		// (?:mailto:)?[A-Za-z0-9_+\-.]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w.-])
		email: Pattern::guarded(
			r"(?:mailto:)?[A-Za-z0-9_+\-.]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}",
			None,
			Some(is_ascii_word_char_dot_or_dash),
		),
		bitcoin: Pattern::plain(&format!(r"{b}[13][a-km-zA-HJ-NP-Z1-9]{{25,34}}{b}")),
		credit_card: Pattern::plain(&format!(r"{b}(?:[0-9]{{4}}[{JS_WS}\-]?){{3}}[0-9]{{4}}{b}")),
		number: Pattern::plain(&format!(r"{b}[0-9]+{b}")),
		special_character: Pattern::plain(r#"([!@#$%^&*()\[\]<>+`_=\\{}"':;?/,\-.~]+)"#),
		space_before_new_line: Pattern::plain(&format!(r"[{JS_WS}]+\n")),
		html_tag: Regex::new(r"<[^>]*>?").unwrap(),
		html_entity: Regex::new(r"&[#0-9a-zA-Z]+;").unwrap(),
	}
});

static ENTITY_MAP: LazyLock<HashMap<&'static str, &'static str>> =
	LazyLock::new(|| HTML_ENTITIES.iter().copied().collect());

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SpamMailDatum {
	pub subject: String,
	pub body: String,
	pub sender: String,
	pub to_recipients: String,
	pub cc_recipients: String,
	pub bcc_recipients: String,
	pub auth_status: String,
	pub server_classification_data: Option<String>,
}

fn is_js_whitespace(c: char) -> bool {
	matches!(
		c,
		'\t' | '\n' | '\x0B' | '\x0C' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
			..='\u{200A}'
				| '\u{2028}' | '\u{2029}'
				| '\u{202F}' | '\u{205F}'
				| '\u{3000}' | '\u{FEFF}'
	)
}

pub fn html_to_text(html: &str) -> String {
	let text = PATTERNS.html_tag.replace_all(html, NoExpand(" "));
	let mut out = String::with_capacity(text.len());
	let mut last = 0;
	// JS builds a UTF-16 string, so adjacent numeric entities can form a surrogate pair; unpaired
	// surrogates become U+FFFD like in TextEncoder
	let mut pending_high_surrogate: Option<(u16, usize)> = None;
	for m in PATTERNS.html_entity.find_iter(&text) {
		let replacement = entity_replacement(m.as_str());
		if let Some((high, end)) = pending_high_surrogate.take() {
			let pairs_with_this = end == m.start()
				&& matches!(replacement, Some(EntityReplacement::CodeUnit(low)) if (0xDC00..=0xDFFF).contains(&low));
			if pairs_with_this {
				let Some(EntityReplacement::CodeUnit(low)) = replacement else {
					unreachable!()
				};
				let c = char::decode_utf16([high, low]).next().unwrap().unwrap();
				out.push(c);
				last = m.end();
				continue;
			}
			out.push('\u{FFFD}');
		}
		out.push_str(&text[last..m.start()]);
		match replacement {
			Some(EntityReplacement::Named(s)) => out.push_str(s),
			Some(EntityReplacement::CodeUnit(unit)) => {
				if (0xD800..=0xDBFF).contains(&unit) {
					pending_high_surrogate = Some((unit, m.end()));
				} else {
					out.push(char::from_u32(u32::from(unit)).unwrap_or('\u{FFFD}'));
				}
			},
			None => out.push_str(m.as_str()),
		}
		last = m.end();
	}
	if pending_high_surrogate.is_some() {
		out.push('\u{FFFD}');
	}
	out.push_str(&text[last..]);
	out
}

enum EntityReplacement {
	Named(&'static str),
	CodeUnit(u16),
}

fn entity_replacement(entity: &str) -> Option<EntityReplacement> {
	if let Some(number) = entity.strip_prefix("&#") {
		let number = &number[..number.len() - 1];
		js_string_to_number(number).map(|n| EntityReplacement::CodeUnit(js_to_uint16(n)))
	} else {
		ENTITY_MAP.get(entity).map(|s| EntityReplacement::Named(s))
	}
}

fn js_string_to_number(s: &str) -> Option<f64> {
	if s.is_empty() {
		return Some(0.0);
	}
	if s == "Infinity" {
		return Some(f64::INFINITY);
	}
	let radix_digits = |digits: &str, radix: u32| -> Option<f64> {
		if digits.is_empty() {
			return None;
		}
		let mut value: u128 = 0;
		let mut overflowed = false;
		for c in digits.chars() {
			let digit = c.to_digit(radix)?;
			match value
				.checked_mul(u128::from(radix))
				.and_then(|v| v.checked_add(u128::from(digit)))
			{
				Some(v) => value = v,
				None => overflowed = true,
			}
		}
		// beyond 2^128 the value as f64 is a multiple of 2^16, so its low 16 bits are 0
		Some(if overflowed {
			f64::INFINITY
		} else {
			value as f64
		})
	};
	let lower = s.get(..2).map(str::to_ascii_lowercase);
	match lower.as_deref() {
		Some("0x") => {
			return radix_digits(&s[2..], 16).map(|v| if v.is_infinite() { 0.0 } else { v })
		},
		Some("0o") => {
			return radix_digits(&s[2..], 8).map(|v| if v.is_infinite() { 0.0 } else { v })
		},
		Some("0b") => {
			return radix_digits(&s[2..], 2).map(|v| if v.is_infinite() { 0.0 } else { v })
		},
		_ => {},
	}
	// StrUnsignedDecimalLiteral restricted to the characters that can occur here: digits [eE digits]
	let (mantissa, exponent) = match s.find(['e', 'E']) {
		Some(i) => (&s[..i], Some(&s[i + 1..])),
		None => (s, None),
	};
	if mantissa.is_empty() || !mantissa.bytes().all(|b| b.is_ascii_digit()) {
		return None;
	}
	if let Some(exponent) = exponent {
		if exponent.is_empty() || !exponent.bytes().all(|b| b.is_ascii_digit()) {
			return None;
		}
	}
	s.parse::<f64>().ok()
}

fn js_to_uint16(n: f64) -> u16 {
	if !n.is_finite() {
		return 0;
	}
	let int = n.trunc();
	let modulo = int.rem_euclid(65536.0);
	modulo as u16
}

pub fn preprocess_mail(mail: &SpamMailDatum) -> String {
	let mail_text = concat_subject_and_body(mail);

	let mut preprocessed = preprocess_text(&mail_text);

	preprocessed.push_str(&format!(
		"\n{}\n{}\n{}\n{}\n{}",
		mail.sender, mail.to_recipients, mail.cc_recipients, mail.bcc_recipients, mail.auth_status
	));
	preprocessed
}

fn preprocess_text(text: &str) -> String {
	let patterns = &*PATTERNS;
	let mut text = html_to_text(text);
	for date in &patterns.dates {
		text = date.replace_all(&text, DATE_TOKEN);
	}
	text = patterns.url.replace_all(&text, URL_TOKEN);
	text = patterns.email.replace_all(&text, EMAIL_TOKEN);
	text = patterns.bitcoin.replace_all(&text, BITCOIN_TOKEN);
	text = patterns.credit_card.replace_all(&text, CREDIT_CARD_TOKEN);
	text = patterns.number.replace_all(&text, NUMBER_TOKEN);
	text = patterns
		.special_character
		.replace_all(&text, SPECIAL_CHARACTER_TOKEN);
	text = patterns
		.space_before_new_line
		.replace_all(&text, SPACE_BEFORE_NEW_LINE_TOKEN);
	text
}

fn concat_subject_and_body(mail: &SpamMailDatum) -> String {
	let concatenated = format!("{}\n{}", mail.subject, mail.body);
	let trimmed = concatenated.trim_matches(is_js_whitespace);
	if trimmed.is_empty() {
		" ".to_owned()
	} else {
		trimmed.to_owned()
	}
}

fn is_end_of_word_char(c: char) -> bool {
	matches!(
		c,
		' ' | '\n'
			| '\r' | '\t'
			| '\x0B' | '\x0C'
			| '.' | ','
			| ':' | ';'
			| '!' | '?'
			| '&' | '"'
			| '<' | '>'
			| '-' | '+'
			| '=' | '('
			| ')' | '['
			| ']' | '{'
			| '}' | '/'
			| '\\' | '^'
			| '_' | '`'
			| '~' | '|'
			| '@'
	)
}

pub fn tokenize(text: &str) -> Vec<String> {
	text.split(is_end_of_word_char)
		.filter_map(|word| {
			let word = word.trim_matches('\'');
			if word.is_empty() {
				None
			} else {
				Some(word.to_lowercase())
			}
		})
		.collect()
}

pub fn vectorize(tokens: &[String]) -> Vec<u8> {
	let mut vector = vec![0u8; VECTOR_DIMENSION];
	for token in tokens {
		let index = hash_bucket(token, VECTOR_DIMENSION as u64);
		if vector[index] < MAX_WORD_FREQUENCY {
			vector[index] += 1;
		}
	}
	vector
}

fn js_parse_int(s: &str) -> Option<i64> {
	let s = s.trim_start_matches(is_js_whitespace);
	let (negative, digits) = match s.as_bytes().first() {
		Some(b'-') => (true, &s[1..]),
		Some(b'+') => (false, &s[1..]),
		_ => (false, s),
	};
	let end = digits
		.bytes()
		.position(|b| !b.is_ascii_digit())
		.unwrap_or(digits.len());
	if end == 0 {
		return None;
	}
	let value: i64 = digits[..end].parse().ok()?;
	Some(if negative { -value } else { value })
}

pub fn one_hot_encode_server_classifiers(server_classification_data: &str) -> Option<Vec<f32>> {
	let mut result = vec![0f32; SERVER_CLASSIFICATION_DIMENSION];
	for tuple in server_classification_data.split(':') {
		let mut parts = tuple.split(',');
		let is_spam = parts.next().and_then(js_parse_int);
		let classifier = parts.next().and_then(js_parse_int);
		let Some(classifier) = classifier else {
			// result[NaN] = ... only sets a non-index property in JS
			continue;
		};
		if classifier < 0 {
			continue;
		}
		let index = usize::try_from(classifier).ok()?.checked_mul(2)?;
		if index + 1 >= SERVER_CLASSIFICATION_DIMENSION {
			return None;
		}
		// NaN ends up as 0 when the input tensor is created as int32
		result[index] = is_spam.unwrap_or(0) as f32;
		result[index + 1] = 1.0;
	}
	Some(result)
}

pub fn extract_server_classifiers(server_classification_data: &str) -> Vec<Option<i64>> {
	server_classification_data
		.split(':')
		.map(|tuple| tuple.split(',').nth(1).and_then(js_parse_int))
		.collect()
}

pub fn create_model_input(mail: &SpamMailDatum) -> Option<Vec<f32>> {
	let preprocessed = preprocess_mail(mail);
	let tokens = tokenize(&preprocessed);
	let vector = vectorize(&tokens);
	let server_part = match &mail.server_classification_data {
		// a "" string is falsy in JS, so it gets the zero vector as well
		Some(data) if !data.is_empty() => one_hot_encode_server_classifiers(data)?,
		_ => vec![0f32; SERVER_CLASSIFICATION_DIMENSION],
	};
	let mut input: Vec<f32> = vector.into_iter().map(f32::from).collect();
	input.extend(server_part);
	Some(input)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn assert_matches_web_client(json: &str) {
		let cases: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
		assert!(!cases.is_empty());
		for case in &cases {
			let s = |key: &str| case[key].as_str().unwrap().to_owned();
			let mail = SpamMailDatum {
				subject: s("subject"),
				body: s("body"),
				sender: s("sender"),
				to_recipients: s("to"),
				cc_recipients: s("cc"),
				bcc_recipients: s("bcc"),
				auth_status: s("authStatus"),
				server_classification_data: None,
			};
			let preprocessed = preprocess_mail(&mail);
			if let Some(expected) = case["preprocessed"].as_str() {
				assert_eq!(preprocessed, expected, "preprocessed text of {}", s("name"));
			}
			let tokens = tokenize(&preprocessed);
			if let Some(expected) = case["tokens"].as_array() {
				let expected: Vec<&str> = expected.iter().map(|t| t.as_str().unwrap()).collect();
				assert_eq!(tokens, expected, "tokens of {}", s("name"));
			}
			let sparse: Vec<(usize, u8)> = vectorize(&tokens)
				.into_iter()
				.enumerate()
				.filter(|(_, count)| *count != 0)
				.collect();
			let expected: Vec<(usize, u8)> = case["vector"]
				.as_array()
				.unwrap()
				.iter()
				.map(|p| {
					(
						p[0].as_u64().unwrap() as usize,
						p[1].as_u64().unwrap() as u8,
					)
				})
				.collect();
			assert_eq!(sparse, expected, "vector of {}", s("name"));
		}
	}

	#[test]
	fn matches_web_client() {
		assert_matches_web_client(include_str!(
			"../../test_data/spam_classification_web_client_parity.json"
		));
	}
}
