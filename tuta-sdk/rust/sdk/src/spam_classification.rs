//! The web client's spam decision for new mails, failing open where it cannot be reproduced.

mod farmhash;
pub mod filter;
mod html_entities;
pub mod model;
pub mod preprocess;

use preprocess::extract_server_classifiers;

/// Must match `SERVER_CLASSIFIERS_TO_TRUST` in SpamClassificationHandler.ts
pub const SERVER_CLASSIFIERS_TO_TRUST: &[i64] = &[6, 28, 2, 27, 23, 26, 22, 14, 5, 4, 8];

const PHISHING_STATUS_SUSPICIOUS: i64 = 1;

/// Must match `InboxRuleType` in Utils.ts
mod inbox_rule_type {
	pub const FROM_EQUALS: &str = "0";
	pub const RECIPIENT_TO_EQUALS: &str = "1";
	pub const RECIPIENT_CC_EQUALS: &str = "2";
	pub const RECIPIENT_BCC_EQUALS: &str = "3";
	pub const SUBJECT_CONTAINS: &str = "4";
	pub const MAIL_HEADER_CONTAINS: &str = "5";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFolder {
	Inbox,
	Spam,
	Other,
}

/// See `SpamClassificationHandler.isMailFromTrustedSender`
#[derive(Debug, Clone, Copy, Default)]
pub struct SenderTrust {
	pub is_contact: bool,
	pub is_self: bool,
	pub is_tuta_team: bool,
}

impl SenderTrust {
	fn is_trusted(&self) -> bool {
		self.is_contact || self.is_self || self.is_tuta_team
	}
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleMatch {
	Match,
	NoMatch,
	/// e.g. a regular expression rule
	Unknown,
}

pub struct InboxRuleCheck {
	pub matches: RuleMatch,
	pub exclude_from_spam_filter: bool,
}

pub struct NewMailFacts<'a> {
	pub source_folder: SourceFolder,
	pub phishing_status: i64,
	pub server_classification_data: Option<&'a str>,
	pub sender_trust: SenderTrust,
	pub inbox_rules: Vec<InboxRuleCheck>,
	pub model_says_spam: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpamDecisionReason {
	NotInInboxOrSpam,
	ExcludedByInboxRule,
	Phishing,
	TrustedSender,
	TrustedServerClassifier,
	ClientModel,
	NoModel,
}

/// Whether the web client would move the new mail to the spam folder
pub fn decide(facts: &NewMailFacts) -> (bool, SpamDecisionReason) {
	if facts.source_folder == SourceFolder::Other {
		return (false, SpamDecisionReason::NotInInboxOrSpam);
	}

	// InboxRuleHandler applies the first matching rule; an unknown excluding rule is assumed to match
	for rule in &facts.inbox_rules {
		match (&rule.matches, rule.exclude_from_spam_filter) {
			(RuleMatch::Match | RuleMatch::Unknown, true) => {
				return (false, SpamDecisionReason::ExcludedByInboxRule)
			},
			(RuleMatch::Match, false) => break,
			_ => continue,
		}
	}

	let is_phishing = facts.phishing_status == PHISHING_STATUS_SUSPICIOUS;
	let has_trusted_server_classifier = facts
		.server_classification_data
		.map(|data| {
			extract_server_classifiers(data)
				.into_iter()
				.flatten()
				.any(|c| SERVER_CLASSIFIERS_TO_TRUST.contains(&c))
		})
		.unwrap_or(false);

	if is_phishing {
		return (true, SpamDecisionReason::Phishing);
	}
	if facts.sender_trust.is_trusted() {
		return (false, SpamDecisionReason::TrustedSender);
	}
	if has_trusted_server_classifier {
		return (
			facts.source_folder == SourceFolder::Spam,
			SpamDecisionReason::TrustedServerClassifier,
		);
	}
	// `(await this.spamClassifier.predict(...)) ?? false`
	let reason = if facts.model_says_spam.is_some() {
		SpamDecisionReason::ClientModel
	} else {
		SpamDecisionReason::NoModel
	};
	(facts.model_says_spam.unwrap_or(false), reason)
}

/// `isRegularExpression` from FormatUtils.ts
fn is_regular_expression(value: &str) -> bool {
	if value.len() < 2 || !value.starts_with('/') {
		return false;
	}
	if value.ends_with('/') {
		return true;
	}
	// /^\/.*\/(?!.*(.)\1)[gimsuy]+$/
	match value.rfind('/') {
		Some(i) if i > 0 => {
			let flags = &value[i + 1..];
			!flags.is_empty()
				&& flags.chars().all(|c| "gimsuy".contains(c))
				&& !flags.as_bytes().windows(2).any(|w| w[0] == w[1])
		},
		_ => false,
	}
}

/// `_checkEmailAddresses` from InboxRuleHandler.ts
fn check_email_addresses<'a>(
	addresses: impl IntoIterator<Item = &'a str>,
	value: &str,
) -> RuleMatch {
	if is_regular_expression(value) {
		return RuleMatch::Unknown;
	}
	let value_is_domain = !value.contains('@');
	let matched = addresses.into_iter().any(|address| {
		let clean = address.trim().to_lowercase();
		if value_is_domain {
			clean.split('@').nth(1) == Some(value)
		} else {
			clean == value
		}
	});
	if matched {
		RuleMatch::Match
	} else {
		RuleMatch::NoMatch
	}
}

/// `_checkContainsRule` from InboxRuleHandler.ts
fn check_contains(text: &str, value: &str) -> RuleMatch {
	if text.contains(value) {
		RuleMatch::Match
	} else if is_regular_expression(value) {
		RuleMatch::Unknown
	} else {
		RuleMatch::NoMatch
	}
}

pub struct InboxRuleSubject<'a> {
	pub from: Vec<&'a str>,
	pub to: Vec<&'a str>,
	pub cc: Vec<&'a str>,
	pub bcc: Vec<&'a str>,
	pub subject: &'a str,
	pub headers: Option<&'a str>,
}

/// `checkInboxRule` from InboxRuleHandler.ts
pub fn check_inbox_rule(rule_type: &str, value: &str, mail: &InboxRuleSubject) -> RuleMatch {
	match rule_type {
		inbox_rule_type::FROM_EQUALS => check_email_addresses(mail.from.iter().copied(), value),
		inbox_rule_type::RECIPIENT_TO_EQUALS => {
			check_email_addresses(mail.to.iter().copied(), value)
		},
		inbox_rule_type::RECIPIENT_CC_EQUALS => {
			check_email_addresses(mail.cc.iter().copied(), value)
		},
		inbox_rule_type::RECIPIENT_BCC_EQUALS => {
			check_email_addresses(mail.bcc.iter().copied(), value)
		},
		inbox_rule_type::SUBJECT_CONTAINS => check_contains(mail.subject, value),
		inbox_rule_type::MAIL_HEADER_CONTAINS => match mail.headers {
			Some(headers) => check_contains(headers, value),
			None => RuleMatch::NoMatch,
		},
		_ => RuleMatch::NoMatch,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn facts() -> NewMailFacts<'static> {
		NewMailFacts {
			source_folder: SourceFolder::Inbox,
			phishing_status: 0,
			server_classification_data: None,
			sender_trust: SenderTrust::default(),
			inbox_rules: vec![],
			model_says_spam: Some(true),
		}
	}

	#[test]
	fn model_spam_in_inbox_is_spam() {
		assert_eq!(decide(&facts()), (true, SpamDecisionReason::ClientModel));
	}

	#[test]
	fn model_ham_is_not_spam() {
		let f = NewMailFacts {
			model_says_spam: Some(false),
			..facts()
		};
		assert_eq!(decide(&f), (false, SpamDecisionReason::ClientModel));
	}

	#[test]
	fn no_model_is_not_spam_even_in_spam_folder() {
		let f = NewMailFacts {
			model_says_spam: None,
			source_folder: SourceFolder::Spam,
			..facts()
		};
		assert_eq!(decide(&f), (false, SpamDecisionReason::NoModel));
	}

	#[test]
	fn trusted_sender_wins_over_model() {
		for trust in [
			SenderTrust {
				is_contact: true,
				..Default::default()
			},
			SenderTrust {
				is_self: true,
				..Default::default()
			},
			SenderTrust {
				is_tuta_team: true,
				..Default::default()
			},
		] {
			let f = NewMailFacts {
				sender_trust: trust,
				..facts()
			};
			assert_eq!(decide(&f), (false, SpamDecisionReason::TrustedSender));
		}
	}

	#[test]
	fn phishing_is_spam_even_from_contact() {
		let f = NewMailFacts {
			phishing_status: 1,
			model_says_spam: Some(false),
			sender_trust: SenderTrust {
				is_contact: true,
				..Default::default()
			},
			..facts()
		};
		assert_eq!(decide(&f), (true, SpamDecisionReason::Phishing));
	}

	#[test]
	fn trusted_server_classifier_keeps_folder() {
		let f = NewMailFacts {
			server_classification_data: Some("0,3:1,6"),
			..facts()
		};
		assert_eq!(
			decide(&f),
			(false, SpamDecisionReason::TrustedServerClassifier)
		);
		let f = NewMailFacts {
			server_classification_data: Some("1,6"),
			source_folder: SourceFolder::Spam,
			model_says_spam: Some(false),
			..facts()
		};
		assert_eq!(
			decide(&f),
			(true, SpamDecisionReason::TrustedServerClassifier)
		);
		let f = NewMailFacts {
			server_classification_data: Some("1,3"),
			..facts()
		};
		assert_eq!(decide(&f), (true, SpamDecisionReason::ClientModel));
	}

	#[test]
	fn other_folders_are_never_spam() {
		let f = NewMailFacts {
			source_folder: SourceFolder::Other,
			phishing_status: 1,
			..facts()
		};
		assert_eq!(decide(&f), (false, SpamDecisionReason::NotInInboxOrSpam));
	}

	#[test]
	fn inbox_rules_first_match_wins_and_unknown_fails_open() {
		let rule = |matches, exclude| InboxRuleCheck {
			matches,
			exclude_from_spam_filter: exclude,
		};
		let f = NewMailFacts {
			inbox_rules: vec![rule(RuleMatch::Match, false), rule(RuleMatch::Match, true)],
			..facts()
		};
		assert_eq!(decide(&f).0, true);
		let f = NewMailFacts {
			inbox_rules: vec![
				rule(RuleMatch::NoMatch, false),
				rule(RuleMatch::Match, true),
			],
			..facts()
		};
		assert_eq!(decide(&f), (false, SpamDecisionReason::ExcludedByInboxRule));
		let f = NewMailFacts {
			inbox_rules: vec![rule(RuleMatch::Unknown, true)],
			..facts()
		};
		assert_eq!(decide(&f), (false, SpamDecisionReason::ExcludedByInboxRule));
		let f = NewMailFacts {
			inbox_rules: vec![
				rule(RuleMatch::Unknown, false),
				rule(RuleMatch::Match, true),
			],
			..facts()
		};
		assert_eq!(decide(&f), (false, SpamDecisionReason::ExcludedByInboxRule));
	}

	#[test]
	fn inbox_rule_matching() {
		let mail = InboxRuleSubject {
			from: vec!["Shop@Example.com"],
			to: vec!["me@tuta.com"],
			cc: vec![],
			bcc: vec![],
			subject: "Your Order",
			headers: Some("X-Foo: bar"),
		};
		assert_eq!(
			check_inbox_rule("0", "shop@example.com", &mail),
			RuleMatch::Match
		);
		assert_eq!(
			check_inbox_rule("0", "example.com", &mail),
			RuleMatch::Match
		);
		assert_eq!(
			check_inbox_rule("0", "other.com", &mail),
			RuleMatch::NoMatch
		);
		assert_eq!(check_inbox_rule("0", "/shop/", &mail), RuleMatch::Unknown);
		assert_eq!(
			check_inbox_rule("1", "me@tuta.com", &mail),
			RuleMatch::Match
		);
		assert_eq!(
			check_inbox_rule("2", "me@tuta.com", &mail),
			RuleMatch::NoMatch
		);
		assert_eq!(check_inbox_rule("4", "Order", &mail), RuleMatch::Match);
		assert_eq!(check_inbox_rule("4", "order", &mail), RuleMatch::NoMatch);
		assert_eq!(check_inbox_rule("4", "/order/i", &mail), RuleMatch::Unknown);
		assert_eq!(check_inbox_rule("5", "X-Foo", &mail), RuleMatch::Match);
	}

	#[test]
	fn regular_expression_detection() {
		assert!(is_regular_expression("/abc/"));
		assert!(is_regular_expression("/abc/gi"));
		assert!(!is_regular_expression("/abc/gg"));
		assert!(!is_regular_expression("abc"));
		assert!(!is_regular_expression("/abc"));
	}
}
