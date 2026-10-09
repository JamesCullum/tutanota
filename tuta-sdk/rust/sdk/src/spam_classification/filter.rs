use super::model::SpamModel;
use super::preprocess::{create_model_input, SpamMailDatum};
use super::{
	check_inbox_rule, decide, InboxRuleCheck, InboxRuleSubject, NewMailFacts, SenderTrust,
	SourceFolder, SpamDecisionReason,
};
#[cfg_attr(test, mockall_double::double)]
use crate::contacts::contact_facade::ContactFacade;
use crate::crypto::crypto_facade::ResolvedSessionKey;
#[cfg_attr(test, mockall_double::double)]
use crate::crypto_entity_client::CryptoEntityClient;
use crate::entities::entity_facade::EntityFacade;
use crate::entities::generated::storage::{BlobAccessTokenPostIn, BlobReadData};
use crate::entities::generated::sys::RootInstance;
use crate::entities::generated::tutanota::{
	Mail, MailAddress, MailBox, MailDetails, MailDetailsBlob, MailSet, MailboxGroupRoot,
	TutanotaProperties,
};
use crate::entities::Entity;
#[cfg_attr(test, mockall_double::double)]
use crate::entity_client::EntityClient;
use crate::folder_system::MailSetKind;
use crate::id::id_tuple::IdTupleGenerated;
use crate::instance_mapper::InstanceMapper;
use crate::mail_facade::MailFacade;
use crate::services::generated::storage::BlobAccessTokenService;
#[cfg_attr(test, mockall_double::double)]
use crate::services::service_executor::ResolvingServiceExecutor;
use crate::services::ExtraServiceParams;
use crate::tutanota_constants::SYSTEM_GROUP_MAIL_ADDRESS;
use crate::type_model_provider::TypeModelProvider;
#[cfg_attr(test, mockall_double::double)]
use crate::user_facade::UserFacade;
use crate::{ApiCallError, GeneratedId, IdTupleCustom, ListLoadDirection};
use std::sync::Arc;

const AUTH_STATUS_AUTHENTICATED: i64 = 0;
const MAIL_STATE_RECEIVED: i64 = 2;

#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct NewMailSpamVerdict {
	pub is_spam: bool,
	pub reason: String,
	pub probability: Option<f32>,
}

#[derive(uniffi::Object)]
pub struct SpamNotificationFilter {
	entity_client: Arc<EntityClient>,
	entity_facade: Arc<dyn EntityFacade>,
	crypto_entity_client: Arc<CryptoEntityClient>,
	instance_mapper: Arc<InstanceMapper>,
	service_executor: Arc<ResolvingServiceExecutor>,
	type_model_provider: Arc<TypeModelProvider>,
	user_facade: Arc<UserFacade>,
	contact_facade: Arc<ContactFacade>,
	mail_facade: MailFacade,
}

impl SpamNotificationFilter {
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn new(
		entity_client: Arc<EntityClient>,
		entity_facade: Arc<dyn EntityFacade>,
		crypto_entity_client: Arc<CryptoEntityClient>,
		instance_mapper: Arc<InstanceMapper>,
		service_executor: Arc<ResolvingServiceExecutor>,
		type_model_provider: Arc<TypeModelProvider>,
		user_facade: Arc<UserFacade>,
		contact_facade: Arc<ContactFacade>,
	) -> Self {
		let mail_facade = MailFacade::new(
			crypto_entity_client.clone(),
			user_facade.clone(),
			service_executor.clone(),
		);
		Self {
			entity_client,
			entity_facade,
			crypto_entity_client,
			instance_mapper,
			service_executor,
			type_model_provider,
			user_facade,
			contact_facade,
			mail_facade,
		}
	}

	async fn load_mail(
		&self,
		mail_id: &IdTupleGenerated,
	) -> Result<(Mail, ResolvedSessionKey), ApiCallError> {
		let type_ref = Mail::type_ref();
		let encrypted = self.entity_client.load(&type_ref, mail_id).await?;
		let type_model = self.entity_client.resolve_server_type_ref(&type_ref)?;
		let session_key = self
			.crypto_entity_client
			.get_crypto_facade()
			.resolve_session_key(&encrypted, &type_model)
			.await
			.map_err(|e| ApiCallError::internal(format!("cannot resolve mail session key: {e}")))?
			.ok_or_else(|| ApiCallError::internal("mail has no session key".to_owned()))?;
		let decrypted =
			self.entity_facade
				.decrypt_and_map(&type_model, encrypted, session_key.clone())?;
		let mail = self
			.instance_mapper
			.parse_entity::<Mail>(decrypted)
			.map_err(|e| ApiCallError::internal_with_err(e, "cannot map mail"))?;
		Ok((mail, session_key))
	}

	/// `MailFacade.loadMailDetailsBlob`
	async fn load_mail_details(
		&self,
		mail: &Mail,
		mail_session_key: &ResolvedSessionKey,
	) -> Result<MailDetails, ApiCallError> {
		let details_id = mail
			.mailDetails
			.as_ref()
			.ok_or_else(|| ApiCallError::internal("mail has no mailDetails".to_owned()))?;
		let access_info = self
			.service_executor
			.post::<BlobAccessTokenService>(
				BlobAccessTokenPostIn {
					_format: 0,
					archiveDataType: None,
					write: None,
					read: Some(BlobReadData {
						_id: None,
						archiveId: details_id.list_id.clone(),
						instanceListId: None,
						instanceIds: vec![],
					}),
				},
				ExtraServiceParams::default(),
			)
			.await?
			.blobAccessInfo;
		let type_ref = MailDetailsBlob::type_ref();
		let mut blobs = self
			.entity_client
			.load_blob_elements(
				&type_ref,
				&details_id.list_id,
				std::slice::from_ref(&details_id.element_id),
				&access_info,
			)
			.await?;
		if blobs.is_empty() {
			return Err(ApiCallError::internal(
				"mail details blob not found".to_owned(),
			));
		}
		let type_model = self.entity_client.resolve_server_type_ref(&type_ref)?;
		let decrypted = self.entity_facade.decrypt_and_map(
			&type_model,
			blobs.swap_remove(0),
			mail_session_key.clone(),
		)?;
		let blob = self
			.instance_mapper
			.parse_entity::<MailDetailsBlob>(decrypted)
			.map_err(|e| ApiCallError::internal_with_err(e, "cannot map mail details"))?;
		Ok(blob.details)
	}

	async fn load_folders(&self, mail_group: &GeneratedId) -> Result<Vec<MailSet>, ApiCallError> {
		let group_root: MailboxGroupRoot = self.crypto_entity_client.load(mail_group).await?;
		let mailbox: MailBox = self.crypto_entity_client.load(&group_root.mailbox).await?;
		self.crypto_entity_client
			.load_range(
				&mailbox.mailSets.mailSets,
				&GeneratedId::min_id(),
				1000,
				ListLoadDirection::ASC,
			)
			.await
	}

	async fn load_tutanota_properties(&self) -> Result<TutanotaProperties, ApiCallError> {
		let type_model = self
			.type_model_provider
			.resolve_client_type_ref(&TutanotaProperties::type_ref())
			.ok_or_else(|| ApiCallError::internal("no type model for TutanotaProperties".into()))?;
		let root_id = IdTupleCustom {
			list_id: self.user_facade.get_user_group_id(),
			element_id: type_model.root_id.clone(),
		};
		let root: RootInstance = self.crypto_entity_client.load(&root_id).await?;
		self.crypto_entity_client.load(&root.reference).await
	}

	async fn is_from_contact(&self, sender: &str) -> Result<bool, ApiCallError> {
		let sender = clean_mail_address(sender);
		let contacts = self.contact_facade.load_all_user_contacts().await?;
		Ok(contacts.iter().any(|contact| {
			contact
				.mailAddresses
				.iter()
				.any(|a| clean_mail_address(&a.address) == sender)
		}))
	}

	async fn is_from_self(&self, sender: &str) -> bool {
		self.mail_facade
			.get_group_id_for_mail_address(sender)
			.await
			.is_ok()
	}

	async fn check(
		&self,
		mail_id: &IdTupleGenerated,
		spam_model: Option<Vec<u8>>,
	) -> Result<NewMailSpamVerdict, ApiCallError> {
		let (mail, session_key) = self.load_mail(mail_id).await?;
		let mail_group = mail
			._ownerGroup
			.clone()
			.ok_or_else(|| ApiCallError::internal("mail has no owner group".into()))?;
		let folders = self.load_folders(&mail_group).await?;
		let folder_kind = |kind: MailSetKind| {
			folders
				.iter()
				.find(|f| f.folderType == kind as i64)
				.and_then(|f| f._id.clone())
		};
		let inbox = folder_kind(MailSetKind::Inbox);
		let spam = folder_kind(MailSetKind::Spam);
		let is_in = |folder: &Option<IdTupleGenerated>| {
			folder
				.as_ref()
				.is_some_and(|folder| mail.sets.iter().any(|set| set == folder))
		};
		let source_folder = if is_in(&spam) {
			SourceFolder::Spam
		} else if is_in(&inbox) {
			SourceFolder::Inbox
		} else {
			SourceFolder::Other
		};

		if !mail.processNeeded {
			return Ok(NewMailSpamVerdict {
				is_spam: source_folder == SourceFolder::Spam,
				reason: "already processed".to_owned(),
				probability: None,
			});
		}
		if source_folder == SourceFolder::Other {
			return Ok(verdict(false, SpamDecisionReason::NotInInboxOrSpam, None));
		}

		let details = self.load_mail_details(&mail, &session_key).await?;
		let details_authenticated = details.authStatus == AUTH_STATUS_AUTHENTICATED;

		let sender_trust = SenderTrust {
			is_contact: details_authenticated && self.is_from_contact(&mail.sender.address).await?,
			is_self: details_authenticated && self.is_from_self(&mail.sender.address).await,
			is_tuta_team: is_tuta_team_mail(&mail),
		};

		let properties = self.load_tutanota_properties().await?;
		let mut from = vec![mail.sender.address.as_str()];
		if let Some(envelope_sender) = &mail.differentEnvelopeSender {
			from.push(envelope_sender.as_str());
		}
		let rule_subject = InboxRuleSubject {
			from,
			to: addresses(&details.recipients.toRecipients),
			cc: addresses(&details.recipients.ccRecipients),
			bcc: addresses(&details.recipients.bccRecipients),
			subject: &mail.subject,
			headers: details
				.headers
				.as_ref()
				.and_then(|h| h.compressedHeaders.as_deref().or(h.headers.as_deref())),
		};
		let inbox_rules = properties
			.inboxRules
			.iter()
			.map(|rule| InboxRuleCheck {
				matches: check_inbox_rule(&rule.r#type, &rule.value, &rule_subject),
				exclude_from_spam_filter: rule.excludeFromSpamFilter.unwrap_or(false),
			})
			.collect();

		let datum = create_spam_mail_datum(&mail, &details);
		let mut probability = None;
		let model_says_spam = match spam_model {
			Some(bytes) => {
				let model =
					SpamModel::decode(&bytes).map_err(|e| ApiCallError::internal(e.to_string()))?;
				match create_model_input(&datum) {
					Some(input) => match model.is_spam(&input) {
						Ok((is_spam, p)) => {
							probability = Some(p);
							Some(is_spam)
						},
						Err(_) => None,
					},
					None => None,
				}
			},
			None => None,
		};

		let (is_spam, reason) = decide(&NewMailFacts {
			source_folder,
			phishing_status: mail.phishingStatus,
			server_classification_data: mail.serverClassificationData.as_deref(),
			sender_trust,
			inbox_rules,
			model_says_spam,
		});
		Ok(verdict(is_spam, reason, probability))
	}
}

#[uniffi::export]
impl SpamNotificationFilter {
	/// Whether the app will move a newly received mail to spam. `spam_model` is the stored
	/// `spam_classification_model.model` of the mail's mailbox.
	pub async fn check_new_mail(
		&self,
		mail_id: IdTupleGenerated,
		spam_model: Option<Vec<u8>>,
	) -> Result<NewMailSpamVerdict, ApiCallError> {
		self.check(&mail_id, spam_model).await
	}
}

fn verdict(
	is_spam: bool,
	reason: SpamDecisionReason,
	probability: Option<f32>,
) -> NewMailSpamVerdict {
	NewMailSpamVerdict {
		is_spam,
		reason: format!("{reason:?}"),
		probability,
	}
}

/// `cleanMailAddress` from CommonCalendarUtils / FormatUtils
fn clean_mail_address(address: &str) -> String {
	address.trim().to_lowercase()
}

/// `isTutaTeamMail` from SharedMailUtils.ts, without the encryption auth check (fails open)
fn is_tuta_team_mail(mail: &Mail) -> bool {
	let address = mail.sender.address.as_str();
	mail.confidential
		&& mail.state == MAIL_STATE_RECEIVED
		&& (address == SYSTEM_GROUP_MAIL_ADDRESS
			|| address.ends_with("@tutao.de")
			|| address == "no-reply@tutanota.de")
}

fn addresses(list: &[MailAddress]) -> Vec<&str> {
	list.iter().map(|a| a.address.as_str()).collect()
}

/// `joinNamesAndMailAddresses` from SpamMailProcessor.ts
fn join_names_and_mail_addresses(addresses: &[MailAddress]) -> String {
	addresses
		.iter()
		.map(|a| format!("{} {}", a.name, a.address))
		.collect::<Vec<_>>()
		.join(" ")
}

/// `convertAuthStatusToSpamCategorizationToken` from SpamMailProcessor.ts
fn auth_status_token(auth_status: Option<i64>) -> &'static str {
	match auth_status {
		Some(0) => "TAUTHENTICATED",
		Some(1) => "THARDFAIL",
		Some(2) => "TSOFTFAIL",
		Some(3) => "TINVALIDMAILFROM",
		Some(4) => "TMISSINGMAILFROM",
		_ => "",
	}
}

/// `createSpamMailDatum` from SpamMailProcessor.ts
pub fn create_spam_mail_datum(mail: &Mail, details: &MailDetails) -> SpamMailDatum {
	SpamMailDatum {
		subject: mail.subject.clone(),
		body: details
			.body
			.compressedText
			.clone()
			.or_else(|| details.body.text.clone())
			.unwrap_or_default(),
		sender: join_names_and_mail_addresses(std::slice::from_ref(&mail.sender)),
		to_recipients: join_names_and_mail_addresses(&details.recipients.toRecipients),
		cc_recipients: join_names_and_mail_addresses(&details.recipients.ccRecipients),
		bcc_recipients: join_names_and_mail_addresses(&details.recipients.bccRecipients),
		auth_status: auth_status_token(mail.authStatus).to_owned(),
		server_classification_data: mail.serverClassificationData.clone(),
	}
}
