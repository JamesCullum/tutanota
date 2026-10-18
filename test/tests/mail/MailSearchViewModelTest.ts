import o from "@tutao/otest"
import { matchers, object, verify, when } from "testdouble"
import stream from "mithril/stream"
import { FULL_INDEXED_TIMESTAMP, Mode, TimeConstants, PlatformId, SessionType } from "../../../src/platform-kit/app-env"
import { MailSearchViewModel } from "../../../src/applications/mail-app/search/view/MailSearchViewModel"
import { LoginController } from "../../../src/applications/common/api/main/LoginController"
import { UserController } from "../../../src/applications/common/api/main/UserController"
import { Indexer } from "../../../src/applications/mail-app/workerUtils/index/Indexer"
import { DeviceConfig, ListAutoSelectBehavior } from "../../../src/applications/common/misc/DeviceConfig"
import { MailSearchModel } from "../../../src/applications/mail-app/search/model/MailSearchModel"
import { SearchIndexStateInfo } from "../../../src/applications/common/api/worker/search/SearchTypes"
import { PaidFunctionResult } from "../../../src/applications/common/search/SearchUtils"
import { SearchRouter } from "../../../src/applications/common/search/view/SearchRouter"
import { getFreeSearchStartDate, getMailRestriction } from "../../../src/applications/mail-app/search/model/MailSearchUtils"
import { withOverriddenEnv } from "../TestUtils"

o.spec("MailSearchViewModel", function () {
	const userId = "userId"
	const appEnv = { mode: Mode.App, platformId: PlatformId.Android }
	const indexTimestamp = Date.now() - 30 * TimeConstants.DAY_IN_MILLIS
	let isFree: boolean
	let sessionType: SessionType
	let indexerFacade: Indexer
	let deviceConfig: DeviceConfig
	let indexState: SearchIndexStateInfo

	function createViewModel(): MailSearchViewModel {
		const userController = Object.assign(object<UserController>(), { userId, sessionType })
		when(userController.isFreeAccount()).thenDo(() => isFree)
		const logins = object<LoginController>()
		when(logins.getUserController()).thenReturn(userController)
		const search = Object.assign(object<MailSearchModel>(), { indexState: stream(indexState) })
		return new MailSearchViewModel(
			object<SearchRouter>(),
			search,
			object(),
			object(),
			logins,
			indexerFacade,
			ListAutoSelectBehavior.NONE,
			deviceConfig,
			null,
			null,
			{ now: () => Date.now(), timeZone: () => "UTC" },
			() => {},
		)
	}

	o.beforeEach(function () {
		isFree = true
		sessionType = SessionType.Persistent
		indexerFacade = object()
		deviceConfig = new DeviceConfig(null)
		indexState = {
			initializing: false,
			mailIndexEnabled: true,
			progress: 0,
			currentMailIndexTimestamp: indexTimestamp,
			aimedMailIndexTimestamp: indexTimestamp,
			indexedMailCount: 0,
			failedIndexingUpTo: null,
			error: null,
		}
	})

	o.spec("free account search range", function () {
		o.test("is unlimited for a free account with a persistent session in the app", async function () {
			await withOverriddenEnv(appEnv, async () => {
				o(createViewModel().isFreeAccountWithUnlimitedSearchRange()).equals(true)
			})
		})

		o.test("is limited for a free account in the browser", async function () {
			await withOverriddenEnv({ mode: Mode.Browser }, async () => {
				o(createViewModel().isFreeAccountWithUnlimitedSearchRange()).equals(false)
			})
		})

		o.test("is limited for a free account with an ephemeral session", async function () {
			sessionType = SessionType.Temporary
			await withOverriddenEnv(appEnv, async () => {
				o(createViewModel().isFreeAccountWithUnlimitedSearchRange()).equals(false)
			})
		})

		o.test("is limited for a free account on desktop", async function () {
			await withOverriddenEnv({ mode: Mode.Desktop, platformId: PlatformId.Linux }, async () => {
				o(createViewModel().isFreeAccountWithUnlimitedSearchRange()).equals(false)
			})
		})

		o.test("is not applicable for a paid account", async function () {
			isFree = false
			await withOverriddenEnv(appEnv, async () => {
				o(createViewModel().isFreeAccountWithUnlimitedSearchRange()).equals(false)
			})
		})

		o.test("end of the search restriction is only applied if requested", function () {
			o(getMailRestriction({}, true).end).equals(getFreeSearchStartDate().getTime())
			o(getMailRestriction({}, false).end).equals(null)
		})
	})

	o.spec("selectStartDate", function () {
		const olderDate = new Date(indexTimestamp - 100 * TimeConstants.DAY_IN_MILLIS)

		o.test("free account with unlimited range gets the requested date and mail bodies are not included", async function () {
			await withOverriddenEnv(appEnv, async () => {
				const viewModel = createViewModel()
				o(viewModel.selectStartDate(olderDate)).equals(PaidFunctionResult.Success)
				verify(indexerFacade.extendMailIndex(olderDate.getTime(), false))
			})
		})

		o.test("free account with unlimited range includes mail bodies if the setting is on", async function () {
			deviceConfig.setSearchAllMailDetails(userId, true)
			await withOverriddenEnv(appEnv, async () => {
				createViewModel().selectStartDate(olderDate)
				verify(indexerFacade.extendMailIndex(olderDate.getTime(), true))
			})
		})

		o.test("paid account includes mail bodies", async function () {
			isFree = false
			await withOverriddenEnv(appEnv, async () => {
				o(createViewModel().selectStartDate(olderDate)).equals(PaidFunctionResult.Success)
				verify(indexerFacade.extendMailIndex(olderDate.getTime(), true))
			})
		})

		o.test("free account in the browser is still limited", async function () {
			await withOverriddenEnv({ mode: Mode.Browser }, async () => {
				const viewModel = createViewModel()
				o(viewModel.selectStartDate(olderDate)).equals(PaidFunctionResult.PaidSubscriptionNeeded)
				o(viewModel.startDate?.getTime()).equals(getFreeSearchStartDate().getTime())
			})
		})

		o.test("free account with an ephemeral session is still limited", async function () {
			sessionType = SessionType.Temporary
			await withOverriddenEnv(appEnv, async () => {
				o(createViewModel().selectStartDate(olderDate)).equals(PaidFunctionResult.PaidSubscriptionNeeded)
			})
		})
	})

	o.spec("search all mail details", function () {
		o.test("turning it on extends the mail index with mail bodies from the current index timestamp", async function () {
			await withOverriddenEnv(appEnv, async () => {
				const viewModel = createViewModel()
				viewModel.setSearchAllMailDetails(true)
				o(viewModel.getSearchAllMailDetails()).equals(true)
				verify(indexerFacade.extendMailIndex(indexTimestamp, true))
			})
		})

		o.test("turning it off only saves the setting", async function () {
			deviceConfig.setSearchAllMailDetails(userId, true)
			await withOverriddenEnv(appEnv, async () => {
				const viewModel = createViewModel()
				viewModel.setSearchAllMailDetails(false)
				o(viewModel.getSearchAllMailDetails()).equals(false)
				verify(indexerFacade.extendMailIndex(matchers.anything(), matchers.anything()), { times: 0 })
			})
		})

		o.test("extendMailIndex passes the setting", async function () {
			await withOverriddenEnv(appEnv, async () => {
				createViewModel().extendMailIndex(FULL_INDEXED_TIMESTAMP)
				verify(indexerFacade.extendMailIndex(FULL_INDEXED_TIMESTAMP, false))
			})
		})

		o.test("detail search is limited for start dates older than the mail body index timestamp", async function () {
			indexState.currentMailBodyIndexTimestamp = indexTimestamp + 10 * TimeConstants.DAY_IN_MILLIS
			await withOverriddenEnv(appEnv, async () => {
				const viewModel = createViewModel()
				viewModel.selectStartDate(new Date(indexTimestamp))
				o(viewModel.isMailDetailSearchLimited()).equals(true)
				viewModel.setSearchAllMailDetails(true)
				o(viewModel.isMailDetailSearchLimited()).equals(false)
			})
		})

		o.test("detail search is not limited if all indexed mails have bodies", async function () {
			await withOverriddenEnv(appEnv, async () => {
				const viewModel = createViewModel()
				viewModel.selectStartDate(new Date(indexTimestamp))
				o(viewModel.isMailDetailSearchLimited()).equals(false)
			})
		})
	})
})
