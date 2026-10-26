import { subjectMatches } from './caep/subjects.js';
import { OAuthError, OIDCClientError } from './errors.js';
import { IndexedDBTokenStore, MemoryTokenStore, WebStorageTokenStore } from './stores.js';
import { TokenManager } from './token-manager.js';
import { base64url, digest, Emitter, withLock } from './util.js';

/** ID token claims an account record keeps, for display and for naming the account to the OP. No tokens. */
const PROFILE_CLAIMS = ['iss', 'sub', 'sid', 'name', 'given_name', 'family_name', 'preferred_username', 'email',
  'phone_number', 'picture', 'acr', 'amr', 'auth_time'];

/**
 * Errors the OP answers a `prompt=none` request with when it would have to show the person a screen
 * (OpenID Connect Core §3.1.2.6). `account_selection_required` is what an OP holding several signed-in
 * accounts answers when nothing in the request says which one.
 */
export const INTERACTION_REQUIRED = Object.freeze(['login_required', 'interaction_required', 'account_selection_required', 'consent_required']);

/** True when `err` is an OAuthError that a request showing the sign-in screen (no `prompt=none`) would get past. */
export function needsInteraction(err) {
  return err instanceof OAuthError && INTERACTION_REQUIRED.includes(err.error);
}

/**
 * @typedef {object} Account  One person signed in through this client in this browser. Holds no token.
 * @property {string} key          Stable id derived from `iss` and `sub`.
 * @property {string} iss
 * @property {string} sub
 * @property {string} [sid]        The OP session (OpenID Connect Front-/Back-Channel Logout `sid`).
 * @property {string} [name]
 * @property {string} [email]
 * @property {string} [preferred_username]
 * @property {'signed-in'|'tokens-missing'|'signed-out'|'ended'} status
 *           `signed-in`: its tokens are in the cache. `tokens-missing`: not signed out, but its cached tokens
 *           could not be used (e.g. expired with no refresh token); `resume()` asks the OP for new ones
 *           without a screen while its session there lasts. `ended`: ended by the OP, a security event or a
 *           refused refresh; see `endedReason`.
 * @property {string} [endedReason]
 * @property {number} addedAt
 * @property {number} lastUsedAt
 * @property {number} [changedAt]  When the status last left `signed-in`.
 */

/**
 * @callback AccountHook
 * @param {Account} account
 * @param {{ getTokenSet: (opts?: { forceRefresh?: boolean }) => Promise<import('./token-set.js').TokenSet> }} access
 *        Reaches this account's tokens during the hook (and, for `onActivate`, for as long as it stays active).
 * @returns {void|Promise<void>}
 */

/**
 * @typedef {object} AccountManagerOptions
 * @property {import('./stores.js').TokenStore} [store]  The cache shared by every tab: the account list and
 *           each account's tokens. Default: IndexedDB where it exists (`IndexedDBTokenStore`), else memory.
 * @property {import('./stores.js').TokenStore} [tabStore]  Where this tab remembers its active account.
 *           Default: sessionStorage where it exists, else memory.
 * @property {string} [storeKey]                Default "accounts".
 * @property {number} [refreshSkewSec]          Default 60.
 * @property {number} [maxAccounts]             Default 10. Past it the account signed out longest ago is
 *           forgotten; when every place is held by a signed-in account, a further sign-in is refused.
 * @property {number} [rememberSignedOutDays]   How long a signed-out account stays listed. Default 30.
 * @property {(account: Account) => string|undefined} [loginHint]  What names an account to the OP in
 *           `login_hint`. Default: `preferred_username`, else `email`.
 * @property {AccountHook} [onActivate]  Runs when an account is about to become this tab's active account,
 *           after its tokens are refreshed if due and before "activated" is emitted — e.g. to poll its CAEP
 *           stream and act on the signals queued while it was dormant. Throwing aborts the activation.
 * @property {(account: Account) => void|Promise<void>} [onDeactivate]  Runs when an account stops being
 *           this tab's active account (e.g. to stop polling its stream).
 * @property {AccountHook} [onLeave]  Runs before an account's tokens are deleted by `signOut()` or `end()`
 *           (e.g. to delete its CAEP stream while its tokens still work).
 * @property {boolean} [broadcast]  Tell this origin's other tabs about changes (BroadcastChannel). Default true.
 */

/**
 * Every account signed in through one client in this browser, with ONE active account per tab — for an
 * OP that keeps several signed-in accounts per browser (e.g. iya-sts `authn.multipleAccounts`).
 *
 * - **One cache, shared by every tab.** Each account's tokens are kept (IndexedDB by default) until it is
 *   signed out or its session ends, so any tab can make any signed-in account active with no trip to the OP.
 * - **One active account per tab.** Only its tokens are reachable (`getTokenSet()`), and only its tokens are
 *   refreshed in the background. The others are dormant: stored, not used, not refreshed. `activate(key)`
 *   refreshes a dormant account's tokens if they are due and runs `onActivate` before it becomes active.
 * - Refreshes hold a lock shared by the tabs (Web Locks), so two tabs never present one rotating refresh
 *   token twice; sign-outs and ended sessions are announced to the other tabs (BroadcastChannel).
 *
 * Signing in: `signIn()` lets the OP decide (its account picker when several are signed in there);
 * `chooseAccount()` always shows the picker (`prompt=select_account`); `addAccount()` is a fresh sign-in
 * (`prompt=login`). `resume(key)` and `reauthenticate(key)` name the account and refuse anybody else.
 * `signOut(key)` revokes that account's tokens and names its ID token at logout, so the OP ends that
 * account's session only.
 *
 * Events: "added" (account), "updated" (account), "activated" (account|undefined, previous|undefined),
 * "refreshed" (account) for the active account, "signed-out" (account), "ended" (account, reason),
 * "forgotten" (account), "activation_error" (account, error), and "change" after any of them, including
 * changes made in another tab.
 */
export class AccountManager extends Emitter {
  #client;
  #tokens;
  #store;
  #tabStore;
  #storeKey;
  #opts;
  /** @type {Map<string, Account>} */
  #accounts = new Map();
  #active;
  #activating;
  #channel;

  /**
   * @param {import('./oidc-client.js').OIDCClient} client
   * @param {AccountManagerOptions} [opts]
   */
  constructor(client, {
    store, tabStore, storeKey = 'accounts', refreshSkewSec = 60, maxAccounts = 10, rememberSignedOutDays = 30,
    loginHint, onActivate, onDeactivate, onLeave, broadcast = true,
  } = {}) {
    super();
    this.#client = client;
    this.#store = store ?? (typeof indexedDB === 'undefined' ? new MemoryTokenStore() : new IndexedDBTokenStore());
    this.#tabStore = tabStore ?? (globalThis.sessionStorage ? new WebStorageTokenStore({ prefix: 'oidc-caep-client:tab:' }) : new MemoryTokenStore());
    this.#storeKey = storeKey;
    this.#opts = {
      maxAccounts, rememberSignedOutDays, refreshSkewSec, onActivate, onDeactivate, onLeave,
      loginHint: loginHint ?? ((a) => a.preferred_username ?? a.email),
    };
    this.#tokens = new TokenManager(client, { store: this.#store, refreshSkewSec });
    this.#tokens.on('refreshed', (key, ts) => { this.#onRefreshed(key, ts).catch(() => {}); });
    this.#tokens.on('expired', (key) => { this.end(key, 'Its tokens could not be renewed.').catch(() => {}); });
    if (broadcast && typeof BroadcastChannel !== 'undefined') {
      this.#channel = new BroadcastChannel(`oidc-caep-client:${storeKey}`);
      this.#channel.onmessage = () => { this.#onRemoteChange().catch(() => {}); };
      this.#channel.unref?.();
    }
  }

  /**
   * Loads the shared account list and reactivates the account this tab had active (refreshing its tokens
   * if due and running `onActivate`). A failed reactivation leaves the tab with no active account and is
   * emitted as "activation_error".
   */
  async init() {
    const forgetBefore = Date.now() - this.#opts.rememberSignedOutDays * 86_400_000;
    await this.#mutate(() => {
      for (const a of [...this.#accounts.values()]) {
        if (a.status === 'signed-out' && (a.changedAt ?? 0) < forgetBefore) this.#accounts.delete(a.key);
      }
    });
    const remembered = await this.#tabStore.get(this.#tabKey());
    if (remembered && this.#accounts.has(remembered)) {
      try {
        await this.#activate(remembered);
      } catch (err) {
        this.emit('activation_error', this.get(remembered), err);
      }
    }
    return this;
  }

  /** @returns {Account[]} Every account in this browser, in the order added. */
  list() {
    return [...this.#accounts.values()].sort((a, b) => a.addedAt - b.addedAt).map((a) => ({ ...a }));
  }

  /** @returns {Account|undefined} */
  get(key) {
    const a = this.#accounts.get(key);
    return a && { ...a };
  }

  /** @returns {Account|undefined} This tab's active account (whatever its status). */
  get active() { return this.get(this.#active); }
  get activeKey() { return this.#active; }

  /** The identity `subjectMatches()` compares a security event's subject with. */
  identity(key) {
    const a = this.#accounts.get(key);
    return a && { iss: a.iss, sub: a.sub, email: a.email, phone_number: a.phone_number, sid: a.sid };
  }

  /**
   * The accounts a security event's subject (`sub_id`) is about. A subject naming a session (an SSF
   * complex subject with `session`) matches only the account signed in with that session.
   * @param {object} subId
   * @returns {Account[]}
   */
  accountsForSubject(subId) {
    return this.list().filter((a) => subjectMatches(subId, this.identity(a.key)));
  }

  // ---------------------------------------------------------------------------
  // The active account's tokens: the only ones reachable
  // ---------------------------------------------------------------------------

  /**
   * The active account's tokens, refreshed first when (nearly) expired. A dormant account's tokens cannot
   * be reached: activate the account first.
   * @param {{ forceRefresh?: boolean }} [opts]
   */
  getTokenSet(opts) {
    return this.#tokensFor(this.#active, opts);
  }

  /** Refreshes the active account's tokens now. */
  refresh() {
    return this.#tokensFor(this.#active, { forceRefresh: true });
  }

  async #tokensFor(key, opts) {
    if (!key || (key !== this.#active && key !== this.#activating)) {
      throw new OIDCClientError('Only the active account\'s tokens can be used; activate the account first', { code: 'not_active' });
    }
    if (this.#accounts.get(key)?.status !== 'signed-in') {
      throw new OIDCClientError('The active account is not signed in', { code: 'no_tokens' });
    }
    return this.#tokens.getTokenSet(key, opts);
  }

  // ---------------------------------------------------------------------------
  // Signing in
  // ---------------------------------------------------------------------------

  /**
   * A sign-in that leaves the choice to the OP: with several accounts signed in there, it shows its
   * account picker; with one, it answers as that account.
   * @param {Parameters<import('./oidc-client.js').OIDCClient['createAuthorizationRequest']>[0]} [opts]
   */
  signIn(opts = {}) {
    return this.#client.createAuthorizationRequest({ ...opts, context: { intent: 'sign-in' } });
  }

  /** A sign-in that always shows the OP's account picker (`prompt=select_account`). */
  chooseAccount(opts = {}) {
    return this.#client.createAuthorizationRequest({ ...opts, prompt: 'select_account', context: { intent: 'choose' } });
  }

  /** A fresh sign-in (`prompt=login`), never the OP's picker: whoever signs in is added as an account. */
  addAccount(opts = {}) {
    return this.#client.createAuthorizationRequest({ ...opts, prompt: 'login', context: { intent: 'add' } });
  }

  /**
   * Asks the OP for this account's tokens again without showing a screen (`prompt=none`, naming the
   * account with `login_hint` and, where cached, `id_token_hint`). Answers with an OAuthError for which
   * `needsInteraction()` is true when the account's session at the OP has ended; `reauthenticate()` then.
   * @param {string} key
   */
  resume(key, opts = {}) {
    return this.#accountRequest(key, 'resume', { prompt: 'none', ...opts });
  }

  /**
   * Signs this account's person in again at the OP (`prompt=login` by default), e.g. for step-up with
   * `acrValues`/`maxAge`. A sign-in as anybody else is refused at the callback (`account_mismatch`).
   * @param {string} key
   */
  reauthenticate(key, opts = {}) {
    return this.#accountRequest(key, 'reauth', { prompt: 'login', ...opts });
  }

  async #accountRequest(key, intent, opts) {
    const a = this.#mustGet(key);
    const cached = await this.#tokens.get(key);
    return this.#client.createAuthorizationRequest({
      loginHint: this.#opts.loginHint(a),
      idTokenHint: cached?.id_token,
      ...opts,
      expectedSub: a.sub,
      context: { intent, key },
    });
  }

  /**
   * Completes any of the requests above from the redirect. The account signed in is added to the cache
   * (or, when it is already listed, signed in again) and becomes this tab's active account.
   *
   * An error the OP returned is thrown as an OAuthError with `err.context` (`{ intent, key? }`) and, for
   * `resume`/`reauth`, `err.account`.
   * @param {URLSearchParams|Record<string,string>|string} response
   * @returns {Promise<{ account: Account, tokenSet: import('./token-set.js').TokenSet, intent: string, added: boolean }>}
   */
  async handleCallback(response) {
    let result;
    try {
      result = await this.#client.completeAuthorization(response);
    } catch (err) {
      if (err.context?.key) {
        await this.#load();
        err.account = this.get(err.context.key);
      }
      throw err;
    }
    const { tokenSet, context } = result;
    const claims = tokenSet.claims;
    const key = await accountKey(claims.iss, claims.sub);
    let added = false;
    await this.#mutate(async () => {
      let account = this.#accounts.get(key);
      added = !account;
      if (added) {
        this.#makeRoom(tokenSet);
        account = { key, addedAt: Date.now() };
        this.#accounts.set(key, account);
      }
      for (const c of PROFILE_CLAIMS) delete account[c];
      Object.assign(account, pick(claims, PROFILE_CLAIMS), { status: 'signed-in', lastUsedAt: Date.now() });
      delete account.endedReason;
      delete account.changedAt;
      await this.#tokens.set(key, tokenSet, { schedule: false });
    });
    this.emit(added ? 'added' : 'updated', this.get(key));
    await this.#activate(key);
    return { account: this.get(key), tokenSet, intent: context?.intent ?? 'sign-in', added };
  }

  // ---------------------------------------------------------------------------
  // Activating
  // ---------------------------------------------------------------------------

  /**
   * Makes a listed account this tab's active account; the previous one becomes dormant. Nothing is sent to
   * the OP unless the account's tokens are due for a refresh. An account that is not `signed-in` becomes
   * active too, with no tokens; `resume()` or `reauthenticate()` it.
   *
   * When the refresh or `onActivate` fails, the previously active account is reactivated and the error thrown.
   * @param {string} key
   * @returns {Promise<Account|undefined>}
   */
  async activate(key) {
    this.#mustGet(key);
    const previous = this.#active;
    try {
      await this.#activate(key);
    } catch (err) {
      if (previous && previous !== key && this.#active !== previous) await this.#activate(previous).catch(() => {});
      throw err;
    }
    return this.active;
  }

  async #activate(key) {
    await this.#load();
    const previous = this.#active;
    if (previous && previous !== key) await this.#deactivate();
    this.#mustGet(key);
    if (this.#accounts.get(key).status === 'signed-in') {
      let ts = await this.#tokens.get(key);
      if (ts?.isExpired(this.#opts.refreshSkewSec)) {
        ts = ts.refresh_token ? await this.#tokens.refresh(key) : undefined;
      }
      if (!ts) {
        await this.#tokens.delete(key).catch(() => {});
        await this.#mutate(() => this.#setStatus(key, 'tokens-missing'));
      } else if (this.#opts.onActivate) {
        this.#activating = key;
        try {
          await this.#opts.onActivate(this.get(key), { getTokenSet: (opts) => this.#tokensFor(key, opts) });
        } finally {
          this.#activating = undefined;
        }
        await this.#load(); // a signal acted on during onActivate may have ended the account
      }
    }
    this.#active = key;
    await this.#tabStore.set(this.#tabKey(), key);
    if (this.#accounts.get(key)?.status === 'signed-in') {
      await this.#mutate(() => { const a = this.#accounts.get(key); if (a) a.lastUsedAt = Date.now(); });
      await this.#tokens.schedule(key);
    }
    if (previous !== key) this.emit('activated', this.get(key), this.get(previous));
    this.emit('change');
  }

  async #deactivate() {
    const key = this.#active;
    if (!key) return;
    this.#tokens.unschedule(key);
    this.#active = undefined;
    await this.#tabStore.delete(this.#tabKey());
    const a = this.get(key);
    if (a) await Promise.resolve(this.#opts.onDeactivate?.(a)).catch(() => {});
  }

  // ---------------------------------------------------------------------------
  // Signing out, ending, forgetting
  // ---------------------------------------------------------------------------

  /**
   * Signs one account out of this browser: `onLeave` runs, its tokens are revoked (with `revoke`) and
   * removed from the cache, and it stays listed as `signed-out`. When it was this tab's active account,
   * the most recently added signed-in account becomes active. Answers an RP-Initiated Logout request
   * naming that account's ID token, so the OP ends that account's session only (or undefined: no
   * end_session_endpoint, or `endSession: false`).
   * @param {string} [key]  Default: the active account.
   * @param {{ revoke?: boolean, endSession?: boolean, postLogoutRedirectUri?: string }} [opts]
   * @returns {Promise<{ url: string, state: string }|undefined>}
   */
  async signOut(key = this.#active, { revoke = true, endSession = true, postLogoutRedirectUri } = {}) {
    const { account, idToken } = await this.#leave(key, 'signed-out', { revoke });
    await this.#afterLeaving(key);
    this.emit('signed-out', account);
    this.emit('change');
    if (!endSession) return undefined;
    return this.#client.createEndSessionRequest({
      idTokenHint: idToken,
      logoutHint: idToken ? undefined : this.#opts.loginHint(account),
      postLogoutRedirectUri,
      context: { key },
    });
  }

  /**
   * Signs every account out of this browser. Answers one logout request that names nobody, so an OP
   * holding several accounts asks the person which to end (or all of them).
   * @param {{ revoke?: boolean, endSession?: boolean, postLogoutRedirectUri?: string }} [opts]
   */
  async signOutAll({ revoke = true, endSession = true, postLogoutRedirectUri } = {}) {
    await this.#load();
    const previous = this.active;
    for (const a of this.list().filter((x) => x.status === 'signed-in' || x.status === 'tokens-missing')) {
      const { account } = await this.#leave(a.key, 'signed-out', { revoke });
      this.emit('signed-out', account);
    }
    if (this.#active) await this.#deactivate();
    if (previous) this.emit('activated', undefined, this.get(previous.key));
    this.emit('change');
    if (!endSession) return undefined;
    return this.#client.createEndSessionRequest({ postLogoutRedirectUri, context: { all: true } });
  }

  /**
   * Ends an account's session in this browser because the OP or a security event says it has ended:
   * `onLeave` runs, its tokens are removed from the cache (not revoked: the OP already knows), and it stays
   * listed as `ended` with the reason. When it was this tab's active account, the most recently added
   * signed-in account becomes active. Does nothing for an account that is not signed in.
   * @param {string} key
   * @param {string} [reason]
   * @returns {Promise<Account|undefined>}
   */
  async end(key, reason) {
    await this.#load();
    const a = this.#accounts.get(key);
    if (!a || (a.status !== 'signed-in' && a.status !== 'tokens-missing')) return a && { ...a };
    const { account } = await this.#leave(key, 'ended', { revoke: false, reason });
    // During its onActivate the account is not active yet; #activate sees the status when the hook returns.
    if (this.#activating !== key) await this.#afterLeaving(key);
    this.emit('ended', account, reason);
    this.emit('change');
    return this.get(key);
  }

  /** Removes an account that is not signed in from the list. A signed-in account must be signed out first. */
  async forget(key) {
    let removed;
    await this.#mutate(() => {
      const a = this.#mustGet(key);
      if (a.status === 'signed-in') throw new OIDCClientError('Sign the account out before forgetting it', { code: 'account_signed_in' });
      this.#accounts.delete(key);
      removed = a;
    });
    await this.#tokens.delete(key).catch(() => {});
    if (this.#active === key) {
      this.#active = undefined;
      await this.#tabStore.delete(this.#tabKey());
      this.emit('activated', undefined, removed);
    }
    this.emit('forgotten', removed);
    this.emit('change');
  }

  /** Cancels refresh timers and stops listening to other tabs (call on shutdown). */
  close() {
    this.#tokens.close();
    this.#channel?.close();
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  #tabKey() { return `active:${this.#storeKey}`; }

  #mustGet(key) {
    const a = this.#accounts.get(key);
    if (!a) throw new OIDCClientError(`No account ${key}`, { code: 'no_account' });
    return a;
  }

  /** Runs onLeave, drops the tokens and records the new status. */
  async #leave(key, status, { revoke, reason }) {
    await this.#load();
    const a = this.#mustGet(key);
    const cached = await this.#tokens.get(key);
    if (cached && this.#opts.onLeave) {
      await Promise.resolve(this.#opts.onLeave(this.get(key), { getTokenSet: (opts) => this.#tokens.getTokenSet(key, opts) })).catch(() => {});
    }
    await this.#tokens.delete(key, { revoke }).catch(() => {});
    await this.#mutate(() => {
      this.#setStatus(key, status);
      const x = this.#accounts.get(key);
      if (x && reason !== undefined) x.endedReason = reason;
    });
    return { account: this.get(key) ?? { ...a, status }, idToken: cached?.id_token };
  }

  /** When the account that left was this tab's active one, the most recently added signed-in account takes over. */
  async #afterLeaving(key) {
    if (this.#active !== key) return;
    await this.#deactivate();
    const next = [...this.#accounts.values()].filter((a) => a.status === 'signed-in').sort((a, b) => b.addedAt - a.addedAt)[0];
    if (next) {
      await this.#activate(next.key).catch((err) => this.emit('activation_error', this.get(next.key), err));
    } else {
      this.emit('activated', undefined, this.get(key));
    }
  }

  #setStatus(key, status) {
    const a = this.#accounts.get(key);
    if (!a) return;
    a.status = status;
    a.changedAt = Date.now();
    if (status !== 'ended') delete a.endedReason;
  }

  /** Before adding an account at the limit: forget the account that left longest ago, or refuse. */
  #makeRoom(tokenSet) {
    if (this.#accounts.size < this.#opts.maxAccounts) return;
    const droppable = [...this.#accounts.values()].filter((a) => a.status !== 'signed-in')
      .sort((a, b) => (a.changedAt ?? a.lastUsedAt) - (b.changedAt ?? b.lastUsedAt));
    if (!droppable.length) {
      void Promise.allSettled([
        tokenSet.refresh_token && this.#client.revoke(tokenSet.refresh_token, 'refresh_token'),
        this.#client.revoke(tokenSet.access_token, 'access_token'),
      ]);
      throw new OIDCClientError(`${this.#opts.maxAccounts} accounts are signed in already; sign one out first`, { code: 'too_many_accounts' });
    }
    this.#accounts.delete(droppable[0].key);
    this.#tokens.delete(droppable[0].key).catch(() => {});
    this.emit('forgotten', droppable[0]);
  }

  async #onRefreshed(key, ts) {
    if (!ts.claims) return;
    await this.#mutate(() => {
      const a = this.#accounts.get(key);
      if (a) Object.assign(a, pick(ts.claims, PROFILE_CLAIMS));
    });
    if (key === this.#active) this.emit('refreshed', this.get(key));
    this.emit('change');
  }

  /** Another tab changed the list. When this tab's active account has left, its tokens stop being refreshed here. */
  async #onRemoteChange() {
    await this.#load();
    const key = this.#active;
    if (key && this.#accounts.get(key)?.status !== 'signed-in') this.#tokens.unschedule(key);
    if (key && !this.#accounts.has(key)) {
      this.#active = undefined;
      await this.#tabStore.delete(this.#tabKey());
      this.emit('activated', undefined, undefined);
    }
    this.emit('change');
  }

  async #load() {
    const saved = await this.#store.get(this.#storeKey);
    this.#accounts = new Map((saved?.accounts ?? []).map((a) => [a.key, a]));
  }

  /** Read-modify-write of the shared list, under a lock shared by the tabs; then tells the other tabs. */
  async #mutate(fn) {
    await withLock(`oidc-caep-client:${this.#storeKey}`, async () => {
      await this.#load();
      await fn();
      await this.#store.set(this.#storeKey, { accounts: [...this.#accounts.values()] });
    });
    this.#channel?.postMessage({ type: 'change' });
  }
}

/** The account key for an `iss` and `sub`: stable, opaque, and safe in a storage key or a URL. */
export async function accountKey(iss, sub) {
  return `acct-${base64url(await digest(`${iss}\n${sub}`)).slice(0, 22)}`;
}

function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (obj[k] !== undefined) out[k] = obj[k];
  return out;
}
