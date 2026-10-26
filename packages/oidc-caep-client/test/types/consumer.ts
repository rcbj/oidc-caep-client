// A TypeScript app using the library: this must compile, and each @ts-expect-error line must still fail.
import {
  AccountManager, CAEP, logEventReceived, needsInteraction, OIDCClient, SSFReceiver, Subject, subjectMatches,
  TokenManager, WebStorageKeyStore, type SecurityEvent, type TokenSet,
} from 'oidc-caep-client';

export async function app(): Promise<void> {
  const client: OIDCClient = await OIDCClient.discover({
    issuer: 'https://idp.example.com',
    clientId: 'my-spa',
    redirectUri: 'https://app.example.com/callback',
    dpop: { keyStore: new WebStorageKeyStore() },
  });
  const { url, state }: { url: string, state: string } = await client.createAuthorizationRequest({ prompt: 'login' });
  void url; void state;

  const tokens = new TokenManager(client);
  const set: TokenSet = await client.callback('https://app.example.com/callback?code=x&state=y');
  await tokens.set('user', set);
  const accessToken: string = set.access_token;
  const sub: unknown = set.claims?.sub;
  void accessToken; void sub;

  const receiver = new SSFReceiver({
    transmitterIssuer: 'https://idp.example.com',
    authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
    maxDeliveryAttempts: 3,
    onEventReceived: async (evt: SecurityEvent) => {
      logEventReceived(evt);
    },
  });
  receiver
    .onSessionRevoked((evt) => {
      const reason: string | undefined = evt.reasonUser?.en;
      void reason;
    })
    .onCredentialChange((evt) => {
      const change: unknown = evt.payload.change_type;
      void change;
    })
    .onError((err, ctx) => {
      const phase: string = ctx.phase;
      const retry: boolean | undefined = ctx.willRetry;
      void err.code; void phase; void retry;
    });
  // A handler may return whatever its work returns; a promise is awaited.
  const signOut = async (why: string): Promise<boolean> => why.length > 0;
  receiver.onSessionRevoked(() => signOut('Your session was ended.'));
  receiver.onEvent(CAEP.RISK_LEVEL_CHANGE, (evt) => {
    if (subjectMatches(evt.subject ?? {}, { iss: 'https://idp.example.com', sub: 'u1' })) void evt.jti;
  });
  await receiver.start({ catchUp: true });
  await receiver.addSubject(Subject.issSub('https://idp.example.com', 'u1'));

  const accounts = await new AccountManager(client, {
    onActivate: async (_account, { getTokenSet }) => { await getTokenSet(); },
  }).init();
  const active: TokenSet = await accounts.getTokenSet();
  void active;
  try {
    await accounts.resume('key');
  } catch (err) {
    const interaction: boolean = needsInteraction(err);
    void interaction;
  }

  // @ts-expect-error a handler must be a function
  receiver.onSessionRevoked('not a function');
  // @ts-expect-error transmitterIssuer is a string
  new SSFReceiver({ transmitterIssuer: 42 });
  // @ts-expect-error an access token is a string, not a number
  const wrong: number = set.access_token;
  void wrong;
  // @ts-expect-error clientId is required
  await OIDCClient.discover({ issuer: 'https://idp.example.com' });
}
