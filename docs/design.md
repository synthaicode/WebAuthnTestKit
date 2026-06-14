# WebAuthnTestKit — IF仕様と利用イメージ

FIDO2/WebAuthnで保護されたAPIを、**疑似デバイス(ソフトウェアauthenticator)**で
自動テスト/プログラム駆動するためのC#ツールキット。

> **状態**: 本書は**実装済みのAPIに同期**しています(コア①+②完成)。進捗は [status.md](status.md)、
> 動く例は `samples/`。仕様の細部はソース(`src/WebAuthnTestKit/`)が最終的な正本です。

---

## 0. これは何で、何でないか(スコープ宣言)

> WebAuthnTestKit is **not** a WebAuthn server library.
> It is **not** an HTTP client.
> It is a **test-side toolkit** that converts application-specific WebAuthn API envelopes
> into standard WebAuthn DTOs, signs them with a software test authenticator,
> and converts the result back into the application's finish JSON shape.

- **サーバ検証ライブラリではない**(検証する側=`py_webauthn`/`webauthn4j` 等の鏡像)。
- **HTTPクライアントではない**。begin/finish を叩くのも、セッション継続も利用者責務。
- 初期版は **attestation fmt=`none` のみ対応**。認証器の真正性検証やAAGUID制限のテストは対象外。
  (疑似デバイスとAPIテストのブートストラップ用途。enterprise attestationポリシーのテストは非対象)

---

## 1. 背景と課題

| | ID/PASS時代 | FIDO2/WebAuthn |
|---|---|---|
| クレデンシャルの性質 | 持ち運び可能・**ドメイン非依存** | **ドメイン束縛**(RP ID)・非可搬 |
| 認証に必要な知識 | 認証APIのIF(契約)だけ | + RPドメイン + 儀式 + authenticator所持 + 人の所作 |
| 戻り値 | トークン文字列 | WebAuthnの標準構造 を **各APIが独自JSONで包む** |

WebAuthnの**中核(clientDataJSON / authenticatorData / 署名 / CBOR)は標準化**されているが、
それを**包むサーバ側エンベロープ(JSON構造・チャレンジのエンコード・戻りトークンの置き場・
begin↔finishで引き継ぐ値)は各サービス独自**。ここに断絶がある。

「昔は認証APIのIFさえ知ればよかった」を、**疑似デバイス + エンベロープ記述子**で
宣言的に取り戻すのが本ツールキットの狙い。

---

## 2. コンセプトとスコープ

- **疑似デバイスを表現できる** — 物理キーなしでWebAuthnの儀式を回す(①)
- **各APIの独自エンベロープを解析・正規化する** — JSON記述子で吸収(②)
- **HTTPフロー実行(③)は利用者責務** — 本ツールは②までで止める純変換ライブラリ

### 確定事項

| 項目 | 決定 |
|---|---|
| 言語 | C#(.NET) |
| attestation | **`none` のみ**(暗号は最小。真正性テストは非対象) |
| 記述子フォーマット | JSON |
| 提供範囲 | **②(エンベロープ・コーデック)まで**。HTTP/セッションは利用者持ち |
| 公開API様式 | 記述子を**バインド済み**(コンストラクタ注入)+ **構築時 fail-fast 検証** |

---

## 3. アーキテクチャ

```
JSON(各API独自)
   ▲ │
   │ ▼   ┌─ RegistrationEnvelopeCodec ─┐
   ②────┤  AuthenticationEnvelopeCodec │──► 標準DTO ──► VirtualAuthenticator(①) ──► 暗号
         └─ EnvelopeEngine(共有・無状態)┘                                          (ES256/CBOR)
   ─────────────────────────────────────────────────────────────────
   ③ HTTPトランスポート / begin・finishのセッション継続 / トークン利用  ← 利用者が実装
```

- **境界DTO(標準WebAuthn型)** が Codec ⇄ デバイス の共通言語。
  - Codec: 「独自JSON ⇄ 標準DTO」
  - デバイス: 「標準DTO ⇄ 暗号」
- **`DecodeOptions` は `Options` と `Context`(begin応答)を一緒に返す** → finish で begin値を引き継ぐ。
- **EnvelopeEngine** は無状態。公開面は記述子バインド済みCodec(**利便性と純粋性の両取り**)。

---

## 4. IF仕様

### 4.1 境界DTO(API非依存・標準WebAuthn)

```csharp
// 儀式の入力(サーバのbegin応答から復号)
// Origin = clientDataJSON に書く完全オリジン(記述子の rp.origin 由来)。RpId(rpIdHash)とは別物。
record CreationOptions(byte[] Challenge, RpEntity Rp, UserEntity User, PubKeyCredParam[] Params, string Origin);
record RequestOptions (byte[] Challenge, string RpId, AllowCredential[] Allow, string Origin);

// begin応答の文脈(finishへ引き継ぐ source 値の供給源)
record EnvelopeContext(JsonNode BeginResponse, JsonNode? UserContext = null);

// DecodeOptions は Options と Context をセットで返す(finishで取り違えない)
record DecodedOptions<TOptions>(TOptions Options, EnvelopeContext Context);

// 儀式の出力(デバイスが生成、finish要求へ詰める)
record AttestationResult(byte[] CredentialId, byte[] ClientDataJson, byte[] AttestationObject);
record AssertionResult  (byte[] CredentialId, byte[] ClientDataJson, byte[] AuthenticatorData,
                         byte[] Signature, byte[]? UserHandle);

// finish応答の解析結果(token単独に閉じない。Valuesで多様な戻り値を受ける)
record CeremonyResult(
    bool Success,
    string? PrimaryToken,                            // 代表トークン(便宜アクセス用)
    IReadOnlyDictionary<string, string> Values,      // accessToken/refreshToken/idToken/sessionId/role/expiresIn...
    JsonNode Raw);

// 補助
record RpEntity(string Id, string? Name);
record UserEntity(byte[] Id, string Name, string DisplayName);
record PubKeyCredParam(string Type, int Alg);        // Alg = -7 (ES256) のみ初期対応
record AllowCredential(string Type, byte[] Id);
```

> **方針**: 戻り値の多様性(accessToken/refreshToken/idToken/sessionId/role/expiresIn 等)は
> `Values` 辞書で受ける。代表値だけ `PrimaryToken` で便宜アクセス。
> 専用の型付き `AuthSession` は**設けない**(辞書で十分・記述子で柔軟に拾える)。

### 4.2 疑似デバイス(①)

```csharp
class VirtualAuthenticator
{
    // 構築時に素性を固定(=「デバイスを登録する」の実体)
    public VirtualAuthenticator(VirtualAuthenticatorOptions options);

    AttestationResult MakeCredential(CreationOptions options);  // 登録。clientData.type = "webauthn.create"
    AssertionResult   GetAssertion (RequestOptions  options);   // 認証。clientData.type = "webauthn.get"

    // 状態の保存/復元(テスト間でデバイスを使い回す)
    DeviceState Export();
    static VirtualAuthenticator Import(DeviceState state);
}

record VirtualAuthenticatorOptions(
    Guid   Aaguid              = default,    // 既定: ゼロGUID
    int    Algorithm           = -7,         // ES256
    bool   SupportsResidentKey = true,
    bool   UserPresent         = true,       // UPフラグ
    bool   UserVerified        = true);      // UVフラグ
```

**契約上の注意:**

- **`GetAssertion` は `signCount` を更新する(mutable)。** 認証後は `Export()` して状態を保存すること。
  再現性が要るテストでは、各ケース開始時に既知の `DeviceState` を `Import` する。
- **`allowCredentials` 照合:** `RequestOptions.Allow` が非空のとき、登録済みcredentialが
  含まれなければ **fail-fast**(`No matching credential in allowCredentials.`)。実運用で頻発する事故。
- **clientDataJSON の `type` は固定**(登録=`webauthn.create` / 認証=`webauthn.get`)。記述子に依存させない。
- **`ClientDataJson` 内の challenge は仕様上必ず base64url**(記述子の `challengeEncoding` に依存させない)。
- attestation=`none` のため `AttestationObject` は `{ fmt:"none", attStmt:{}, authData }`。証明書チェーンは生成しない。

### 4.3 エンベロープ・コーデック(②)

```csharp
interface IEnvelopeCodec<TOptions, TFinish>
{
    // begin応答 → 標準options + 文脈(challengeを byte[] 化)
    DecodedOptions<TOptions> DecodeOptions(JsonNode beginResponse);

    // device出力 + begin文脈 → finish用body(source.* 引き継ぎが可能に)
    JsonNode EncodeFinish(TFinish deviceOutput, EnvelopeContext context);

    // finish応答 → token + Values + 成否
    CeremonyResult DecodeResult(JsonNode finishResponse);

    // 直近 EncodeFinish のデバッグ情報(失敗原因の追跡)
    EnvelopeDebugInfo? LastDebug { get; }
}

class RegistrationEnvelopeCodec   : IEnvelopeCodec<CreationOptions, AttestationResult>
{
    public RegistrationEnvelopeCodec(ServiceDescriptor descriptor);   // 構築時に記述子をバインド+検証
}
class AuthenticationEnvelopeCodec : IEnvelopeCodec<RequestOptions, AssertionResult>
{
    public AuthenticationEnvelopeCodec(ServiceDescriptor descriptor);
}

// 失敗追跡用(エンコード違い/rpId不一致/credentialId不一致/テンプレ埋め忘れ/JSONPathミス 等)
record EnvelopeDebugInfo(
    string RpId,
    string Origin,
    string ChallengeBase64Url,
    string CredentialIdBase64Url,
    string OptionsPath,
    IReadOnlyList<string> ResolvedTemplateVariables,
    IReadOnlyList<string> UnresolvedTemplateVariables);
```

各Codecの責務は **3点**:`DecodeOptions`(begin)/ `EncodeFinish`(finish要求)/ `DecodeResult`(finish応答)。

### 4.4 共有エンジン(無状態)・ファサード

```csharp
static class EnvelopeEngine          // Codecの下回り(重複排除)
{
    JsonNode Resolve(JsonNode root, string path);          // JSONパス解決
    byte[]   Decode (string s, string encoding);           // base64url/base64/hex
    string   Encode (byte[] b, string encoding);
    JsonNode Fill   (JsonNode template, IReadOnlyDictionary<string,string> values);  // {{...}} 差し込み
    bool     Eval   (JsonNode root, string condition);     // successWhen 評価
}

class TestKit                         // 多サービスの入口(名前空間 WebAuthnTestKit との衝突回避で TestKit)
{
    public TestKit(IEnumerable<ServiceDescriptor> descriptors);
    public static TestKit FromJson(params string[] descriptorJson);   // JSON文字列から直接ロード
    public RegistrationEnvelopeCodec   Registration(string service);
    public AuthenticationEnvelopeCodec Authentication(string service);
}
```

### 4.5 記述子の fail-fast 検証(構築時)

`new XxxEnvelopeCodec(descriptor)` の時点で最低限を検証し、**実行時ではなく初期化時に落とす**:

- `service` 名がある
- `rp.id` がある / `rp.origin` がURLとして妥当
- `begin.optionsPath` がある
- `challengeEncoding` が対応値(`base64url`/`base64`/`hex`)。`userIdEncoding`/`credentialIdEncoding` も同様(既定 base64url)
- `finish.body` に**未知の予約変数(`{{...}}`)が無い**(標準変数 or `source.*` のみ許可)
- `result.tokenPath` / `successWhen` / `values`(名前→パス map)はいずれも任意

### 4.6 JSON記述子スキーマ

標準WebAuthn responseフィールドを**個別に埋める方式**と、**assertion/attestation全体を
base64url化して1フィールドに入れる方式**の両対応。`{{source.*}}` で begin応答の値を finish に引き継ぐ。

```json
{
  "service": "example-api",
  "rp": { "id": "example.com", "origin": "https://example.com" },

  "registration": {
    "begin": {
      "optionsPath": "$.data.publicKey",
      "challengeEncoding": "base64url",
      "userIdEncoding": "base64url"
    },
    "finish": {
      "body": {
        "registrationId": "{{source.registrationId}}",
        "fidoAttestation": "{{attestationJsonBase64Url}}"
      },
      "result": { "tokenPath": "$.data.session.jwt", "successWhen": "$.status == 'ok'" }
    }
  },

  "assertion": {
    "begin": { "optionsPath": "$.publicKey", "challengeEncoding": "base64url", "credentialIdEncoding": "base64url" },
    "finish": {
      "body": {
        "requestId": "{{source.requestId}}",
        "fidoAssertion": "{{assertionJsonBase64Url}}"
      },
      "result": { "tokenPath": "$.token", "successWhen": "$.status == 'ok'",
                  "values": { "refreshToken": "$.refresh", "role": "$.user.role" } }
    }
  }
}
```

個別フィールド方式の例(`response` を素直に展開する従来型API):

```json
"finish": {
  "body": {
    "credential": {
      "id": "{{credentialId}}", "rawId": "{{rawId}}", "type": "public-key",
      "response": {
        "clientDataJSON": "{{clientDataJSON}}",
        "authenticatorData": "{{authenticatorData}}",
        "signature": "{{signature}}",
        "userHandle": "{{userHandle}}"
      }
    }
  }
}
```

#### 標準提供テンプレート変数

```
# 個別フィールド
{{credentialId}}
{{rawId}}
{{clientDataJSON}}
{{authenticatorData}}      # 認証のみ
{{signature}}              # 認証のみ
{{userHandle}}            # 認証のみ
{{attestationObject}}     # 登録のみ

# 全体オブジェクト(JSON文字列 / そのbase64url)
{{assertionJson}}         {{assertionJsonBase64Url}}     # 認証
{{attestationJson}}       {{attestationJsonBase64Url}}   # 登録

# begin応答からの引き継ぎ(任意パス)
{{source.<path>}}         # 例: {{source.requestId}} {{source.transactionId}}
                         #     {{source.state}} {{source.tenantId}} {{source.csrfToken}}
                         #     {{source.challengeId}} {{source.registrationToken}}
```

- `assertionJson` = 標準assertion responseオブジェクト全体(`{id,rawId,type,response:{...}}`)のJSON文字列。
  `assertionJsonBase64Url` はそのbase64url。登録側も同様。
- `rp.id` / `rp.origin` を**第一級項目**にして、ドメイン束縛をAPIごとに明示注入。
- `result.values`(任意)= 名前→JSONパスの map。finish応答から複数値を抽出して `CeremonyResult.Values` に格納。
  代表値は `result.tokenPath` → `PrimaryToken`。
- 宣言で収まらない変形は将来フック併用に逃がす(初期は宣言のみ)。

---

## 5. 利用イメージ

### 5.1 登録(Registration)

```csharp
var kit    = new TestKit(descriptors);                 // または TestKit.FromJson(descriptorJson)
var device = new VirtualAuthenticator(new());          // 疑似デバイスを用意
var reg    = kit.Registration("example-api");          // 記述子バインド済み(構築時に検証)

// ① 利用者: 事前ログイン(既存セッション確立)— 別手段の認証は利用者持ち
var http = new HttpClient(new HttpClientHandler { CookieContainer = jar });
await LoginWithPassword(http, ...);

// ② begin を叩く(HTTP=利用者)
var beginJson = await http.PostJsonAsync("/register/begin", new { ... });

// ③ Codec → デバイス → Codec(本ツールの担当)。Context を finish へ引き継ぐ
var decoded = reg.DecodeOptions(beginJson);            // Options + Context
var att     = device.MakeCredential(decoded.Options);  // 疑似デバイスが署名
var body    = reg.EncodeFinish(att, decoded.Context);  // source.* を含む finish body

// ④ finish を叩く(HTTP=利用者)。Cookie/CSRF/stateの継続も利用者持ち
var finishJson = await http.PostJsonAsync("/register/finish", body);

// ⑤ 結果解析(本ツール)
var result = reg.DecodeResult(finishJson);
Assert.True(result.Success);

// ⑥ デバイス状態を保存して認証フローへ持ち越す
var state = device.Export();
```

### 5.2 認証(Authentication)

```csharp
var device = VirtualAuthenticator.Import(state);       // 登録済みデバイスを復元
var auth   = kit.Authentication("example-api");

var beginJson  = await http.PostJsonAsync("/assertion/begin", new { ... });
var decoded    = auth.DecodeOptions(beginJson);
var assertion  = device.GetAssertion(decoded.Options); // ← signCount が進む
var body       = auth.EncodeFinish(assertion, decoded.Context);
var finishJson = await http.PostJsonAsync("/assertion/finish", body);

var result = auth.DecodeResult(finishJson);
var token  = result.PrimaryToken;                      // result.Values["refreshToken"] 等も取れる

// 認証後は必ず状態を保存(signCount を進めたため)
state = device.Export();

// ⑦ トークンを使って保護APIを検証(利用者のテスト本体)
http.DefaultRequestHeaders.Authorization = new("Bearer", token);
var protectedResp = await http.GetAsync("/me");
Assert.Equal(HttpStatusCode.OK, protectedResp.StatusCode);
```

### 5.3 失敗時のデバッグ

```csharp
var body = auth.EncodeFinish(assertion, decoded.Context);
if (auth.LastDebug is { UnresolvedTemplateVariables.Count: > 0 } dbg)
    throw new InvalidOperationException(
        $"未解決テンプレート: {string.Join(", ", dbg.UnresolvedTemplateVariables)} / rpId={dbg.RpId}");
```

---

## 6. ②で止めた場合に利用者へ残る処理

本ツールは「JSON ⇄ 署名 ⇄ JSON」の純変換のみ。以下は**利用者が実装**:

1. **HTTPトランスポート** — begin/finish を実際に叩く(`HttpClient`)。
2. **セッション継続(最大の山)** — サーバは begin のchallengeを Cookie/サーバ側stateで
   finish と紐付ける。**CookieContainer・CSRF・stateブロブの2呼び出し間の保持**。
   (`source.*` で本文に乗る値は本ツールが運ぶが、ヘッダ/Cookieは利用者)
3. **オーケストレーション/順序** — begin→①→②→finish の配線と中断制御。
4. **前段認証(ブートストラップ)** — 登録は「既ログイン済みセッション」や招待トークン前提が多い。
5. **トークンの利用** — 抽出後の保存・`Bearer`付与・リフレッシュ。
6. **エラー/ステータス解釈・リトライ** — HTTP/サーバ固有エラー封筒の判定。
7. **デバイス状態の永続化IO** — `Export`/`Import` の保存先選択とロード(`signCount` の保全)。
8. **テストアサーション** — 「トークン取得」「保護APIが200」の検証本体。

> 2〜4(特に begin/finish のセッション継続)が最も間違えやすい。
> 将来、利用者の `HttpClient` を注入する**薄い③(フローランナー)**を任意提供すれば、
> このハマりどころを一箇所に閉じ込められる(②止めでも成立はする)。

---

## 7. C#実装ピース

| 関心事 | 使用技術 |
|---|---|
| 鍵/署名(ES256) | `System.Security.Cryptography.ECDsa`(P-256 / SHA-256) |
| CBOR(COSE鍵・attestationObject) | `System.Formats.Cbor`(.NET標準) |
| JSON(記述子・エンベロープ操作) | `System.Text.Json` / `JsonNode` |
| JSONパス解決 | 簡易パス解決の自作 or `JsonPath.Net` 併用 |
| base64url | .NET 9 `Base64Url`、未満は自前変換 |

---

## 8. 設計判断の記録

- **記述子は「持つ」(コンストラクタ注入)+ 構築時検証** — テスト用途は「1フィクスチャ=1サービス」が主。
  呼び出し側が静か / fail-fast。動的切替が要る時だけ無状態エンジンを直接使う。
- **公開=バインド済みファサード、内部=無状態エンジン** — 利便性と純粋性の両立。
- **`DecodeOptions` は Options + Context を返す** — finish が begin の `source.*` 値を取り違えず引き継ぐ。
- **儀式ごとにCodecを分離** — 登録/認証でペイロード形が本質的に異なるため god-class を回避。
- **`GetAssertion` は mutable(`signCount` 更新)** — 初期はmutableで可。認証後 `Export` 必須をドキュメント明記。
- **`CeremonyResult`** — 代表値は `PrimaryToken`、その他は `Values` 辞書。型付き `AuthSession` は設けない。
- **clientDataJSON の type / challenge は仕様固定** — 記述子非依存。境界を切って事故防止。
- **`allowCredentials` 照合の fail-fast** — 未登録credentialでの認証試行を初期化段階で弾く。

---

## 9. 実装状況

この設計書のコア(①+②)は**実装完了**。当初の手順は全て消化済み:

1. ✅ 境界DTO 確定(`Origin` を含む)。
2. ✅ `VirtualAuthenticator`(ES256 / none / signCount / allowCredentials照合 / Export・Import)。
3. ✅ `EnvelopeEngine` + 2つのCodec + `TestKit` ファサード。
4. ✅ 構築時検証 + `EnvelopeDebugInfo`。
5. ✅ Docker 上の独立サーバ(Fido2NetLib)で end-to-end 疎通。

詳細な状況・テスト構成・CI/Release は [status.md](status.md) を参照。
サンプル(記述子 / デモサーバ / 実行可能クライアント)は `samples/` を参照。
