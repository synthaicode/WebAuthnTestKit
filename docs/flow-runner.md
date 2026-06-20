# Thin HTTP Flow Runner(③)— 設計ノート

状態: **計画段階**(未実装)。本書は [design.md §6](design.md) と [status.md](status.md) が将来作業
として挙げているレイヤ③の仕様。コア①(VirtualAuthenticator)+②(エンベロープコーデック)は不変で、
③はその上に乗る。

> English: [flow-runner.en.md](flow-runner.en.md)

---

## 0. 目的と非目的

コーデック層(②)は「JSON ⇄ 署名 ⇄ JSON」で止まる。その周り — begin/finish をHTTPで呼び、2回の呼び出しを
**同一セッション**に保つこと — は現状コンシューマの責務で、[`samples/DemoClient/Program.cs`](../samples/DemoClient/Program.cs)
の `RegisterFlow` / `AuthFlow` に手書きされている。[design.md §6](design.md) のとおり、項目2〜4(とりわけ
begin/finish のセッション継続)が最も間違いやすい。

**目的。** `begin → device → finish` を1呼び出しで連結する*薄い*ランナー。HttpClientは**コンシューマが注入**し、
begin と finish が必ず同一の `CookieContainer` / ハンドラを共有するようにする。セッション継続の落とし穴と失敗時の
診断を一箇所に閉じ込める。

**非目的(意図的に薄く保つ)。** ランナーは以下を**持たない**:

- ブートストラップのログイン(同じHttpClientで先にログイン済み前提)
- トークン利用(`Bearer` 付与、リフレッシュ)
- デバイス状態の永続化(`Export`/`Import` — ランナーはメモリ上で `signCount` を進めるのみ)
- テストアサーション
- リトライ/バックオフ方針

READMEの意味での「HTTPクライアント」にもならない。1セレモニーに必要な2回のPOSTだけ発行して返る。
「not an HTTP client」というスコープ宣言には1つだけ但し書きが付く — ③は**オプトイン**の利便機能で、独立した
名前空間に隔離される。

---

## 1. エンドポイントと begin ボディの出どころ

ディスクリプタは begin **レスポンス**内のオプション位置(`begin.optionsPath`)は知っているが、エンドポイントURLも
begin **リクエストボディ**も持たない。DemoClient は `/attestation/options`、`/assertion/options`、
`{ "username": ... }` をハードコードしている。

決定(v1): **呼び出し側がメソッド引数で渡す。** ディスクリプタのスキーマは不変、変更は完全に後方互換、ランナーは
1ファイルで済む。将来の宣言的 `transport` セクション(begin/finish パス + `{{ctx.*}}` の begin ボディテンプレート)は
別の大きめの機能で、本書のスコープ外。

---

## 2. 公開サーフェス

新名前空間 `WebAuthnTestKit.Flow`、型は1つ。`HttpClient` に触れる唯一のコードとして隔離する。

```csharp
namespace WebAuthnTestKit.Flow;

/// <summary>
/// オプションのレイヤ③。1セレモニーの begin → device → finish を、呼び出し側が注入した HttpClient 上で連結する。
/// 注入された client がセッション継続(cookie / CSRF / bearer)を担い、ランナーは自前の client を作らない。
/// 純粋な配線で、永続化・トークン・アサーションは呼び出し側のまま(design.md §6)。
/// </summary>
public sealed class WebAuthnFlowRunner
{
    public WebAuthnFlowRunner(HttpClient http, TestKit kit);

    public Task<FlowResult> RegisterAsync(
        string service,
        VirtualAuthenticator device,
        string beginPath,
        string finishPath,
        JsonNode beginBody,
        Action<HttpRequestMessage>? configureRequest = null,
        CancellationToken ct = default);

    public Task<FlowResult> AuthenticateAsync(
        string service,
        VirtualAuthenticator device,
        string beginPath,
        string finishPath,
        JsonNode beginBody,
        string? userVerification = null,                  // "required" | "preferred" | "discouraged"。指定時に begin ボディへ注入
        Action<HttpRequestMessage>? configureRequest = null,
        CancellationToken ct = default);
}

/// <summary>1セレモニーを端から端まで駆動した結果。</summary>
public sealed record FlowResult(
    CeremonyResult Result,        // success / PrimaryToken / Values / 生の finish レスポンス(②由来)
    byte[] CredentialId,          // 行使した資格情報(登録:新規/認証:署名したもの)
    JsonNode BeginResponse,       // 生の begin JSON(アサーション/デバッグ用)
    EnvelopeDebugInfo? Debug);    // EncodeFinish 段階の codec.LastDebug
```

補足。

- `CredentialId` を表に出すのは、登録が現状これを別途返しており(`attestation.CredentialId`)、呼び出し側が
  必要とするため。②単体では `CeremonyResult` に入らない。
- `userVerification` は任意オプション。`null`(既定)なら begin ボディに手を加えず、値を渡した時だけ
  ランナーが begin ボディへ `["userVerification"] = value` を**マージ**してから送る(DemoClient の `--uv` フラグ相当を
  呼び出し側で組み立てずに済ませる)。フィールド名は WebAuthn 標準の `userVerification` に合わせる。別名のサービスは
  この引数を使わず `beginBody` に直接書く。登録側で必要なら `RegisterAsync` の `beginBody` に同様に書く。
- `configureRequest` は唯一の拡張フック(呼び出しごとのヘッダ/クエリ)。任意なので通常呼び出しは1行のまま。
  begin と finish の**両リクエスト**に適用される。
- HttpClient の設定ノブは新設しない。ベースアドレス・タイムアウト・cookie・既定ヘッダ・認証は**注入された**
  client のプロパティ。これが継続性の正しさとランナーの薄さを両立させる。

### 呼び出しの形(DemoClient の手書きフローを置換)

```csharp
var runner = new WebAuthnFlowRunner(http, kit);   // 必要なら http は既にログイン済み

var reg = await runner.RegisterAsync("fido2-demo", device,
    "/attestation/options", "/attestation/result",
    new JsonObject { ["username"] = user });

var auth = await runner.AuthenticateAsync("fido2-demo", device,
    "/assertion/options", "/assertion/result",
    new JsonObject { ["username"] = user },
    userVerification: "required");             // 任意。省略時は begin ボディそのまま

// 呼び出し側の責務は不変: signCount 永続化の device.Export()、トークン利用、Assert.True(auth.Result.Success)
```

---

## 3. 内部シーケンス

`RegisterAsync`(認証は assertion コーデック / `GetAssertion` による鏡像。`userVerification` 引数を渡した場合は
ステップ2の前に `beginBody` へマージする):

1. `codec = kit.Registration(service)` — fail-fast のディスクリプタ検証(②のまま)
2. `begin = POST beginPath, beginBody` → JSON パース  *(ステップ: `Begin`)*
3. `decoded = codec.DecodeOptions(begin)`  *(`DecodeOptions`)*
4. `att = device.MakeCredential(decoded.Options)`  *(`Sign`)*
5. `body = codec.EncodeFinish(att, decoded.Context)`、`codec.LastDebug` を捕捉  *(`EncodeFinish`)*
6. `finish = POST finishPath, body` → JSON パース  *(`Finish`)*
7. `result = codec.DecodeResult(finish)`  *(`DecodeResult`)*
8. `FlowResult(result, att.CredentialId, begin, codec.LastDebug)` を返す

共通の `POST` ヘルパ(DemoClient のものを踏襲)は `configureRequest` を適用し、注入された client で送信、
非成功ステータスならステップタグ・パス・ステータスコード・レスポンスボディ付きで `WebAuthnFlowException` を投げる。

---

## 4. エラーと診断 — 本当の付加価値

**どのステップ**で失敗したかを示し、散らばりがちなコーデック診断を載せる型付き例外:

```csharp
public sealed class WebAuthnFlowException : Exception
{
    public FlowStep Step { get; }            // Begin | DecodeOptions | Sign | EncodeFinish | Finish | DecodeResult
    public string Service { get; }
    public EnvelopeDebugInfo? Debug { get; } // EncodeFinish 失敗時に充填(未解決の {{template}}、rpId、origin)
}

public enum FlowStep { Begin, DecodeOptions, Sign, EncodeFinish, Finish, DecodeResult }
```

- begin/finish のHTTP非成功 → `Step = Begin|Finish`、メッセージにステータス+ボディ
- `EncodeFinish` が未解決テンプレート変数(`LastDebug.UnresolvedTemplateVariables`)を生む →
  リテラルな `{{source.x}}` を含むボディを黙ってPOSTする代わりに、`Step = EncodeFinish` と `Debug` 付きで投げる。
  最頻のディスクリプタ誤りをランナーの境界で捕える。
- `DecodeResult` の `Result.Success == false` は**投げず**に返す — 成功/失敗は呼び出し側がアサートする正当な
  テスト結果。投げるのはプロトコル/トランスポート障害のみ。

---

## 5. 実装の段取り(GOが出たら)

1. `src/WebAuthnTestKit/Flow/WebAuthnFlowRunner.cs` — ランナー + `FlowResult` + `WebAuthnFlowException`
   + `FlowStep`。他のソースは不変(②の上に純粋追加)。
2. **ユニットテスト**(`tests/WebAuthnTestKit.Tests`、`Category!=Integration`): スタブ
   `HttpMessageHandler` が定型の begin/finish JSON を返す — ネットワーク不要。検証: 正しい連結、両POSTを同一
   ハンドラが処理すること(継続性)、`configureRequest` が両方に適用、`FlowResult` 各フィールド、各 `FlowStep`
   失敗系(不正ステータス、未解決テンプレート、`Success=false` が投げず返ること)。
3. **統合テスト**(`tests/WebAuthnTestKit.IntegrationTests`、Docker): 既存の Fido2NetLib コンテナを再利用し、
   register + authenticate をそれぞれ1ランナー呼び出しで実行、サーバ側で検証。既存5テストに倣う。
4. **ドッグフード**: `samples/DemoClient` の `RegisterFlow`/`AuthFlow` をランナーに載せ替え、手書き `Post` 配線を
   削除 — ランナーがまさにそのグルーを吸収することを示す。
5. **ドキュメント**: [design.en.md](design.en.md) / [design.md](design.md) で③を「コンシューマが実装」(§6)から
   「提供、オプトイン」へ。[status.md](status.md) のロードマップと「未実装」一覧を更新。README の
   「Optional/future work」→「shipped」行とスコープ但し書きを追加。

## 6. 先送りの論点(v1ではやらない)

- 宣言的 `transport` ディスクリプタセクション(begin/finish パス + begin ボディテンプレート)— 呼び出しを
  `runner.RegisterAsync(service, device, ctx)` にできる。§1 の自然な後継。
- 「注入ハンドラを再利用」を超える cookie/CSRF ヘルパ(例: begin レスポンスのCSRFトークンを finish **ヘッダ**へ。
  現状はボディの `source.*` 持ち回りのみ)。
- 合成版 `RegisterAndAuthenticateAsync` の利便メソッド。
