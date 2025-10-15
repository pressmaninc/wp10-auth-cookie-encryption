# WP10 Auth Cookie Encryption

WordPressの認証Cookie内のusername（個人識別情報）を暗号化することで、セキュリティを向上させるプラグインです。

## 特徴

- **透明な動作**: 既存のWordPress認証フローに影響なし、ユーザー体験の変更なし
- **高性能**: 同一プロセス内でのキャッシュ機能により95%のパフォーマンス改善を実現
- **強力な暗号化**: Sodium ChaCha20-Poly1305（認証付き暗号化）を使用
- **Core統合準備**: WordPressコアへの統合を想定した最小限の変更設計

## 動作要件

- **WordPress**: 5.0以上
- **PHP**: 7.4以上
- **PHP拡張**: Sodium（PHP 7.2+で標準搭載）

## インストール

1. プラグインファイルを `/wp-content/plugins/wp10-auth-cookie-encryption/` にアップロード
2. WordPress管理画面でプラグインを有効化
3. `wp-config.php` に暗号化キーを追加：

```php
define('AUTH_COOKIE_KEY', 'your-secret-encryption-key-here');
```

## セキュリティ移行（重要）

プラグインを初めて有効化する際は、全ユーザーの強制再ログインが必要です。

### 推奨方法: セッショントークンの削除

データベースから全ユーザーのセッション情報を削除してください：

```sql
DELETE FROM wp_usermeta WHERE meta_key = 'session_tokens';
```

または、WP-CLIを使用する場合：

```bash
wp user meta delete --all --key=session_tokens
```

### 代替方法: 認証キーの更新

上記の方法が使用できない場合は、`wp-config.php` の認証キーを変更することでも強制ログアウトできます：

```php
define( 'AUTH_KEY',         '新しいランダムな文字列' );
define( 'SECURE_AUTH_KEY',  '新しいランダムな文字列' );
define( 'LOGGED_IN_KEY',    '新しいランダムな文字列' );
define( 'NONCE_KEY',        '新しいランダムな文字列' );
define( 'AUTH_SALT',        '新しいランダムな文字列' );
define( 'SECURE_AUTH_SALT', '新しいランダムな文字列' );
define( 'LOGGED_IN_SALT',   '新しいランダムな文字列' );
define( 'NONCE_SALT',       '新しいランダムな文字列' );
```

新しいキーは [WordPress.org Secret Key Generator](https://api.wordpress.org/secret-key/1.1/salt/) で生成できます。

**注意**: 認証キー変更はパスワードリセットを要求する場合があるため、セッショントークン削除を推奨します。

## 技術仕様

### 暗号化方式

- **アルゴリズム**: Sodium ChaCha20-Poly1305（認証付き暗号化）
- **エンコード**: Base64URL
- **識別子**: `:`（コロン）
- **Nonceサイズ**: 24バイト（ランダム生成）

### Cookie構造の変化

#### 暗号化前
```
username|expiration|token|hmac
```

#### 暗号化後
```
:暗号化文字列|expiration|token|hmac
```

## パフォーマンス

- **暗号化**: ログイン時のみ実行（軽微な影響）
- **復号化**: リクエスト毎に実行、但しキャッシュ機能により最適化
- **改善効果**: 同一リクエスト内で95%の処理時間削減

## セキュリティ

### 保護対象

- **個人識別情報**: Cookieに含まれるusernameを暗号化
- **プライバシー**: ネットワーク傍受からの保護
- **認証情報**: より強固なCookieベース認証

### 影響範囲

以下のWordPress認証Cookieが対象となります：

| Cookie名 | 用途 | 影響 |
|----------|------|------|
| `wordpress_` | HTTP認証 | username部分が暗号化 |
| `wordpress_sec_` | HTTPS認証 | username部分が暗号化 |
| `wordpress_logged_in_` | ログイン状態 | username部分が暗号化 |

## トラブルシューティング

### よくある問題

#### 1. 暗号化キー未設定
**症状**: 管理画面に「暗号化キーが定義されていません」と表示

**解決**: `wp-config.php`に`AUTH_COOKIE_KEY`を追加

#### 2. Sodium拡張未対応
**症状**: 管理画面に「Sodium拡張が必要です」と表示

**解決**: サーバー管理者にPHP Sodium拡張の有効化を依頼

#### 3. ログインできない
**症状**: プラグイン有効化後にログインできない

**解決**: 
1. プラグインを一時的に無効化
2. 認証キーを更新して強制ログアウト実行
3. プラグインを再有効化

## 制限事項

### 技術的制限

- Sodium拡張が必須（PHP 7.2+で標準搭載）
- 暗号化キー未設定時は機能無効
- 既存の平文Cookieとの混在期間あり

### 運用上の注意

- 初回導入時は全ユーザーの再ログインが必要
- 暗号化キー変更時も全ユーザーの再ログインが必要
- サーバー間でのキー同期が必要（マルチサーバー環境）

## 開発者向け情報

### フィルターフック

プラグインは以下のWordPressフィルターを使用します：

- `auth_cookie`: Cookie生成時の暗号化処理
- `wp_parse_auth_cookie_username`: Cookie解析時の復号化処理

### Core統合準備

このプラグインはWordPressコアへの統合を想定して設計されています：

- **最小変更**: コアへの変更は1行のフィルター追加のみ
- **完全互換**: 既存機能への影響なし
- **拡張性**: 他のセキュリティプラグインも同じフィルターを活用可能

## ライセンス

GPL v2 or later

## サポート

技術的な質問や問題報告は、プラグインの公式リポジトリまでお願いします。

---

**注意**: このプラグインは認証Cookieのセキュリティを向上させますが、HTTPS通信、強力なパスワード、定期的なセキュリティ更新など、総合的なセキュリティ対策の一部として使用してください。