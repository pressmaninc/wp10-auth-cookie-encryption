<?php
/**
 * Plugin Name: WP10 Auth Cookie Encryption
 * Plugin URI: https://github.com/yourusername/wp10-auth-cookie-encryption
 * Description: WordPressの認証CookieからPII（個人識別情報）を除去し、セキュリティを向上させるプラグインです。
 * Version: 1.0.0
 * Author: pressman HS
 * Author URI: https://yourwebsite.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 5.0
 * Tested up to: 6.4
 * Requires PHP: 7.4
 * Text Domain: wp10-auth-cookie-encryption
 * Package: WP10_Auth_Cookie_Encryption
 */

// セキュリティチェック：直接アクセスを防ぐ.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * WP10 Auth Cookie Encryption メインクラス
 */
class WP10_Auth_Cookie_Encryption {

	/**
	 * プラグインバージョン
	 */
	const VERSION = '1.0.0';

	/**
	 * Sodium暗号化のnonce長
	 */
	const SODIUM_NONCE_LENGTH = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;

	/**
	 * 暗号化Cookie識別子
	 */
	const ENCRYPTION_PREFIX = ':';

	/**
	 * ユーザー名復号
	 *
	 * コロン（:）プレフィックス付きの暗号化されたusernameを復号する。
	 * 識別子がない場合や復号に失敗した場合はfalseを返す。
	 *
	 * @since 1.0.0
	 *
	 * @param string $encrypted_data コロン（:）で始まる暗号化されたusername.
	 * @return string|false 復号されたusernameまたは復号失敗時はfalse.
	 */
	public static function decrypt_username( string $encrypted_data ): string|false {
		if ( ! defined( 'AUTH_COOKIE_KEY' ) ) {
			return false;
		}

		if ( ! function_exists( 'sodium_crypto_secretbox_open' ) ) {
			return false;
		}

		try {
			// 識別子プレフィックスを除去
			if ( 0 !== strpos( $encrypted_data, self::ENCRYPTION_PREFIX ) ) {
				return false;
			}
			
			$encrypted_data = substr( $encrypted_data, strlen( self::ENCRYPTION_PREFIX ) );
			$key = AUTH_COOKIE_KEY;
			
			// キーが32バイトでない場合はハッシュ化して調整
			if ( SODIUM_CRYPTO_SECRETBOX_KEYBYTES !== strlen( $key ) ) {
				$key = hash( 'sha256', $key, true );
			}

			// Base64URLデコード
			$encrypted_data = strtr( $encrypted_data, '-_', '+/' );
			$encrypted_data = str_pad( $encrypted_data, strlen( $encrypted_data ) % 4, '=', STR_PAD_RIGHT );
			$data = base64_decode( $encrypted_data );

			if ( false === $data ) {
				return false;
			}

			// nonce（24バイト）と暗号化データを分離
			$nonce = substr( $data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$encrypted = substr( $data, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

			// Sodium復号（認証付き復号）
			$decrypted = sodium_crypto_secretbox_open( $encrypted, $nonce, $key );

			return ( false !== $decrypted ) ? $decrypted : false;

		} catch ( Exception $e ) {
			return false;
		}
	}

	/**
	 * ユーザー名暗号化
	 *
	 * usernameを暗号化してコロン（:）プレフィックスを付加する。
	 *
	 * @since 1.0.0
	 *
	 * @param string $username 暗号化するusername.
	 * @return string|false 暗号化されたusernameまたは暗号化失敗時はfalse.
	 */
	public static function encrypt_username( string $username ): string|false {
		if ( ! defined( 'AUTH_COOKIE_KEY' ) ) {
			return false;
		}

		if ( ! function_exists( 'sodium_crypto_secretbox' ) ) {
			return false;
		}

		try {
			$key = AUTH_COOKIE_KEY;
			
			// キーが32バイトでない場合はハッシュ化して調整
			if ( SODIUM_CRYPTO_SECRETBOX_KEYBYTES !== strlen( $key ) ) {
				$key = hash( 'sha256', $key, true );
			}

			// nonceを生成
			$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

			// Sodium暗号化（認証付き暗号化）
			$encrypted = sodium_crypto_secretbox( $username, $nonce, $key );

			// nonce + 暗号化データを結合
			$data = $nonce . $encrypted;

			// Base64URLエンコード
			$encoded = base64_encode( $data );
			$encoded = strtr( $encoded, '+/', '-_' );
			$encoded = rtrim( $encoded, '=' );

			// 識別子プレフィックスを付加
			return self::ENCRYPTION_PREFIX . $encoded;

		} catch ( Exception $e ) {
			return false;
		}
	}

	/**
	 * コンストラクタ
	 */
	public function __construct() {
		// Sodium拡張の確認（システム要件）.
		if ( ! function_exists( 'sodium_crypto_secretbox' ) ) {
			add_action( 'admin_notices', [ $this, 'show_sodium_missing_notice' ] );
			return;
		}

		// 暗号化キーの存在確認（ユーザー設定）.
		if ( ! $this->is_encryption_key_defined() ) {
			add_action( 'admin_notices', [ $this, 'show_key_missing_notice' ] );
			return;
		}

		// すべての条件をクリアした場合のみフィルターを登録
		$this->register_filters();
	}

	/**
	 * フィルターの登録
	 * 
	 * すべての前提条件をクリアした場合に呼び出される。
	 */
	private function register_filters(): void {
		// auth_cookieフィルタでCookie生成時に暗号化.
		add_filter( 'auth_cookie', [ $this, 'encrypt_auth_cookie' ], 10, 5 );

		// wp_parse_auth_cookie_usernameフィルタでCookie解析時に復号化.
		add_filter( 'wp_parse_auth_cookie_username', [ $this, 'decrypt_username_with_cache' ], 10, 2 );
	}

	/**
	 * 暗号化キーが定義されているかチェック
	 */
	private function is_encryption_key_defined(): bool {
		return defined( 'AUTH_COOKIE_KEY' ) &&
			   ! empty( AUTH_COOKIE_KEY );
	}

	/**
	 * 暗号化キー未定義時の管理画面通知
	 */
	public function show_key_missing_notice(): void {
		?>
		<div class="notice notice-error">
			<p>
				<strong>WP10 Auth Cookie Encryption:</strong>
				暗号化キーが定義されていません。wp-config.phpに以下の行を追加してください：<br>
				<code>define('AUTH_COOKIE_KEY', 'your-secret-key-here');</code>
			</p>
		</div>
		<?php
	}

	/**
	 * Sodium未対応時の管理画面通知
	 */
	public function show_sodium_missing_notice(): void {
		?>
		<div class="notice notice-error">
			<p>
				<strong>WP10 Auth Cookie Encryption:</strong>
				Sodium拡張が必要です（PHP 7.2+で標準搭載）。サーバー管理者にお問い合わせください。
			</p>
		</div>
		<?php
	}

	/**
	 * 認証Cookie暗号化処理
	 *
	 * WordPressのauth_cookieフィルタで呼び出される。
	 * Cookie内のusername部分を暗号化し、識別子（:）を付加する。
	 *
	 * @since 1.0.0
	 *
	 * @param string $cookie     元のCookie値.
	 * @param int    $user_id    ユーザーID.
	 * @param int    $expiration 有効期限のタイムスタンプ.
	 * @param string $token      セッショントークン.
	 * @param string $scheme     認証スキーム.
	 * @return string 暗号化されたCookie値.
	 */
	public function encrypt_auth_cookie( string $cookie, int $user_id, int $expiration, string $token, string $scheme ): string {
		try {
			// Cookieを分解（wp_parse_auth_cookie()で既に4要素は保証済み）.
			$cookie_elements = explode( '|', $cookie );

			// username部分（最初の要素）を暗号化（識別子付き）.
			$username = $cookie_elements[0];
			$encrypted_username = self::encrypt_username( $username );

			if ( false === $encrypted_username ) {
				$this->log_error( 'Failed to encrypt username', [ 'username' => $username ] );
				return $cookie; // 暗号化に失敗した場合は元のCookieを返す.
			}

			// 暗号化されたusernameで置換.
			$cookie_elements[0] = $encrypted_username;

			// Cookieを再構築.
			$encrypted_cookie = implode( '|', $cookie_elements );

			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				$this->log_debug(
					'Cookie encrypted successfully',
					[
						'username'         => $username,
						'original_length'  => strlen( $cookie ),
						'encrypted_length' => strlen( $encrypted_cookie ),
					]
				);
			}

			return $encrypted_cookie;

		} catch ( Exception $e ) {
			$this->log_error(
				'Exception in encrypt_auth_cookie',
				[
					'message'  => $e->getMessage(),
					'username' => isset( $username ) ? $username : 'unknown',
				]
			);
			return $cookie; // エラー時は元のCookieを返す.
		}
	}

	/**
	 * 認証Cookie username復号処理（キャッシュ付き）
	 *
	 * wp_parse_auth_cookie_usernameフィルターで呼び出される。
	 * 暗号化されたusernameを復号し、キャッシュ機能で最適化する。
	 *
	 * @since 1.0.0
	 *
	 * @param string $username 元のusername（暗号化されている可能性あり）.
	 * @param array  $cookie_data Cookie関連データ.
	 * @return string 復号されたusernameまたは元のusername.
	 */
	public function decrypt_username_with_cache( string $username, array $cookie_data ): string {
		// 早期リターン: 暗号化プレフィックスがない場合は平文
		if ( 0 !== strpos( $username, self::ENCRYPTION_PREFIX ) ) {
			return $username;
		}

		// 同一プロセス内でのキャッシュ
		static $decryption_cache = [];
		
		if ( isset( $decryption_cache[ $username ] ) ) {
			// キャッシュヒット
			return $decryption_cache[ $username ];
		}

		// 復号処理
		$decrypted_username = self::decrypt_username( $username );
		if ( false !== $decrypted_username ) {
			$decryption_cache[ $username ] = $decrypted_username;
			return $decrypted_username;
		}

		// 復号失敗時は元のusernameを返す（フォールバック）
		return $username;
	}

	/**
	 * エラーログ出力
	 *
	 * @param string $message ログメッセージ.
	 * @param array  $context コンテキスト情報.
	 */
	private function log_error( string $message, array $context = [] ): void {
		$log_message = 'WP10 Auth Cookie Encryption Error: ' . $message;
		if ( ! empty( $context ) ) {
			$log_message .= ' Context: ' . wp_json_encode( $context );
		}
		error_log( $log_message );
	}

	/**
	 * デバッグログ出力
	 *
	 * @param string $message ログメッセージ.
	 * @param array  $context コンテキスト情報.
	 */
	private function log_debug( string $message, array $context = [] ): void {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$log_message = 'WP10 Auth Cookie Encryption Debug: ' . $message;
			if ( ! empty( $context ) ) {
				$log_message .= ' Context: ' . wp_json_encode( $context );
			}
			error_log( $log_message );
		}
	}

}

// インスタンス化
new WP10_Auth_Cookie_Encryption();

// プラガブル関数を読み込み
require_once __DIR__ . '/includes/pluggable.php';
