<?php
/**
 * WordPressプラガブル関数のオーバーライド
 *
 * @package WP10_Auth_Cookie_Encryption
 * @since 1.0.0
 */

// 直接アクセスを防ぐ.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// WordPressプラガブル関数のオーバーライド
// wp_parse_auth_cookie()が未定義の場合のみ、このカスタム実装を使用
if ( ! function_exists( 'wp_parse_auth_cookie' ) ) {
	/**
	 * Parse a cookie into its components
	 *
	 * WordPressコアのwp_parse_auth_cookie関数に暗号化処理を追加した実装。
	 * コロン（:）で始まるusernameを暗号化されたものとして判定し、復号処理を行う。
	 *
	 * @since 1.0.0
	 *
	 * @param string $cookie Cookie値. 空の場合は$_COOKIEから自動取得.
	 * @param string $scheme 認証スキーム ('auth', 'secure_auth', 'logged_in', または空文字).
	 * @return array|false {
	 *     Cookie情報の配列、または解析失敗時はfalse.
	 *
	 *     @type string $username   ユーザー名（復号済み）.
	 *     @type string $expiration 有効期限のタイムスタンプ.
	 *     @type string $token      セッショントークン.
	 *     @type string $hmac       HMAC値.
	 *     @type string $scheme     使用された認証スキーム.
	 * }
	 */
	function wp_parse_auth_cookie( string $cookie = '', string $scheme = '' ): array|false {
		// WordPressコアの実装をそのまま使用
		if ( empty( $cookie ) ) {
			switch ( $scheme ) {
				case 'auth':
					$cookie_name = AUTH_COOKIE;
					break;
				case 'secure_auth':
					$cookie_name = SECURE_AUTH_COOKIE;
					break;
				case 'logged_in':
					$cookie_name = LOGGED_IN_COOKIE;
					break;
				default:
					if ( is_ssl() ) {
						$cookie_name = SECURE_AUTH_COOKIE;
						$scheme      = 'secure_auth';
					} else {
						$cookie_name = AUTH_COOKIE;
						$scheme      = 'auth';
					}
			}

			if ( empty( $_COOKIE[ $cookie_name ] ) ) {
				return false;
			}
			$cookie = $_COOKIE[ $cookie_name ];
		}

		$cookie_elements = explode( '|', $cookie );
		if ( count( $cookie_elements ) !== 4 ) {
			return false;
		}

		list( $username, $expiration, $token, $hmac ) = $cookie_elements;

		// ここまでWordPressコアの実装を引用

		/**
		 * 認証Cookieのusername処理フィルター
		 * 
		 * プラグインが認証Cookieのusername部分を処理できるようにする。
		 * 暗号化、ハッシュ化、その他の変換処理に使用可能。
		 *
		 * @since 1.0.0
		 *
		 * @param string $username 元のusername
		 * @param array  $cookie_data Cookie関連データ
		 */
		$username = apply_filters( 
			'wp_parse_auth_cookie_username', 
			$username, 
			compact( 'cookie', 'scheme', 'expiration', 'token', 'hmac' ) 
		);

		// WordPressコアと同じ返り値
		return compact( 'username', 'expiration', 'token', 'hmac', 'scheme' );
	}
}
