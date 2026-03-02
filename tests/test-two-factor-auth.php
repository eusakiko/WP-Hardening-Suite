<?php
/**
 * Tests for the Two_Factor_Auth TOTP implementation.
 *
 * Validates secret generation, TOTP code generation and verification,
 * recovery code generation, and Base32 encoding/decoding.
 *
 * @package WP_Sentinel_Security
 */

require_once __DIR__ . '/bootstrap.php';

// Stub WordPress functions used by Two_Factor_Auth.
if ( ! function_exists( 'sanitize_text_field' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function sanitize_text_field( $str ) {
		return trim( strip_tags( $str ) );
	}
}

if ( ! function_exists( '__' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function __( $text, $domain = 'default' ) {
		return $text;
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function get_bloginfo( $key = '' ) {
		return 'Test Site';
	}
}

if ( ! function_exists( 'wp_hash' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function wp_hash( $data ) {
		return hash( 'sha256', $data );
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function wp_json_encode( $data ) {
		return json_encode( $data );
	}
}

/**
 * In-memory user meta store for testing.
 */
$GLOBALS['_sentinel_test_user_meta'] = array();

if ( ! function_exists( 'get_user_meta' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function get_user_meta( $user_id, $key, $single = false ) {
		$value = $GLOBALS['_sentinel_test_user_meta'][ $user_id ][ $key ] ?? null;
		return $single ? ( $value ?? '' ) : ( $value ? array( $value ) : array() );
	}
}

if ( ! function_exists( 'update_user_meta' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function update_user_meta( $user_id, $key, $value ) {
		$GLOBALS['_sentinel_test_user_meta'][ $user_id ][ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_user_meta' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function delete_user_meta( $user_id, $key ) {
		unset( $GLOBALS['_sentinel_test_user_meta'][ $user_id ][ $key ] );
		return true;
	}
}

require_once SENTINEL_PLUGIN_DIR . 'includes/modules/auth/class-two-factor-auth.php';

/**
 * Class Test_Two_Factor_Auth
 */
class Test_Two_Factor_Auth extends \PHPUnit\Framework\TestCase {

	/** @var Two_Factor_Auth */
	private $tfa;

	protected function setUp(): void {
		$GLOBALS['_sentinel_test_user_meta'] = array();
		$this->tfa = new Two_Factor_Auth( array() );
	}

	protected function tearDown(): void {
		$GLOBALS['_sentinel_test_user_meta'] = array();
	}

	// ── Secret generation ────────────────────────────────────────────────────

	/**
	 * Generated secret should be the expected length.
	 */
	public function test_generate_secret_length() {
		$secret = $this->tfa->generate_secret( 16 );
		$this->assertSame( 16, strlen( $secret ) );
	}

	/**
	 * Generated secret should only contain Base32 characters.
	 */
	public function test_generate_secret_charset() {
		$secret = $this->tfa->generate_secret( 32 );
		$this->assertRegExp( '/^[A-Z2-7]+$/', $secret );
	}

	/**
	 * Two generated secrets should be different (randomness).
	 */
	public function test_generate_secret_uniqueness() {
		$secret1 = $this->tfa->generate_secret();
		$secret2 = $this->tfa->generate_secret();
		$this->assertNotSame( $secret1, $secret2 );
	}

	// ── TOTP code generation ─────────────────────────────────────────────────

	/**
	 * Generated code should have the expected digit length.
	 */
	public function test_get_code_length() {
		$secret = $this->tfa->generate_secret();
		$code   = $this->tfa->get_code( $secret );
		$this->assertSame( 6, strlen( $code ) );
	}

	/**
	 * Generated code should be numeric.
	 */
	public function test_get_code_numeric() {
		$secret = $this->tfa->generate_secret();
		$code   = $this->tfa->get_code( $secret );
		$this->assertRegExp( '/^\d{6}$/', $code );
	}

	/**
	 * Same secret and time should produce the same code.
	 */
	public function test_get_code_deterministic() {
		$secret = 'JBSWY3DPEHPK3PXP'; // Known test secret.
		$time   = 1234567890;

		$code1 = $this->tfa->get_code( $secret, $time );
		$code2 = $this->tfa->get_code( $secret, $time );

		$this->assertSame( $code1, $code2 );
	}

	/**
	 * Different time steps should generally produce different codes.
	 */
	public function test_get_code_varies_with_time() {
		$secret = 'JBSWY3DPEHPK3PXP';

		$code1 = $this->tfa->get_code( $secret, 1000000 );
		$code2 = $this->tfa->get_code( $secret, 2000000 );

		$this->assertNotSame( $code1, $code2 );
	}

	// ── TOTP code verification ───────────────────────────────────────────────

	/**
	 * Code generated for the current time should verify successfully.
	 */
	public function test_verify_code_current_time() {
		$secret = $this->tfa->generate_secret();
		$code   = $this->tfa->get_code( $secret );

		$this->assertTrue( $this->tfa->verify_code( $secret, $code ) );
	}

	/**
	 * Wrong code should fail verification.
	 */
	public function test_verify_code_wrong_code() {
		$secret = $this->tfa->generate_secret();
		$this->assertFalse( $this->tfa->verify_code( $secret, '000000' ) );
	}

	/**
	 * Code with wrong length should fail verification.
	 */
	public function test_verify_code_wrong_length() {
		$secret = $this->tfa->generate_secret();
		$this->assertFalse( $this->tfa->verify_code( $secret, '12345' ) );
	}

	/**
	 * Code within window tolerance should verify successfully.
	 */
	public function test_verify_code_window_tolerance() {
		$secret = $this->tfa->generate_secret();
		$now    = time();

		// Generate code for one period in the past.
		$past_code = $this->tfa->get_code( $secret, $now - 30 );

		// Should still verify with window=1.
		$this->assertTrue( $this->tfa->verify_code( $secret, $past_code, 1 ) );
	}

	// ── Recovery codes ───────────────────────────────────────────────────────

	/**
	 * Should generate the expected number of recovery codes.
	 */
	public function test_generate_recovery_codes_count() {
		$codes = $this->tfa->generate_recovery_codes( 8 );
		$this->assertCount( 8, $codes );
	}

	/**
	 * Recovery codes should be uppercase hex strings.
	 */
	public function test_generate_recovery_codes_format() {
		$codes = $this->tfa->generate_recovery_codes( 4 );
		foreach ( $codes as $code ) {
			$this->assertRegExp( '/^[0-9A-F]+$/', $code );
		}
	}

	/**
	 * Recovery codes should be unique.
	 */
	public function test_generate_recovery_codes_unique() {
		$codes = $this->tfa->generate_recovery_codes( 100 );
		$this->assertCount( 100, array_unique( $codes ) );
	}

	// ── User enable / disable ────────────────────────────────────────────────

	/**
	 * Enabling 2FA for a user should store the secret and mark as enabled.
	 */
	public function test_enable_for_user() {
		$secret         = $this->tfa->generate_secret();
		$recovery_codes = $this->tfa->enable_for_user( 1, $secret );

		$this->assertTrue( $this->tfa->is_enabled_for_user( 1 ) );
		$this->assertNotEmpty( $recovery_codes );
	}

	/**
	 * Disabling 2FA for a user should clear all metadata.
	 */
	public function test_disable_for_user() {
		$secret = $this->tfa->generate_secret();
		$this->tfa->enable_for_user( 1, $secret );
		$this->tfa->disable_for_user( 1 );

		$this->assertFalse( $this->tfa->is_enabled_for_user( 1 ) );
	}

	/**
	 * User without 2FA configured should report as disabled.
	 */
	public function test_not_enabled_by_default() {
		$this->assertFalse( $this->tfa->is_enabled_for_user( 999 ) );
	}

	// ── Provisioning URI ─────────────────────────────────────────────────────

	/**
	 * Provisioning URI should follow the otpauth:// format.
	 */
	public function test_provisioning_uri_format() {
		$secret = 'JBSWY3DPEHPK3PXP';
		$uri    = $this->tfa->get_provisioning_uri( $secret, 'user@example.com' );

		$this->assertStringStartsWith( 'otpauth://totp/', $uri );
		$this->assertStringContainsString( 'secret=JBSWY3DPEHPK3PXP', $uri );
		$this->assertStringContainsString( 'digits=6', $uri );
		$this->assertStringContainsString( 'period=30', $uri );
	}
}
