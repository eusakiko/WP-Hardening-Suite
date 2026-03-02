<?php
/**
 * Tests for the Firewall_Engine WAF rule matching.
 *
 * Validates that the WAF correctly detects SQL injection, XSS, LFI/RFI,
 * command injection, and protocol-abuse patterns, while allowing
 * legitimate input through.
 *
 * @package WP_Sentinel_Security
 */

require_once __DIR__ . '/bootstrap.php';

// Stub WordPress functions used by Firewall_Engine.
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

if ( ! function_exists( 'esc_url_raw' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function esc_url_raw( $url ) {
		return filter_var( $url, FILTER_SANITIZE_URL );
	}
}

if ( ! function_exists( 'get_option' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function get_option( $key, $default = false ) {
		return $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function update_option( $key, $value ) {
		return true;
	}
}

require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-ip-manager.php';
require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-firewall-engine.php';

/**
 * Class Test_Firewall_Engine
 */
class Test_Firewall_Engine extends \PHPUnit\Framework\TestCase {

	/** @var Firewall_Engine */
	private $engine;

	protected function setUp(): void {
		$this->engine = new Firewall_Engine( array() );
	}

	// ── SQL Injection ────────────────────────────────────────────────────────

	/**
	 * UNION SELECT injection should be detected.
	 */
	public function test_detects_union_select_sqli() {
		$match = $this->engine->match_rules( "1' UNION SELECT username, password FROM users--" );
		$this->assertNotNull( $match );
		$this->assertSame( 'sqli-union', $match['id'] );
	}

	/**
	 * OR 1=1 tautology injection should be detected.
	 */
	public function test_detects_tautology_sqli() {
		$match = $this->engine->match_rules( "admin' OR 1=1" );
		$this->assertNotNull( $match );
		$this->assertSame( 'sqli-tautology', $match['id'] );
	}

	/**
	 * SLEEP-based blind injection should be detected.
	 */
	public function test_detects_sleep_sqli() {
		$match = $this->engine->match_rules( "1 AND SLEEP(5)" );
		$this->assertNotNull( $match );
		$this->assertSame( 'sqli-sleep', $match['id'] );
	}

	/**
	 * Stacked query with DROP should be detected.
	 */
	public function test_detects_stacked_query_sqli() {
		$match = $this->engine->match_rules( "1; DROP TABLE users" );
		$this->assertNotNull( $match );
		$this->assertSame( 'sqli-stacked', $match['id'] );
	}

	// ── XSS ──────────────────────────────────────────────────────────────────

	/**
	 * Script tag injection should be detected.
	 */
	public function test_detects_script_tag_xss() {
		$match = $this->engine->match_rules( '<script>alert("xss")</script>' );
		$this->assertNotNull( $match );
		$this->assertSame( 'xss-script-tag', $match['id'] );
	}

	/**
	 * Inline event handler injection should be detected.
	 */
	public function test_detects_event_handler_xss() {
		$match = $this->engine->match_rules( '" onerror="alert(1)"' );
		$this->assertNotNull( $match );
		$this->assertSame( 'xss-event-handler', $match['id'] );
	}

	/**
	 * javascript: URI scheme should be detected.
	 */
	public function test_detects_javascript_uri_xss() {
		$match = $this->engine->match_rules( 'javascript:alert(document.cookie)' );
		$this->assertNotNull( $match );
		$this->assertSame( 'xss-javascript-uri', $match['id'] );
	}

	// ── LFI / RFI ────────────────────────────────────────────────────────────

	/**
	 * Directory traversal should be detected.
	 */
	public function test_detects_directory_traversal() {
		$match = $this->engine->match_rules( '../../../etc/passwd' );
		$this->assertNotNull( $match );
		$this->assertSame( 'lfi-traversal', $match['id'] );
	}

	/**
	 * Access to /etc/passwd should be detected.
	 */
	public function test_detects_etc_passwd_access() {
		$match = $this->engine->match_rules( '/etc/passwd' );
		$this->assertNotNull( $match );
		$this->assertSame( 'lfi-etc-passwd', $match['id'] );
	}

	// ── Command injection ────────────────────────────────────────────────────

	/**
	 * Piped command should be detected.
	 */
	public function test_detects_piped_command() {
		$match = $this->engine->match_rules( '| whoami' );
		$this->assertNotNull( $match );
		$this->assertSame( 'cmdi-pipe', $match['id'] );
	}

	// ── Protocol attacks ─────────────────────────────────────────────────────

	/**
	 * Null byte injection should be detected.
	 */
	public function test_detects_null_byte() {
		$match = $this->engine->match_rules( 'file.php%00.jpg' );
		$this->assertNotNull( $match );
		$this->assertSame( 'proto-null-byte', $match['id'] );
	}

	/**
	 * PHP wrapper abuse should be detected.
	 */
	public function test_detects_php_wrapper() {
		$match = $this->engine->match_rules( 'php://input' );
		$this->assertNotNull( $match );
		$this->assertSame( 'proto-php-wrapper', $match['id'] );
	}

	// ── Legitimate input ─────────────────────────────────────────────────────

	/**
	 * Normal text should not trigger any rules.
	 */
	public function test_allows_normal_text() {
		$match = $this->engine->match_rules( 'Hello, this is a normal search query about SQL tutorials.' );
		$this->assertNull( $match );
	}

	/**
	 * Normal URL should not trigger any rules.
	 */
	public function test_allows_normal_url() {
		$match = $this->engine->match_rules( '/wp-admin/post.php?post=123&action=edit' );
		$this->assertNull( $match );
	}

	/**
	 * Empty string should not trigger any rules.
	 */
	public function test_allows_empty_string() {
		$match = $this->engine->match_rules( '' );
		$this->assertNull( $match );
	}

	/**
	 * Non-string input should not trigger any rules.
	 */
	public function test_allows_non_string() {
		$match = $this->engine->match_rules( null );
		$this->assertNull( $match );
	}

	// ── Rules structure ──────────────────────────────────────────────────────

	/**
	 * All rules must have required keys.
	 */
	public function test_rules_have_required_keys() {
		$rules = Firewall_Engine::get_rules();
		$this->assertNotEmpty( $rules );

		foreach ( $rules as $rule ) {
			$this->assertArrayHasKey( 'id', $rule );
			$this->assertArrayHasKey( 'pattern', $rule );
			$this->assertArrayHasKey( 'description', $rule );
			$this->assertArrayHasKey( 'severity', $rule );
			$this->assertNotEmpty( $rule['id'] );
			$this->assertNotEmpty( $rule['pattern'] );
		}
	}
}
