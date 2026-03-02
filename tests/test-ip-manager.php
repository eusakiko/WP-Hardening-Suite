<?php
/**
 * Tests for the IP_Manager — IP blocking, whitelisting, and CIDR support.
 *
 * @package WP_Sentinel_Security
 */

require_once __DIR__ . '/bootstrap.php';

// Stub WordPress functions used by IP_Manager.
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

/**
 * In-memory option store for testing (no WordPress DB).
 */
$GLOBALS['_sentinel_test_options'] = array();

if ( ! function_exists( 'get_option' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function get_option( $key, $default = false ) {
		return $GLOBALS['_sentinel_test_options'][ $key ] ?? $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function update_option( $key, $value ) {
		$GLOBALS['_sentinel_test_options'][ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'absint' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function absint( $val ) {
		return abs( (int) $val );
	}
}

require_once SENTINEL_PLUGIN_DIR . 'includes/modules/firewall/class-ip-manager.php';

/**
 * Class Test_IP_Manager
 */
class Test_IP_Manager extends \PHPUnit\Framework\TestCase {

	/** @var IP_Manager */
	private $manager;

	protected function setUp(): void {
		$GLOBALS['_sentinel_test_options'] = array();
		$this->manager = new IP_Manager( array() );
	}

	protected function tearDown(): void {
		$GLOBALS['_sentinel_test_options'] = array();
	}

	// ── Validation ───────────────────────────────────────────────────────────

	/**
	 * Valid IPv4 address should pass validation.
	 */
	public function test_valid_ipv4() {
		$this->assertTrue( $this->manager->is_valid_ip_or_cidr( '192.168.1.1' ) );
	}

	/**
	 * Valid CIDR notation should pass validation.
	 */
	public function test_valid_cidr() {
		$this->assertTrue( $this->manager->is_valid_ip_or_cidr( '10.0.0.0/8' ) );
	}

	/**
	 * Valid IPv6 address should pass validation.
	 */
	public function test_valid_ipv6() {
		$this->assertTrue( $this->manager->is_valid_ip_or_cidr( '::1' ) );
	}

	/**
	 * Invalid IP should fail validation.
	 */
	public function test_invalid_ip() {
		$this->assertFalse( $this->manager->is_valid_ip_or_cidr( 'not-an-ip' ) );
	}

	/**
	 * Invalid CIDR mask should fail validation.
	 */
	public function test_invalid_cidr_mask() {
		$this->assertFalse( $this->manager->is_valid_ip_or_cidr( '10.0.0.0/33' ) );
	}

	// ── Blocking ─────────────────────────────────────────────────────────────

	/**
	 * Blocking an IP and checking is_blocked should return true.
	 */
	public function test_block_and_check_ip() {
		$this->manager->block_ip( '192.168.1.100', 'Test block' );
		$this->assertTrue( $this->manager->is_blocked( '192.168.1.100' ) );
	}

	/**
	 * Unblocked IP should not be marked as blocked.
	 */
	public function test_unblocked_ip_not_blocked() {
		$this->assertFalse( $this->manager->is_blocked( '10.0.0.1' ) );
	}

	/**
	 * Unblocking an IP should remove it from the blocked list.
	 */
	public function test_unblock_ip() {
		$this->manager->block_ip( '192.168.1.100', 'Test block' );
		$this->manager->unblock_ip( '192.168.1.100' );
		$this->assertFalse( $this->manager->is_blocked( '192.168.1.100' ) );
	}

	/**
	 * CIDR range block should match IPs within the range.
	 */
	public function test_cidr_range_block() {
		$this->manager->block_ip( '10.0.0.0/24', 'Block range' );
		$this->assertTrue( $this->manager->is_blocked( '10.0.0.50' ) );
		$this->assertTrue( $this->manager->is_blocked( '10.0.0.255' ) );
		$this->assertFalse( $this->manager->is_blocked( '10.0.1.1' ) );
	}

	// ── Whitelisting ─────────────────────────────────────────────────────────

	/**
	 * Whitelisting an IP and checking is_whitelisted should return true.
	 */
	public function test_whitelist_and_check_ip() {
		$this->manager->whitelist_ip( '192.168.1.1', 'Admin' );
		$this->assertTrue( $this->manager->is_whitelisted( '192.168.1.1' ) );
	}

	/**
	 * Removing from whitelist should make it no longer whitelisted.
	 */
	public function test_remove_whitelist() {
		$this->manager->whitelist_ip( '192.168.1.1', 'Admin' );
		$this->manager->remove_whitelist( '192.168.1.1' );
		$this->assertFalse( $this->manager->is_whitelisted( '192.168.1.1' ) );
	}

	// ── CIDR matching ────────────────────────────────────────────────────────

	/**
	 * IP within a /24 range should match.
	 */
	public function test_ip_in_cidr_24() {
		$this->assertTrue( $this->manager->ip_in_cidr( '192.168.1.100', '192.168.1.0/24' ) );
	}

	/**
	 * IP outside a /24 range should not match.
	 */
	public function test_ip_not_in_cidr_24() {
		$this->assertFalse( $this->manager->ip_in_cidr( '192.168.2.1', '192.168.1.0/24' ) );
	}

	/**
	 * IP in a /8 range should match.
	 */
	public function test_ip_in_cidr_8() {
		$this->assertTrue( $this->manager->ip_in_cidr( '10.255.255.255', '10.0.0.0/8' ) );
	}

	/**
	 * /32 range should match only the exact IP.
	 */
	public function test_ip_in_cidr_32() {
		$this->assertTrue( $this->manager->ip_in_cidr( '1.2.3.4', '1.2.3.4/32' ) );
		$this->assertFalse( $this->manager->ip_in_cidr( '1.2.3.5', '1.2.3.4/32' ) );
	}

	/**
	 * Invalid CIDR format should return false.
	 */
	public function test_invalid_cidr_format() {
		$this->assertFalse( $this->manager->ip_in_cidr( '10.0.0.1', 'not-cidr' ) );
	}

	// ── Expiry ───────────────────────────────────────────────────────────────

	/**
	 * Expired blocked IP should be automatically cleaned up.
	 */
	public function test_expired_block_cleaned() {
		$GLOBALS['_sentinel_test_options'][ IP_Manager::BLOCKED_OPTION ] = array(
			'1.2.3.4' => array(
				'reason'     => 'test',
				'blocked_at' => time() - 7200,
				'expiry'     => time() - 3600, // Expired 1 hour ago.
			),
		);

		$this->assertFalse( $this->manager->is_blocked( '1.2.3.4' ) );
	}

	/**
	 * Non-expired blocked IP should remain blocked.
	 */
	public function test_non_expired_block_remains() {
		$GLOBALS['_sentinel_test_options'][ IP_Manager::BLOCKED_OPTION ] = array(
			'1.2.3.4' => array(
				'reason'     => 'test',
				'blocked_at' => time(),
				'expiry'     => time() + 3600, // Expires in 1 hour.
			),
		);

		$this->assertTrue( $this->manager->is_blocked( '1.2.3.4' ) );
	}

	/**
	 * Blocking an invalid IP should return false.
	 */
	public function test_block_invalid_ip() {
		$this->assertFalse( $this->manager->block_ip( 'not-an-ip' ) );
	}
}
