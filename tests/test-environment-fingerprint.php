<?php
/**
 * Tests for Environment_Fingerprint sensitive data redaction.
 *
 * Verifies that the fingerprint output does not expose full extension lists
 * or raw server IP addresses.
 *
 * @package WP_Sentinel_Security
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';

// Stub WordPress functions used by Environment_Fingerprint.
if ( ! function_exists( 'home_url' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function home_url( $path = '' ) {
		return 'http://localhost' . $path;
	}
}

if ( ! function_exists( 'site_url' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function site_url( $path = '' ) {
		return 'http://localhost' . $path;
	}
}

if ( ! function_exists( 'is_ssl' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function is_ssl() {
		return false;
	}
}

if ( ! function_exists( 'is_multisite' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function is_multisite() {
		return false;
	}
}

if ( ! function_exists( 'get_option' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function get_option( $key, $default = false ) {
		return $default;
	}
}

if ( ! function_exists( 'wp_get_theme' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function wp_get_theme() {
		$stub = new stdClass();
		$stub->stylesheet = 'twentytwentythree';
		// Mimic get_stylesheet() as a callable.
		return new class {
			public function get_stylesheet() {
				return 'twentytwentythree';
			}
		};
	}
}

if ( ! function_exists( 'get_transient' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function get_transient( $key ) {
		return false;
	}
}

if ( ! function_exists( 'wp_remote_get' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function wp_remote_get( $url, $args = array() ) {
		return new WP_Error( 'http_error', 'Stubbed' );
	}
}

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		public function __construct( $code = '', $msg = '', $data = '' ) {}
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function sanitize_text_field( $str ) {
		return trim( strip_tags( $str ) );
	}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function wp_unslash( $value ) {
		return is_string( $value ) ? stripslashes( $value ) : $value;
	}
}

require_once SENTINEL_PLUGIN_DIR . 'includes/modules/intelligence/class-environment-fingerprint.php';

/**
 * Class Test_Environment_Fingerprint_Redaction
 */
class Test_Environment_Fingerprint_Redaction extends \PHPUnit\Framework\TestCase {

	/** @var Environment_Fingerprint */
	private $fingerprint;

	protected function setUp(): void {
		$this->fingerprint = new Environment_Fingerprint();
	}

	/**
	 * The php section must not expose the full extension list.
	 */
	public function test_php_info_does_not_expose_extension_list() {
		$data = $this->fingerprint->fingerprint();

		$this->assertArrayHasKey( 'php', $data );
		// Full extension array must be absent.
		$this->assertArrayNotHasKey( 'extensions', $data['php'], 'Full extension list must not be present in fingerprint output.' );
		// Count is acceptable as a proxy metric.
		$this->assertArrayHasKey( 'extension_count', $data['php'] );
		$this->assertIsInt( $data['php']['extension_count'] );
	}

	/**
	 * The network section must not expose the raw server IP.
	 */
	public function test_network_info_does_not_expose_server_ip() {
		$_SERVER['SERVER_ADDR'] = '10.0.0.1';

		$data = $this->fingerprint->fingerprint();

		$this->assertArrayHasKey( 'network', $data );
		$this->assertArrayNotHasKey( 'server_ip', $data['network'], 'Raw server IP must not be present in fingerprint output.' );
		// is_local flag should still be present.
		$this->assertArrayHasKey( 'is_local', $data['network'] );
	}
}
