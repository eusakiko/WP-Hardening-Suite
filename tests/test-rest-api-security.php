<?php
/**
 * Tests for REST API security hardening.
 *
 * Covers permission rejection, input validation, and enum enforcement
 * for the Sentinel_Rest_Api class.
 *
 * @package WP_Sentinel_Security
 */

require_once dirname( __DIR__ ) . '/tests/bootstrap.php';
require_once dirname( __DIR__ ) . '/includes/api/class-sentinel-rest-api.php';

// ---------------------------------------------------------------------------
// Minimal WordPress function stubs required by Sentinel_Rest_Api.
// ---------------------------------------------------------------------------

if ( ! function_exists( 'current_user_can' ) ) {
	// Default stub: deny all. Individual tests override via $GLOBALS.
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function current_user_can( $cap ) {
		return isset( $GLOBALS['_sentinel_test_user_can'] ) ? (bool) $GLOBALS['_sentinel_test_user_can'] : false;
	}
}

if ( ! function_exists( 'sanitize_key' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function sanitize_key( $key ) {
		return strtolower( preg_replace( '/[^a-z0-9_\-]/', '', $key ) );
	}
}

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

// ---------------------------------------------------------------------------
// Minimal class stubs required by Sentinel_Rest_Api.
// ---------------------------------------------------------------------------

/**
 * Minimal WP_Error stub for unit tests.
 */
if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		public $code;
		public $message;
		public $data;

		public function __construct( $code = '', $message = '', $data = '' ) {
			$this->code    = $code;
			$this->message = $message;
			$this->data    = $data;
		}

		public function get_error_code() {
			return $this->code;
		}

		public function get_error_message() {
			return $this->message;
		}

		public function get_error_data() {
			return $this->data;
		}
	}
}

/**
 * Minimal WP_REST_Response stub.
 */
if ( ! class_exists( 'WP_REST_Response' ) ) {
	class WP_REST_Response {
		public $data;
		public $status;

		public function __construct( $data = null, $status = 200 ) {
			$this->data   = $data;
			$this->status = $status;
		}

		public function get_status() {
			return $this->status;
		}

		public function get_data() {
			return $this->data;
		}
	}
}

/**
 * Minimal WP_REST_Request stub.
 */
if ( ! class_exists( 'WP_REST_Request' ) ) {
	class WP_REST_Request {
		private $params = array();

		public function set_param( $key, $value ) {
			$this->params[ $key ] = $value;
		}

		public function get_param( $key ) {
			return isset( $this->params[ $key ] ) ? $this->params[ $key ] : null;
		}
	}
}

/**
 * Class Test_Rest_Api_Security
 */
class Test_Rest_Api_Security extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		// Default to unprivileged user for each test.
		$GLOBALS['_sentinel_test_user_can'] = false;
	}

	protected function tearDown(): void {
		unset( $GLOBALS['_sentinel_test_user_can'] );
	}

	/**
	 * Test that check_permission returns WP_Error when user lacks capability.
	 */
	public function test_check_permission_returns_error_when_no_capability() {
		$GLOBALS['_sentinel_test_user_can'] = false;

		$result = Sentinel_Rest_Api::check_permission();

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'rest_forbidden', $result->get_error_code() );
		$this->assertSame( 403, $result->get_error_data()['status'] );
	}

	/**
	 * Test that check_permission returns true when user has manage_options.
	 */
	public function test_check_permission_returns_true_when_authorized() {
		$GLOBALS['_sentinel_test_user_can'] = true;

		$result = Sentinel_Rest_Api::check_permission();

		$this->assertTrue( $result );
	}

	/**
	 * Test that start_scan rejects invalid scan types.
	 */
	public function test_start_scan_rejects_invalid_type() {
		$request = new WP_REST_Request();
		$request->set_param( 'scan_type', 'malicious_type' );

		$result = Sentinel_Rest_Api::start_scan( $request );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'invalid_scan_type', $result->get_error_code() );
		$this->assertSame( 400, $result->get_error_data()['status'] );
	}

	/**
	 * Test that start_scan does NOT return an invalid_scan_type error for valid types.
	 *
	 * Note: downstream Scanner_Engine execution may fail in the test environment
	 * (no DB/WordPress), but the validation layer itself must not reject valid values.
	 */
	public function test_start_scan_does_not_reject_valid_types() {
		$valid_types = array( 'quick', 'full', 'malware', 'integrity' );

		foreach ( $valid_types as $type ) {
			$request = new WP_REST_Request();
			$request->set_param( 'scan_type', $type );

			try {
				$result = Sentinel_Rest_Api::start_scan( $request );

				if ( $result instanceof WP_Error ) {
					// A WP_Error is only acceptable if it is NOT the scan-type validation error.
					$this->assertNotSame(
						'invalid_scan_type',
						$result->get_error_code(),
						"Valid scan type '{$type}' must not be rejected by the allowlist check."
					);
				}
			} catch ( \Throwable $e ) {
				// An error from downstream (missing DB, missing class) is acceptable.
				// What matters is the scan type was not rejected by the validator.
				$this->assertStringNotContainsString(
					'Invalid scan type',
					$e->getMessage(),
					"Valid scan type '{$type}' must not trigger the Invalid scan type error."
				);
			}
		}
	}

	/**
	 * Test that update_vulnerability rejects invalid status values.
	 */
	public function test_update_vulnerability_rejects_invalid_status() {
		$request = new WP_REST_Request();
		$request->set_param( 'id', 1 );
		$request->set_param( 'status', 'hacked' );

		$result = Sentinel_Rest_Api::update_vulnerability( $request );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'invalid_status', $result->get_error_code() );
		$this->assertSame( 400, $result->get_error_data()['status'] );
	}

	/**
	 * Test that update_vulnerability rejects zero/invalid IDs.
	 */
	public function test_update_vulnerability_rejects_zero_id() {
		$request = new WP_REST_Request();
		$request->set_param( 'id', 0 );
		$request->set_param( 'status', 'fixed' );

		$result = Sentinel_Rest_Api::update_vulnerability( $request );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'invalid_id', $result->get_error_code() );
		$this->assertSame( 400, $result->get_error_data()['status'] );
	}

	/**
	 * Test that get_report rejects zero/invalid IDs.
	 */
	public function test_get_report_rejects_zero_id() {
		$request = new WP_REST_Request();
		$request->set_param( 'id', 0 );

		$result = Sentinel_Rest_Api::get_report( $request );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'invalid_id', $result->get_error_code() );
		$this->assertSame( 400, $result->get_error_data()['status'] );
	}
}
