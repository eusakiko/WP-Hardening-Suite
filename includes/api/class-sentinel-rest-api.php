<?php
/**
 * REST API endpoints for WP Sentinel Security.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Rest_Api
 */
class Sentinel_Rest_Api {

	/**
	 * API namespace.
	 *
	 * @var string
	 */
	const NAMESPACE = 'sentinel/v1';

	/**
	 * Register REST API routes.
	 *
	 * @return void
	 */
	public static function register_routes() {
		$permission = array( __CLASS__, 'check_permission' );

		register_rest_route(
			self::NAMESPACE,
			'/status',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_status' ),
				'permission_callback' => $permission,
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/scans',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_scans' ),
				'permission_callback' => $permission,
				'args'                => array(
					'page'     => array( 'type' => 'integer', 'default' => 1 ),
					'per_page' => array( 'type' => 'integer', 'default' => 20 ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/scan',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'start_scan' ),
				'permission_callback' => $permission,
				'args'                => array(
					'scan_type' => array( 'type' => 'string', 'default' => 'quick' ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/vulnerabilities',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( __CLASS__, 'get_vulnerabilities' ),
				'permission_callback' => $permission,
				'args'                => array(
					'severity'       => array( 'type' => 'string' ),
					'component_type' => array( 'type' => 'string' ),
					'status'         => array( 'type' => 'string' ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE,
			'/vulnerabilities/(?P<id>\d+)',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( __CLASS__, 'update_vulnerability' ),
				'permission_callback' => $permission,
				'args'                => array(
					'id'     => array( 'type' => 'integer', 'required' => true ),
					'status' => array(
						'type'    => 'string',
						'enum'    => array( 'open', 'fixed', 'ignored', 'false_positive' ),
						'required' => true,
					),
				),
			)
		);
	}

	/**
	 * Permission check: must have manage_options capability.
	 *
	 * @return bool|WP_Error
	 */
	public static function check_permission() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error(
				'rest_forbidden',
				__( 'You do not have permission to access this endpoint.', 'wp-sentinel-security' ),
				array( 'status' => 403 )
			);
		}
		return true;
	}

	/**
	 * GET /sentinel/v1/status — Overall security status.
	 *
	 * @return WP_REST_Response
	 */
	public static function get_status() {
		$score     = Scoring_Engine::calculate_site_score();
		$last_scan = Sentinel_DB::get_latest_scan();

		return new WP_REST_Response(
			array(
				'score'          => $score,
				'last_scan'      => $last_scan,
				'server_info'    => Sentinel_Helper::get_server_info(),
			),
			200
		);
	}

	/**
	 * GET /sentinel/v1/scans — Paginated scan history.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public static function get_scans( $request ) {
		$limit  = absint( $request->get_param( 'per_page' ) ) ?: 20;
		$scans  = Sentinel_DB::get_scan_history( $limit );

		return new WP_REST_Response( $scans, 200 );
	}

	/**
	 * POST /sentinel/v1/scan — Start a new scan.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function start_scan( $request ) {
		$scan_type = sanitize_text_field( $request->get_param( 'scan_type' ) ?: 'quick' );

		if ( ! class_exists( 'Scanner_Engine' ) ) {
			require_once SENTINEL_PLUGIN_DIR . 'includes/modules/scanner/class-scanner-engine.php';
		}

		$settings = get_option( 'sentinel_settings', array() );
		$engine   = new Scanner_Engine( $settings );
		$engine->init();

		$scan_id = $engine->run_scan( $scan_type, 'rest_api' );

		return new WP_REST_Response( array( 'scan_id' => $scan_id ), 201 );
	}

	/**
	 * GET /sentinel/v1/vulnerabilities — List vulnerabilities with optional filters.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response
	 */
	public static function get_vulnerabilities( $request ) {
		$filters = array();

		foreach ( array( 'severity', 'component_type', 'status' ) as $param ) {
			$value = $request->get_param( $param );
			if ( $value ) {
				$filters[ $param ] = sanitize_text_field( $value );
			}
		}

		$vulns = Sentinel_DB::get_open_vulnerabilities( $filters );

		return new WP_REST_Response( $vulns, 200 );
	}

	/**
	 * PUT /sentinel/v1/vulnerabilities/{id} — Update vulnerability status.
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function update_vulnerability( $request ) {
		global $wpdb;

		$id     = absint( $request->get_param( 'id' ) );
		$status = sanitize_text_field( $request->get_param( 'status' ) );

		if ( ! $id ) {
			return new WP_Error( 'invalid_id', __( 'Invalid vulnerability ID.', 'wp-sentinel-security' ), array( 'status' => 400 ) );
		}

		$update_data = array( 'status' => $status );
		$update_formats = array( '%s' );

		if ( in_array( $status, array( 'fixed', 'ignored', 'false_positive' ), true ) ) {
			$update_data['resolved_at'] = current_time( 'mysql' );
			$update_formats[]           = '%s';
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$updated = $wpdb->update(
			"{$wpdb->prefix}sentinel_vulnerabilities",
			$update_data,
			array( 'id' => $id ),
			$update_formats,
			array( '%d' )
		);

		if ( false === $updated ) {
			return new WP_Error( 'update_failed', __( 'Failed to update vulnerability.', 'wp-sentinel-security' ), array( 'status' => 500 ) );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$vuln = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE id = %d",
				$id
			)
		);

		return new WP_REST_Response( $vuln, 200 );
	}
}
