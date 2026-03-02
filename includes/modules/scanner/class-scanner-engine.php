<?php
/**
 * Scanner Engine — Orchestrates all scan types.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Scanner_Engine
 */
class Scanner_Engine {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Scanner type → sub-scanner class name map.
	 *
	 * @var array
	 */
	private static $scanner_map = array(
		'full'   => array(
			'Core_Integrity',
			'Plugin_Vulnerability',
			'Theme_Vulnerability',
			'Config_Analyzer',
			'Permission_Checker',
			'File_Monitor',
			'Malware_Detector',
			'User_Audit',
			'Database_Scanner',
			'Compliance_Checker',
			'SSL_Scanner',
			'Header_Analyzer',
		),
		'quick'  => array( 'Core_Integrity', 'Plugin_Vulnerability', 'Config_Analyzer' ),
		'core'   => array( 'Core_Integrity' ),
		'plugins' => array( 'Plugin_Vulnerability' ),
		'themes' => array( 'Theme_Vulnerability' ),
		'files'  => array( 'File_Monitor', 'Permission_Checker', 'Malware_Detector' ),
		'config' => array( 'Config_Analyzer' ),
		'user_audit' => array( 'User_Audit' ),
		'database'   => array( 'Database_Scanner' ),
		'compliance' => array( 'Compliance_Checker' ),
		'ssl'        => array( 'SSL_Scanner' ),
		'headers'    => array( 'Header_Analyzer' ),
	);

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Initialise the scanner: load sub-scanners, register AJAX handlers.
	 *
	 * @return void
	 */
	public function init() {
		$scanner_dir = SENTINEL_PLUGIN_DIR . 'includes/modules/scanner/';

		$files = array(
			'class-core-integrity.php',
			'class-plugin-vulnerability.php',
			'class-theme-vulnerability.php',
			'class-config-analyzer.php',
			'class-permission-checker.php',
			'class-file-monitor.php',
			'class-malware-detector.php',
			'class-user-audit.php',
			'class-database-scanner.php',
			'class-compliance-checker.php',
			'class-ssl-scanner.php',
			'class-header-analyzer.php',
		);

		foreach ( $files as $file ) {
			require_once $scanner_dir . $file;
		}

		// AJAX handlers (logged-in users only).
		add_action( 'wp_ajax_sentinel_start_scan',    array( $this, 'ajax_start_scan' ) );
		add_action( 'wp_ajax_sentinel_scan_progress', array( $this, 'ajax_scan_progress' ) );
		add_action( 'wp_ajax_sentinel_cancel_scan',   array( $this, 'ajax_cancel_scan' ) );
	}

	// -----------------------------------------------------------------------
	// AJAX handlers
	// -----------------------------------------------------------------------

	/**
	 * AJAX: start a new scan.
	 *
	 * @return void
	 */
	public function ajax_start_scan() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$scan_type = isset( $_POST['scan_type'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_type'] ) ) : 'quick';

		if ( ! array_key_exists( $scan_type, self::$scanner_map ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid scan type.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$scan_id = $wpdb->insert(
			"{$wpdb->prefix}sentinel_scans",
			array(
				'scan_type'   => $scan_type,
				'status'      => 'pending',
				'started_at'  => current_time( 'mysql' ),
				'triggered_by' => 'manual',
			),
			array( '%s', '%s', '%s', '%s' )
		);

		if ( false === $scan_id ) {
			wp_send_json_error( array( 'message' => __( 'Failed to create scan record.', 'wp-sentinel-security' ) ) );
		}

		$scan_id = $wpdb->insert_id;

		// Schedule the actual scan as a one-time cron to run immediately.
		wp_schedule_single_event( time(), 'sentinel_run_async_scan', array( $scan_id, $scan_type ) );

		// Run synchronously if async is disabled.
		if ( empty( $this->settings['async_scanning'] ) ) {
			$this->run_scan( $scan_type, 'manual', $scan_id );
		}

		wp_send_json_success( array( 'scan_id' => $scan_id ) );
	}

	/**
	 * AJAX: get scan progress.
	 *
	 * @return void
	 */
	public function ajax_scan_progress() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$scan_id = absint( $_POST['scan_id'] ?? 0 );
		if ( ! $scan_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid scan ID.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$scan = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_scans WHERE id = %d",
				$scan_id
			)
		);

		if ( ! $scan ) {
			wp_send_json_error( array( 'message' => __( 'Scan not found.', 'wp-sentinel-security' ) ) );
		}

		// Calculate pseudo-progress based on elapsed time.
		$elapsed  = time() - strtotime( $scan->started_at );
		$progress = min( 95, $elapsed * 5 );

		if ( in_array( $scan->status, array( 'completed', 'failed', 'cancelled' ), true ) ) {
			$progress = 100;
		}

		// Fetch vulnerabilities if completed.
		$vulnerabilities = array();
		if ( 'completed' === $scan->status ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$vulnerabilities = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE scan_id = %d ORDER BY cvss_score DESC",
					$scan_id
				)
			);
		}

		wp_send_json_success(
			array(
				'status'          => $scan->status,
				'progress'        => $progress,
				'status_text'     => ucfirst( $scan->status ) . '...',
				'vulnerabilities' => $vulnerabilities,
			)
		);
	}

	/**
	 * AJAX: cancel a running scan.
	 *
	 * @return void
	 */
	public function ajax_cancel_scan() {
		check_ajax_referer( 'sentinel_scan_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$scan_id = absint( $_POST['scan_id'] ?? 0 );
		if ( ! $scan_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid scan ID.', 'wp-sentinel-security' ) ) );
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			"{$wpdb->prefix}sentinel_scans",
			array( 'status' => 'cancelled', 'completed_at' => current_time( 'mysql' ) ),
			array( 'id' => $scan_id ),
			array( '%s', '%s' ),
			array( '%d' )
		);

		wp_send_json_success();
	}

	// -----------------------------------------------------------------------
	// Core scan runner
	// -----------------------------------------------------------------------

	/**
	 * Run a scan of the given type.
	 *
	 * @param string $type         Scan type key.
	 * @param string $triggered_by How the scan was triggered (manual|cron).
	 * @param int    $scan_id      Existing scan row ID, or 0 to create one.
	 * @return int Scan row ID.
	 */
	public function run_scan( $type, $triggered_by = 'manual', $scan_id = 0 ) {
		global $wpdb;

		if ( ! $scan_id ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->insert(
				"{$wpdb->prefix}sentinel_scans",
				array(
					'scan_type'    => $type,
					'status'       => 'running',
					'started_at'   => current_time( 'mysql' ),
					'triggered_by' => $triggered_by,
				),
				array( '%s', '%s', '%s', '%s' )
			);
			$scan_id = $wpdb->insert_id;
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				"{$wpdb->prefix}sentinel_scans",
				array( 'status' => 'running' ),
				array( 'id' => $scan_id ),
				array( '%s' ),
				array( '%d' )
			);
		}

		$scanners    = self::$scanner_map[ $type ] ?? self::$scanner_map['quick'];
		$all_vulns   = array();
		$total_checks = 0;

		foreach ( $scanners as $scanner_class ) {
			if ( ! class_exists( $scanner_class ) ) {
				continue;
			}

			try {
				$scanner = new $scanner_class( $this->settings );
				$results = $scanner->scan();

				foreach ( $results as $vuln ) {
					$all_vulns[]  = $vuln;
					$total_checks++;
				}
			} catch ( Exception $e ) {
				// Log but continue scanning.
				error_log( 'WP Sentinel: Scanner error in ' . $scanner_class . ': ' . $e->getMessage() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			}
		}

		// Save vulnerabilities.
		foreach ( $all_vulns as $vuln ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->insert(
				"{$wpdb->prefix}sentinel_vulnerabilities",
				array_merge(
					$vuln,
					array(
						'scan_id'     => $scan_id,
						'detected_at' => current_time( 'mysql' ),
						'status'      => 'open',
					)
				),
				null
			);
		}

		$risk_score = $this->calculate_risk_score( $all_vulns );

		// Summarize by severity.
		$by_severity = array_count_values( array_column( $all_vulns, 'severity' ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			"{$wpdb->prefix}sentinel_scans",
			array(
				'status'               => 'completed',
				'completed_at'         => current_time( 'mysql' ),
				'total_checks'         => $total_checks,
				'vulnerabilities_found' => count( $all_vulns ),
				'risk_score'           => $risk_score,
				'summary'              => wp_json_encode( $by_severity ),
			),
			array( 'id' => $scan_id ),
			array( '%s', '%s', '%d', '%d', '%f', '%s' ),
			array( '%d' )
		);

		return $scan_id;
	}

	/**
	 * Calculate risk score based on vulnerabilities found.
	 *
	 * @param array $vulnerabilities Array of vulnerability data arrays.
	 * @return float Risk score (0-100).
	 */
	private function calculate_risk_score( $vulnerabilities ) {
		$score = 100.0;

		$penalties = array(
			'critical' => 25,
			'high'     => 15,
			'medium'   => 8,
			'low'      => 3,
		);

		foreach ( $vulnerabilities as $v ) {
			$sev   = $v['severity'] ?? 'info';
			$score -= $penalties[ $sev ] ?? 0;
		}

		return max( 0.0, min( 100.0, $score ) );
	}
}
