<?php
/**
 * Admin class.
 *
 * Handles menu registration, asset enqueuing, settings, and page rendering.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Admin
 */
class Sentinel_Admin {

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Register admin hooks.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_filter( 'plugin_action_links_' . SENTINEL_PLUGIN_BASENAME, array( $this, 'add_plugin_links' ) );

		// Activity log AJAX handlers.
		add_action( 'wp_ajax_sentinel_export_activity_log', array( $this, 'ajax_export_activity_log' ) );
		add_action( 'wp_ajax_sentinel_clear_old_logs',      array( $this, 'ajax_clear_old_logs' ) );

		// Backup download via admin-post.
		add_action( 'admin_post_sentinel_download_backup', array( $this, 'handle_download_backup' ) );
	}

	/**
	 * Register admin menu and submenus.
	 *
	 * @return void
	 */
	public function register_menu() {
		add_menu_page(
			__( 'Sentinel Security', 'wp-sentinel-security' ),
			__( 'Sentinel Security', 'wp-sentinel-security' ),
			'manage_options',
			'sentinel-security',
			array( $this, 'render_dashboard' ),
			'dashicons-shield-alt',
			3
		);

		$submenus = array(
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Dashboard', 'wp-sentinel-security' ),
				'menu'   => __( 'Dashboard', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-security',
				'cb'     => array( $this, 'render_dashboard' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Scanner', 'wp-sentinel-security' ),
				'menu'   => __( 'Scanner', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-scanner',
				'cb'     => array( $this, 'render_scanner' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Hardening', 'wp-sentinel-security' ),
				'menu'   => __( 'Hardening', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-hardening',
				'cb'     => array( $this, 'render_hardening' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Backups', 'wp-sentinel-security' ),
				'menu'   => __( 'Backups', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-backups',
				'cb'     => array( $this, 'render_backups' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Reports', 'wp-sentinel-security' ),
				'menu'   => __( 'Reports', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-reports',
				'cb'     => array( $this, 'render_reports' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Alerts', 'wp-sentinel-security' ),
				'menu'   => __( 'Alerts', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-alerts',
				'cb'     => array( $this, 'render_alerts' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Activity Log', 'wp-sentinel-security' ),
				'menu'   => __( 'Activity', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-activity',
				'cb'     => array( $this, 'render_activity' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Intelligence', 'wp-sentinel-security' ),
				'menu'   => __( 'Intelligence', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-intelligence',
				'cb'     => array( $this, 'render_intelligence' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Settings', 'wp-sentinel-security' ),
				'menu'   => __( 'Settings', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-settings',
				'cb'     => array( $this, 'render_settings' ),
			),
			array(
				'parent' => 'sentinel-security',
				'title'  => __( 'Setup Wizard', 'wp-sentinel-security' ),
				'menu'   => __( 'Setup Wizard', 'wp-sentinel-security' ),
				'slug'   => 'sentinel-wizard',
				'cb'     => array( $this, 'render_wizard' ),
			),
		);

		foreach ( $submenus as $submenu ) {
			add_submenu_page(
				$submenu['parent'],
				$submenu['title'],
				$submenu['menu'],
				'manage_options',
				$submenu['slug'],
				$submenu['cb']
			);
		}
	}

	/**
	 * Enqueue admin assets.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		// Only load on sentinel pages.
		if ( false === strpos( $hook, 'sentinel' ) ) {
			return;
		}

		// CSS.
		wp_enqueue_style(
			'sentinel-admin',
			SENTINEL_PLUGIN_URL . 'admin/css/sentinel-admin.css',
			array(),
			SENTINEL_VERSION
		);

		wp_enqueue_style(
			'sentinel-dashboard',
			SENTINEL_PLUGIN_URL . 'admin/css/sentinel-dashboard.css',
			array( 'sentinel-admin' ),
			SENTINEL_VERSION
		);

		// Reports CSS.
		wp_enqueue_style(
			'sentinel-reports',
			SENTINEL_PLUGIN_URL . 'admin/css/sentinel-reports.css',
			array( 'sentinel-admin' ),
			SENTINEL_VERSION
		);

		// Intelligence JS.
		wp_enqueue_script(
			'sentinel-intelligence',
			SENTINEL_PLUGIN_URL . 'admin/js/sentinel-intelligence.js',
			array( 'sentinel-admin' ),
			SENTINEL_VERSION,
			true
		);

		// Chart.js — prefer local vendor copy, fall back to CDN.
		$local_chartjs = SENTINEL_PLUGIN_DIR . 'admin/js/vendor/chart.umd.min.js';
		if ( file_exists( $local_chartjs ) ) {
			$chartjs_url = SENTINEL_PLUGIN_URL . 'admin/js/vendor/chart.umd.min.js';
		} else {
			$chartjs_url = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
		}
		wp_enqueue_script(
			'chartjs',
			$chartjs_url,
			array(),
			'4.4.0',
			true
		);

		// Plugin JS.
		wp_enqueue_script(
			'sentinel-admin',
			SENTINEL_PLUGIN_URL . 'admin/js/sentinel-admin.js',
			array( 'jquery', 'chartjs' ),
			SENTINEL_VERSION,
			true
		);

		wp_enqueue_script(
			'sentinel-scanner',
			SENTINEL_PLUGIN_URL . 'admin/js/sentinel-scanner.js',
			array( 'sentinel-admin' ),
			SENTINEL_VERSION,
			true
		);

		// Localize script data.
		wp_localize_script(
			'sentinel-admin',
			'sentinelData',
			array(
				'ajaxUrl'      => admin_url( 'admin-ajax.php' ),
				'restUrl'      => rest_url( 'sentinel/v1/' ),
				'updateUrl'    => admin_url( 'update-core.php' ),
				'hardeningUrl' => admin_url( 'admin.php?page=sentinel-hardening' ),
				'nonces'   => array(
					'scan'         => wp_create_nonce( 'sentinel_scan_nonce' ),
					'backup'       => wp_create_nonce( 'sentinel_backup_nonce' ),
					'restore'      => wp_create_nonce( 'sentinel_restore_nonce' ),
					'delete'       => wp_create_nonce( 'sentinel_delete_nonce' ),
					'intelligence' => wp_create_nonce( 'sentinel_intelligence_nonce' ),
					'hardening'    => wp_create_nonce( 'sentinel_hardening_nonce' ),
					'report'       => wp_create_nonce( 'sentinel_report_nonce' ),
					'alert'        => wp_create_nonce( 'sentinel_alert_nonce' ),
					'rest'         => wp_create_nonce( 'wp_rest' ), // BUG FIX: REST API nonce.
				),
				'i18n'     => array(
					'scanning'           => __( 'Scanning...', 'wp-sentinel-security' ),
					'scanComplete'       => __( 'Scan complete!', 'wp-sentinel-security' ),
					'scanCompleteNext'   => __( 'What to do next: review the findings below and address critical issues first.', 'wp-sentinel-security' ),
					'scanFailed'         => __( 'Scan failed. Please try again.', 'wp-sentinel-security' ),
					'backupCreating'     => __( 'Creating backup...', 'wp-sentinel-security' ),
					'backupComplete'     => __( 'Backup created successfully!', 'wp-sentinel-security' ),
					'backupCompleteNext' => __( 'What to do next: you can safely apply security changes now.', 'wp-sentinel-security' ),
					'backupFailed'       => __( 'Backup failed. Please try again.', 'wp-sentinel-security' ),
					'confirmDelete'      => __( 'Are you sure you want to delete this backup? This action cannot be undone.', 'wp-sentinel-security' ),
					'confirmRestore'     => __( 'Are you sure you want to restore this backup? Your current data will be replaced.', 'wp-sentinel-security' ),
					'cancel'             => __( 'Cancel', 'wp-sentinel-security' ),
					'noVulnerabilities'  => __( 'No vulnerabilities found.', 'wp-sentinel-security' ),
					'urgencyCritical'    => __( 'Critical (Do today)', 'wp-sentinel-security' ),
					'urgencyHigh'        => __( 'High (Within 48h)', 'wp-sentinel-security' ),
					'urgencyMedium'      => __( 'Medium (This week)', 'wp-sentinel-security' ),
					'urgencyLow'         => __( 'Low (Monitor)', 'wp-sentinel-security' ),
					'urgencyInfo'        => __( 'Info', 'wp-sentinel-security' ),
					'fixNow'             => __( 'Fix now', 'wp-sentinel-security' ),
					'viewGuide'          => __( 'View guide', 'wp-sentinel-security' ),
					'whatThisMeans'      => __( 'What this means:', 'wp-sentinel-security' ),
					'whatToDoNext'       => __( 'What to do next:', 'wp-sentinel-security' ),
					'detailsUnavailable' => __( 'Details not available.', 'wp-sentinel-security' ),
				),
				'scoreHistory' => Scoring_Engine::get_score_history( 30 ),
			)
		);
	}

	/**
	 * Register plugin settings.
	 *
	 * @return void
	 */
	public function register_settings() {
		register_setting(
			'sentinel_settings_group',
			'sentinel_settings',
			array( $this, 'sanitize_settings' )
		);
	}

	/**
	 * Sanitize settings before saving.
	 *
	 * @param array $input Raw settings input.
	 * @return array Sanitized settings.
	 */
	public function sanitize_settings( $input ) {
		$output = array();

		$output['scan_frequency']       = in_array( $input['scan_frequency'] ?? '', array( 'hourly', 'twicedaily', 'daily', 'weekly', 'monthly' ), true )
			? $input['scan_frequency']
			: 'daily';
		$output['backup_before_action'] = ! empty( $input['backup_before_action'] );
		$output['alert_email']          = sanitize_email( $input['alert_email'] ?? '' );
		$output['alert_channels']       = array_map( 'sanitize_text_field', (array) ( $input['alert_channels'] ?? array( 'email' ) ) );
		$output['scoring_method']       = 'cvss_v3';
		$output['log_retention_days']   = max( 1, absint( $input['log_retention_days'] ?? 90 ) );
		$output['async_scanning']       = ! empty( $input['async_scanning'] );
		$output['wpscan_api_key']       = sanitize_text_field( $input['wpscan_api_key'] ?? '' );
		$output['slack_webhook']        = esc_url_raw( $input['slack_webhook'] ?? '' );
		$output['telegram_bot_token']   = sanitize_text_field( $input['telegram_bot_token'] ?? '' );
		$output['telegram_chat_id']     = sanitize_text_field( $input['telegram_chat_id'] ?? '' );
		$output['company_name']         = sanitize_text_field( $input['company_name'] ?? '' );
		$output['company_logo']         = esc_url_raw( $input['company_logo'] ?? '' );

		return $output;
	}

	/**
	 * Add plugin action links.
	 *
	 * @param array $links Existing links.
	 * @return array Modified links.
	 */
	public function add_plugin_links( $links ) {
		$plugin_links = array(
			'<a href="' . esc_url( admin_url( 'admin.php?page=sentinel-security' ) ) . '">' . esc_html__( 'Dashboard', 'wp-sentinel-security' ) . '</a>',
			'<a href="' . esc_url( admin_url( 'admin.php?page=sentinel-settings' ) ) . '">' . esc_html__( 'Settings', 'wp-sentinel-security' ) . '</a>',
		);
		return array_merge( $plugin_links, $links );
	}

	// -------------------------------------------------------------------------
	// Page render methods
	// -------------------------------------------------------------------------

	/**
	 * Render dashboard page.
	 *
	 * @return void
	 */
	public function render_dashboard() {
		$score     = Scoring_Engine::calculate_site_score();
		$last_scan = $this->get_last_scan();
		$alerts    = $this->get_recent_alerts( 10 );
		require SENTINEL_PLUGIN_DIR . 'admin/views/dashboard.php';
	}

	/**
	 * Render scanner page.
	 *
	 * @return void
	 */
	public function render_scanner() {
		$scan_history = Sentinel_DB::get_scan_history( 10 );
		require SENTINEL_PLUGIN_DIR . 'admin/views/scanner.php';
	}

	/**
	 * Render hardening page.
	 *
	 * @return void
	 */
	public function render_hardening() {
		$hardening_dir = SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/';

		require_once $hardening_dir . 'class-file-hardening.php';
		require_once $hardening_dir . 'class-wp-config-hardening.php';
		require_once $hardening_dir . 'class-user-hardening.php';
		require_once $hardening_dir . 'class-database-hardening.php';
		require_once $hardening_dir . 'class-api-hardening.php';
		require_once $hardening_dir . 'class-hardening-engine.php';

		$engine = new Hardening_Engine( $this->settings );
		$engine->init();

		$checks = $engine->get_all_checks();
		$score  = $engine->get_hardening_score();

		require SENTINEL_PLUGIN_DIR . 'admin/views/hardening.php';
	}

	/**
	 * Render backups page.
	 *
	 * @return void
	 */
	public function render_backups() {
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-database.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-files.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-engine.php';
		$engine       = new Backup_Engine( $this->settings );
		$backups      = $engine->get_backups( 1, 20 );
		$storage_size = $engine->get_backup_storage_size();
		$backup_count = $backups['total'];
		$backups      = $backups['items'];
		require SENTINEL_PLUGIN_DIR . 'admin/views/backups.php';
	}

	/**
	 * Render reports page.
	 *
	 * @return void
	 */
	public function render_reports() {
		$engine       = new Report_Engine( $this->settings );
		$report_data  = $engine->get_reports( 1, 20 );
		$reports      = $report_data['items'];
		$report_count = $report_data['total'];
		require SENTINEL_PLUGIN_DIR . 'admin/views/reports.php';
	}

	/**
	 * Render alerts page.
	 *
	 * @return void
	 */
	public function render_alerts() {
		$settings   = $this->settings;
		$alert_data = Sentinel_DB::get_activity_log( array( 'event_category' => 'alert' ), 1, 20 );
		$alerts     = $alert_data['items'];
		require SENTINEL_PLUGIN_DIR . 'admin/views/alerts.php';
	}

	/**
	 * Render activity log page.
	 *
	 * @return void
	 */
	public function render_activity() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$page    = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1;
		$filters = array();

		if ( ! empty( $_GET['date_from'] ) ) {
			$filters['date_from'] = sanitize_text_field( wp_unslash( $_GET['date_from'] ) );
		}
		if ( ! empty( $_GET['date_to'] ) ) {
			$filters['date_to'] = sanitize_text_field( wp_unslash( $_GET['date_to'] ) );
		}
		if ( ! empty( $_GET['category'] ) ) {
			$filters['event_category'] = sanitize_text_field( wp_unslash( $_GET['category'] ) );
		}
		if ( ! empty( $_GET['severity'] ) ) {
			$filters['severity'] = sanitize_text_field( wp_unslash( $_GET['severity'] ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$log_data = Sentinel_DB::get_activity_log( $filters, $page, 20 );
		require SENTINEL_PLUGIN_DIR . 'admin/views/activity.php';
	}

	/**
	 * Render intelligence page.
	 *
	 * @return void
	 */
	public function render_intelligence() {
		require SENTINEL_PLUGIN_DIR . 'admin/views/intelligence.php';
	}

	/**
	 * Render settings page.
	 *
	 * @return void
	 */
	public function render_settings() {
		require SENTINEL_PLUGIN_DIR . 'admin/views/settings.php';
	}

	/**
	 * Render setup wizard page.
	 *
	 * @return void
	 */
	public function render_wizard() {
		require SENTINEL_PLUGIN_DIR . 'admin/views/wizard.php';
	}

	// -------------------------------------------------------------------------
	// Helper methods
	// -------------------------------------------------------------------------

	/**
	 * Get recent alerts from the activity log.
	 *
	 * @param int $limit Number of alerts to retrieve.
	 * @return array
	 */
	private function get_recent_alerts( $limit = 10 ) {
		$log_data = Sentinel_DB::get_activity_log(
			array( 'severity' => 'high' ),
			1,
			$limit
		);
		return $log_data['items'];
	}

	/**
	 * Get the last completed scan.
	 *
	 * @return object|null
	 */
	private function get_last_scan() {
		return Sentinel_DB::get_latest_scan();
	}

	/**
	 * Get list of backups.
	 *
	 * @return array
	 */
	private function get_backups_list() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_backups WHERE status != %s ORDER BY created_at DESC LIMIT 50",
				'deleted'
			)
		);
	}

	/**
	 * AJAX: export activity log as CSV.
	 *
	 * @return void
	 */
	public function ajax_export_activity_log() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$log_data = Sentinel_DB::get_activity_log( array(), 1, 10000 );
		$items    = $log_data['items'];

		$filename = 'sentinel-activity-log-' . gmdate( 'Y-m-d' ) . '.csv';

		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		// BOM for Excel compatibility.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo "\xEF\xBB\xBF";

		$output = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen

		fputcsv( $output, array( 'Date', 'User ID', 'Event Type', 'Category', 'Severity', 'IP Address', 'Description' ) );

		foreach ( $items as $item ) {
			fputcsv(
				$output,
				array(
					$item->created_at,
					$item->user_id,
					$item->event_type,
					$item->event_category,
					$item->severity,
					$item->ip_address,
					$item->description,
				)
			);
		}

		fclose( $output ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		exit;
	}

	/**
	 * AJAX: clear old activity log entries.
	 *
	 * @return void
	 */
	public function ajax_clear_old_logs() {
		check_ajax_referer( 'sentinel_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'wp-sentinel-security' ) ), 403 );
		}

		$retention_days = absint( $this->settings['log_retention_days'] ?? 90 );
		$deleted        = Sentinel_DB::cleanup_old_logs( $retention_days );

		if ( false === $deleted ) {
			wp_send_json_error( array( 'message' => __( 'Failed to clear logs.', 'wp-sentinel-security' ) ) );
		}

		wp_send_json_success(
			array(
				'message' => sprintf(
					/* translators: %d: number of log entries deleted */
					__( '%d log entries deleted.', 'wp-sentinel-security' ),
					(int) $deleted
				),
			)
		);
	}

	/**
	 * Admin-post handler: stream a backup file download.
	 *
	 * @return void
	 */
	public function handle_download_backup() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'wp-sentinel-security' ), 403 );
		}

		$backup_id = isset( $_GET['backup_id'] ) ? absint( $_GET['backup_id'] ) : 0;

		if ( ! $backup_id ) {
			wp_die( esc_html__( 'Invalid backup ID.', 'wp-sentinel-security' ) );
		}

		$nonce_key = 'sentinel_download_backup_' . $backup_id;
		if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), $nonce_key ) ) {
			wp_die( esc_html__( 'Security check failed.', 'wp-sentinel-security' ) );
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$backup = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_backups WHERE id = %d AND status = %s",
				$backup_id,
				'completed'
			)
		);

		if ( ! $backup || empty( $backup->file_path ) || ! file_exists( $backup->file_path ) ) {
			wp_die( esc_html__( 'Backup file not found.', 'wp-sentinel-security' ) );
		}

		$extension = strtolower( pathinfo( $backup->file_path, PATHINFO_EXTENSION ) );
		$mime      = ( 'zip' === $extension ) ? 'application/zip' : 'application/octet-stream';

		header( 'Content-Type: ' . $mime );
		header( 'Content-Disposition: attachment; filename="' . sanitize_file_name( basename( $backup->file_path ) ) . '"' );
		header( 'Content-Length: ' . filesize( $backup->file_path ) );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		readfile( $backup->file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
		exit;
	}
}
