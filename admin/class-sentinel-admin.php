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

		// Chart.js from CDN.
		wp_enqueue_script(
			'chartjs',
			'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js',
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
				'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
				'restUrl'  => rest_url( 'sentinel/v1/' ),
				'nonces'   => array(
					'scan'         => wp_create_nonce( 'sentinel_scan_nonce' ),
					'backup'       => wp_create_nonce( 'sentinel_backup_nonce' ),
					'restore'      => wp_create_nonce( 'sentinel_restore_nonce' ),
					'delete'       => wp_create_nonce( 'sentinel_delete_nonce' ),
					'intelligence' => wp_create_nonce( 'sentinel_intelligence_nonce' ),
					'hardening'    => wp_create_nonce( 'sentinel_hardening_nonce' ),
				),
				'i18n'     => array(
					'scanning'          => __( 'Scanning...', 'wp-sentinel-security' ),
					'scanComplete'      => __( 'Scan complete!', 'wp-sentinel-security' ),
					'scanFailed'        => __( 'Scan failed. Please try again.', 'wp-sentinel-security' ),
					'backupCreating'    => __( 'Creating backup...', 'wp-sentinel-security' ),
					'backupComplete'    => __( 'Backup created successfully!', 'wp-sentinel-security' ),
					'backupFailed'      => __( 'Backup failed. Please try again.', 'wp-sentinel-security' ),
					'confirmDelete'     => __( 'Are you sure you want to delete this backup? This action cannot be undone.', 'wp-sentinel-security' ),
					'confirmRestore'    => __( 'Are you sure you want to restore this backup? Your current data will be replaced.', 'wp-sentinel-security' ),
					'cancel'            => __( 'Cancel', 'wp-sentinel-security' ),
					'noVulnerabilities' => __( 'No vulnerabilities found.', 'wp-sentinel-security' ),
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

		$output['scan_frequency']       = in_array( $input['scan_frequency'] ?? '', array( 'hourly', 'twicedaily', 'daily', 'weekly' ), true )
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
		$backups = $this->get_backups_list();
		echo '<div class="wrap"><h1>' . esc_html__( 'Backups', 'wp-sentinel-security' ) . '</h1>';
		echo '<p>' . esc_html__( 'Backup management coming soon.', 'wp-sentinel-security' ) . '</p></div>';
	}

	/**
	 * Render reports page.
	 *
	 * @return void
	 */
	public function render_reports() {
		echo '<div class="wrap"><h1>' . esc_html__( 'Reports', 'wp-sentinel-security' ) . '</h1>';
		echo '<p>' . esc_html__( 'Report generation coming soon.', 'wp-sentinel-security' ) . '</p></div>';
	}

	/**
	 * Render alerts page.
	 *
	 * @return void
	 */
	public function render_alerts() {
		echo '<div class="wrap"><h1>' . esc_html__( 'Alerts', 'wp-sentinel-security' ) . '</h1>';
		echo '<p>' . esc_html__( 'Alert configuration coming soon.', 'wp-sentinel-security' ) . '</p></div>';
	}

	/**
	 * Render activity log page.
	 *
	 * @return void
	 */
	public function render_activity() {
		$page     = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$log_data = Sentinel_DB::get_activity_log( array(), $page, 20 );
		echo '<div class="wrap"><h1>' . esc_html__( 'Activity Log', 'wp-sentinel-security' ) . '</h1>';
		echo '<table class="wp-list-table widefat fixed striped"><thead><tr><th>' . esc_html__( 'Date', 'wp-sentinel-security' ) . '</th><th>' . esc_html__( 'Event', 'wp-sentinel-security' ) . '</th><th>' . esc_html__( 'Severity', 'wp-sentinel-security' ) . '</th><th>' . esc_html__( 'Description', 'wp-sentinel-security' ) . '</th></tr></thead><tbody>';
		if ( ! empty( $log_data['items'] ) ) {
			foreach ( $log_data['items'] as $entry ) {
				echo '<tr><td>' . esc_html( $entry->created_at ) . '</td><td>' . esc_html( $entry->event_type ) . '</td><td>' . esc_html( $entry->severity ) . '</td><td>' . esc_html( $entry->description ) . '</td></tr>';
			}
		} else {
			echo '<tr><td colspan="4">' . esc_html__( 'No activity recorded yet.', 'wp-sentinel-security' ) . '</td></tr>';
		}
		echo '</tbody></table></div>';
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
}
