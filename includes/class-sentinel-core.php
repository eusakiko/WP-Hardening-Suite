<?php
/**
 * Core plugin class.
 *
 * Manages plugin initialization, settings, dependencies, modules, and hooks.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Core
 *
 * Singleton core orchestrator for WP Sentinel Security.
 */
class Sentinel_Core {

	/**
	 * Single instance of the class.
	 *
	 * @var Sentinel_Core
	 */
	private static $instance = null;

	/**
	 * Loaded modules.
	 *
	 * @var array
	 */
	private $modules = array();

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings = array();

	/**
	 * Get singleton instance.
	 *
	 * @return Sentinel_Core
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor — use get_instance().
	 */
	private function __construct() {}

	/**
	 * Initialize the plugin.
	 *
	 * @return void
	 */
	public function init() {
		$this->load_settings();
		$this->load_dependencies();
		$this->register_modules();
		$this->init_modules();
		$this->register_hooks();
	}

	/**
	 * Load plugin settings with defaults.
	 *
	 * @return void
	 */
	private function load_settings() {
		$defaults = array(
			'scan_frequency'       => 'daily',
			'backup_before_action' => true,
			'alert_email'          => get_option( 'admin_email' ),
			'alert_channels'       => array( 'email' ),
			'scoring_method'       => 'cvss_v3',
			'log_retention_days'   => 90,
			'async_scanning'       => true,
		);

		$saved          = get_option( 'sentinel_settings', array() );
		$this->settings = wp_parse_args( $saved, $defaults );
	}

	/**
	 * Load required files.
	 *
	 * @return void
	 */
	private function load_dependencies() {
		// Utilities.
		require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-sentinel-helper.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-sentinel-cron.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-sentinel-cache.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-scoring-engine.php';

		// Database.
		require_once SENTINEL_PLUGIN_DIR . 'includes/database/class-sentinel-db.php';

		// API.
		require_once SENTINEL_PLUGIN_DIR . 'includes/api/class-vulnerability-feed.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/api/class-sentinel-rest-api.php';

		// Admin.
		if ( is_admin() ) {
			require_once SENTINEL_PLUGIN_DIR . 'admin/class-sentinel-admin.php';
		}
	}

	/**
	 * Register scanner module.
	 *
	 * @return void
	 */
	private function register_modules() {
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/scanner/class-scanner-engine.php';
		$this->modules['scanner'] = new Scanner_Engine( $this->settings );

		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/intelligence/class-intelligence-engine.php';
		$this->modules['intelligence'] = new Intelligence_Engine( $this->settings );

		// Hardening module.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-file-hardening.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-wp-config-hardening.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-user-hardening.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-database-hardening.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-api-hardening.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/hardening/class-hardening-engine.php';
		$this->modules['hardening'] = new Hardening_Engine( $this->settings );

		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-database.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-files.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/backup/class-backup-engine.php';
		$this->modules['backup'] = new Backup_Engine( $this->settings );

		// Reports module.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/reports/class-report-json-renderer.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/reports/class-report-csv-renderer.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/reports/class-report-html-renderer.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/reports/class-report-engine.php';
		$this->modules['reports'] = new Report_Engine( $this->settings );

		// Alert module.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/class-alert-email.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/class-alert-slack.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/class-alert-telegram.php';
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/alerts/class-alert-engine.php';
		$this->modules['alerts'] = new Alert_Engine( $this->settings );

		// Activity logger.
		require_once SENTINEL_PLUGIN_DIR . 'includes/modules/activity/class-activity-logger.php';
		$this->modules['activity'] = new Activity_Logger();
	}

	/**
	 * Initialize all registered modules.
	 *
	 * @return void
	 */
	private function init_modules() {
		foreach ( $this->modules as $module ) {
			if ( method_exists( $module, 'init' ) ) {
				$module->init();
			}
		}
	}

	/**
	 * Register core plugin hooks.
	 *
	 * @return void
	 */
	private function register_hooks() {
		// Cron.
		Sentinel_Cron::register();

		// REST API.
		add_action( 'rest_api_init', array( 'Sentinel_Rest_Api', 'register_routes' ) );

		// Admin.
		if ( is_admin() ) {
			$admin = new Sentinel_Admin( $this->settings );
			$admin->register();
		}
	}

	/**
	 * Get a setting value.
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	public function get_setting( $key, $default = null ) {
		return isset( $this->settings[ $key ] ) ? $this->settings[ $key ] : $default;
	}

	/**
	 * Get all settings.
	 *
	 * @return array
	 */
	public function get_settings() {
		return $this->settings;
	}
}
