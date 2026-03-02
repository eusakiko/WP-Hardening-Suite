<?php
/**
 * Plugin Name:       WP Sentinel Security
 * Plugin URI:        https://github.com/eusakiko/WP-Hardening-Suite
 * Description:       Advanced security plugin for WordPress — Detection, analysis and vulnerability management.
 * Version:           2.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            WP Sentinel Security
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-sentinel-security
 * Domain Path:       /languages
 * Network:           true
 *
 * @package WP_Sentinel_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin constants.
define( 'SENTINEL_VERSION', '2.0.0' );
define( 'SENTINEL_PLUGIN_FILE', __FILE__ );
define( 'SENTINEL_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'SENTINEL_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'SENTINEL_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'SENTINEL_DB_VERSION', '1.0.0' );
define( 'SENTINEL_MIN_PHP', '7.4' );
define( 'SENTINEL_MIN_WP', '5.8' );

/**
 * Check plugin requirements before loading.
 *
 * @return bool True if requirements are met.
 */
function sentinel_check_requirements() {
	$errors = array();

	if ( version_compare( PHP_VERSION, SENTINEL_MIN_PHP, '<' ) ) {
		$errors[] = sprintf(
			/* translators: 1: Required PHP version, 2: Current PHP version */
			__( 'WP Sentinel Security requires PHP %1$s or higher. Your current PHP version is %2$s.', 'wp-sentinel-security' ),
			SENTINEL_MIN_PHP,
			PHP_VERSION
		);
	}

	global $wp_version;
	if ( version_compare( $wp_version, SENTINEL_MIN_WP, '<' ) ) {
		$errors[] = sprintf(
			/* translators: 1: Required WP version, 2: Current WP version */
			__( 'WP Sentinel Security requires WordPress %1$s or higher. Your current WordPress version is %2$s.', 'wp-sentinel-security' ),
			SENTINEL_MIN_WP,
			$wp_version
		);
	}

	if ( ! empty( $errors ) ) {
		add_action(
			'admin_notices',
			function () use ( $errors ) {
				foreach ( $errors as $error ) {
					echo '<div class="notice notice-error"><p>' . esc_html( $error ) . '</p></div>';
				}
			}
		);
		return false;
	}

	return true;
}

// Autoloader for plugin classes.
spl_autoload_register(
	function ( $class ) {
		$class_map = array(
			// Core.
			'Sentinel_Core'        => 'class-sentinel-core.php',
			'Sentinel_Activator'   => 'class-sentinel-activator.php',
			'Sentinel_Deactivator' => 'class-sentinel-deactivator.php',
			// Database.
			'Sentinel_DB'          => 'database/class-sentinel-db.php',
			// Utils.
			'Sentinel_Helper'      => 'utils/class-sentinel-helper.php',
			'Sentinel_Cron'        => 'utils/class-sentinel-cron.php',
			'Sentinel_Cache'       => 'utils/class-sentinel-cache.php',
			'Scoring_Engine'       => 'utils/class-scoring-engine.php',
			// Scanner modules.
			'Scanner_Engine'       => 'modules/scanner/class-scanner-engine.php',
			'Core_Integrity'       => 'modules/scanner/class-core-integrity.php',
			'Plugin_Vulnerability' => 'modules/scanner/class-plugin-vulnerability.php',
			'Theme_Vulnerability'  => 'modules/scanner/class-theme-vulnerability.php',
			'File_Monitor'         => 'modules/scanner/class-file-monitor.php',
			'Config_Analyzer'      => 'modules/scanner/class-config-analyzer.php',
			'Permission_Checker'   => 'modules/scanner/class-permission-checker.php',
			'Malware_Detector'     => 'modules/scanner/class-malware-detector.php',
			'User_Audit'           => 'modules/scanner/class-user-audit.php',
			// API.
			'Sentinel_Rest_Api'    => 'api/class-sentinel-rest-api.php',
			'Vulnerability_Feed'   => 'api/class-vulnerability-feed.php',
			// Firewall (WAF).
			'Firewall_Engine'      => 'modules/firewall/class-firewall-engine.php',
			'IP_Manager'           => 'modules/firewall/class-ip-manager.php',
			// Authentication.
			'Two_Factor_Auth'      => 'modules/auth/class-two-factor-auth.php',
			// Alert channels.
			'Alert_Discord'        => 'modules/alerts/class-alert-discord.php',
			'Alert_Webhook'        => 'modules/alerts/class-alert-webhook.php',
		);

		if ( isset( $class_map[ $class ] ) ) {
			$file = SENTINEL_PLUGIN_DIR . 'includes/' . $class_map[ $class ];
			if ( file_exists( $file ) ) {
				require_once $file;
			}
		}
	}
);

// Activation and deactivation hooks.
register_activation_hook( __FILE__, array( 'Sentinel_Activator', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Sentinel_Deactivator', 'deactivate' ) );

// Bootstrap plugin on plugins_loaded.
add_action(
	'plugins_loaded',
	function () {
		if ( ! sentinel_check_requirements() ) {
			return;
		}

		load_plugin_textdomain(
			'wp-sentinel-security',
			false,
			dirname( SENTINEL_PLUGIN_BASENAME ) . '/languages'
		);

		Sentinel_Core::get_instance()->init();
	}
);
