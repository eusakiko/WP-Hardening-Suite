<?php
/**
 * Plugin Name:       WP Sentinel Security
 * Plugin URI:        https://github.com/eusakiko/WP-Hardening-Suite
 * Description:       Advanced security plugin for WordPress — Detection, analysis and vulnerability management.
 * Version:           1.0.0
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
define( 'SENTINEL_VERSION', '1.0.0' );
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
		$prefix = 'Sentinel_';
		if ( 0 !== strpos( $class, $prefix ) ) {
			return;
		}

		$file_name = 'class-' . strtolower( str_replace( '_', '-', $class ) ) . '.php';

		$locations = array(
			SENTINEL_PLUGIN_DIR . 'includes/',
			SENTINEL_PLUGIN_DIR . 'includes/database/',
			SENTINEL_PLUGIN_DIR . 'includes/utils/',
			SENTINEL_PLUGIN_DIR . 'includes/modules/scanner/',
			SENTINEL_PLUGIN_DIR . 'includes/api/',
			SENTINEL_PLUGIN_DIR . 'admin/',
		);

		foreach ( $locations as $location ) {
			$file = $location . $file_name;
			if ( file_exists( $file ) ) {
				require_once $file;
				return;
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
