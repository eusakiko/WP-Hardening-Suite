<?php
/**
 * PHPUnit bootstrap for WP Sentinel Security tests.
 *
 * @package WP_Sentinel_Security
 */

// Define minimal WordPress constants needed for unit testing.
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'WPINC' ) ) {
	define( 'WPINC', 'wp-includes' );
}

if ( ! defined( 'SENTINEL_VERSION' ) ) {
	define( 'SENTINEL_VERSION', '1.0.0' );
}

if ( ! defined( 'SENTINEL_PLUGIN_DIR' ) ) {
	define( 'SENTINEL_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'SENTINEL_PLUGIN_URL' ) ) {
	define( 'SENTINEL_PLUGIN_URL', 'http://localhost/wp-content/plugins/wp-sentinel-security/' );
}

if ( ! defined( 'SENTINEL_PLUGIN_FILE' ) ) {
	define( 'SENTINEL_PLUGIN_FILE', SENTINEL_PLUGIN_DIR . 'wp-sentinel-security.php' );
}

if ( ! defined( 'SENTINEL_PLUGIN_BASENAME' ) ) {
	define( 'SENTINEL_PLUGIN_BASENAME', 'wp-sentinel-security/wp-sentinel-security.php' );
}

if ( ! defined( 'SENTINEL_DB_VERSION' ) ) {
	define( 'SENTINEL_DB_VERSION', '1.0.0' );
}

if ( ! defined( 'SENTINEL_MIN_PHP' ) ) {
	define( 'SENTINEL_MIN_PHP', '7.4' );
}

if ( ! defined( 'SENTINEL_MIN_WP' ) ) {
	define( 'SENTINEL_MIN_WP', '5.8' );
}

if ( ! defined( 'DAY_IN_SECONDS' ) ) {
	define( 'DAY_IN_SECONDS', 86400 );
}

if ( ! defined( 'YEAR_IN_SECONDS' ) ) {
	define( 'YEAR_IN_SECONDS', 31536000 );
}

if ( ! defined( 'WEEK_IN_SECONDS' ) ) {
	define( 'WEEK_IN_SECONDS', 604800 );
}

if ( ! defined( 'MONTH_IN_SECONDS' ) ) {
	define( 'MONTH_IN_SECONDS', 2592000 );
}

// Load utility classes for unit testing.
require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-sentinel-helper.php';
require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-sentinel-cache.php';
require_once SENTINEL_PLUGIN_DIR . 'includes/utils/class-scoring-engine.php';
