<?php
/**
 * Plugin deactivator class.
 *
 * Handles deactivation tasks such as clearing scheduled cron events.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Deactivator
 */
class Sentinel_Deactivator {

	/**
	 * Run deactivation tasks.
	 *
	 * @return void
	 */
	public static function deactivate() {
		$cron_hooks = array(
			'sentinel_scheduled_scan',
			'sentinel_cleanup_logs',
			'sentinel_vulnerability_feed_update',
			'sentinel_backup_cleanup',
		);

		foreach ( $cron_hooks as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}

		if ( class_exists( 'Sentinel_Cache' ) ) {
			Sentinel_Cache::flush_all();
		}
	}
}
