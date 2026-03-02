<?php
/**
 * Cron management class.
 *
 * Registers custom cron schedules and connects action hooks to callbacks.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_Cron
 */
class Sentinel_Cron {

	/**
	 * Register cron schedules and action hooks.
	 *
	 * @return void
	 */
	public static function register() {
		// Add custom intervals.
		add_filter( 'cron_schedules', array( __CLASS__, 'add_cron_intervals' ) );

		// Connect cron hooks to callbacks.
		add_action( 'sentinel_scheduled_scan', array( __CLASS__, 'run_scheduled_scan' ) );
		add_action( 'sentinel_cleanup_logs', array( __CLASS__, 'run_log_cleanup' ) );
		add_action( 'sentinel_vulnerability_feed_update', array( __CLASS__, 'run_feed_update' ) );
		add_action( 'sentinel_backup_cleanup', array( __CLASS__, 'run_backup_cleanup' ) );
	}

	/**
	 * Add custom cron intervals (weekly, monthly).
	 *
	 * @param array $schedules Existing schedules.
	 * @return array Modified schedules.
	 */
	public static function add_cron_intervals( $schedules ) {
		if ( ! isset( $schedules['weekly'] ) ) {
			$schedules['weekly'] = array(
				'interval' => WEEK_IN_SECONDS,
				'display'  => __( 'Once Weekly', 'wp-sentinel-security' ),
			);
		}

		if ( ! isset( $schedules['monthly'] ) ) {
			$schedules['monthly'] = array(
				'interval' => MONTH_IN_SECONDS,
				'display'  => __( 'Once Monthly', 'wp-sentinel-security' ),
			);
		}

		return $schedules;
	}

	/**
	 * Run the scheduled security scan.
	 *
	 * @return void
	 */
	public static function run_scheduled_scan() {
		if ( class_exists( 'Scanner_Engine' ) ) {
			$engine = new Scanner_Engine( get_option( 'sentinel_settings', array() ) );
			$engine->init();
			$engine->run_scan( 'quick', 'cron' );
		}
	}

	/**
	 * Run log cleanup.
	 *
	 * @return void
	 */
	public static function run_log_cleanup() {
		$settings = get_option( 'sentinel_settings', array() );
		$days     = isset( $settings['log_retention_days'] ) ? absint( $settings['log_retention_days'] ) : 90;
		Sentinel_DB::cleanup_old_logs( $days );
	}

	/**
	 * Update the vulnerability feed cache.
	 *
	 * @return void
	 */
	public static function run_feed_update() {
		Sentinel_Cache::flush_all();
	}

	/**
	 * Clean up expired backups.
	 *
	 * @return void
	 */
	public static function run_backup_cleanup() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$expired = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_backups WHERE expires_at < %s AND status = %s",
				current_time( 'mysql' ),
				'completed'
			)
		);

		foreach ( $expired as $backup ) {
			if ( file_exists( $backup->file_path ) ) {
				unlink( $backup->file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				"{$wpdb->prefix}sentinel_backups",
				array( 'status' => 'deleted' ),
				array( 'id' => $backup->id ),
				array( '%s' ),
				array( '%d' )
			);
		}
	}
}
