<?php
/**
 * Database helper class.
 *
 * Static helper methods for common database queries with prepared statements.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Sentinel_DB
 */
class Sentinel_DB {

	/**
	 * Get open vulnerabilities with optional filters.
	 *
	 * @param array $filters Optional filters: severity, component_type, status.
	 * @return array
	 */
	public static function get_open_vulnerabilities( $filters = array() ) {
		global $wpdb;

		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $filters['severity'] ) ) {
			$where[]  = 'severity = %s';
			$params[] = sanitize_text_field( $filters['severity'] );
		}

		if ( ! empty( $filters['component_type'] ) ) {
			$where[]  = 'component_type = %s';
			$params[] = sanitize_text_field( $filters['component_type'] );
		}

		if ( ! empty( $filters['status'] ) ) {
			$where[]  = 'status = %s';
			$params[] = sanitize_text_field( $filters['status'] );
		} else {
			$where[]  = 'status = %s';
			$params[] = 'open';
		}

		$where_clause = implode( ' AND ', $where );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE {$where_clause} ORDER BY cvss_score DESC, detected_at DESC",
				$params
			)
		);
	}

	/**
	 * Get the latest completed scan.
	 *
	 * @return object|null
	 */
	public static function get_latest_scan() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_scans WHERE status = %s ORDER BY completed_at DESC LIMIT 1",
				'completed'
			)
		);
	}

	/**
	 * Get scan history.
	 *
	 * @param int $limit Number of scans to return.
	 * @return array
	 */
	public static function get_scan_history( $limit = 20 ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_scans ORDER BY started_at DESC LIMIT %d",
				absint( $limit )
			)
		);
	}

	/**
	 * Get activity log with pagination.
	 *
	 * @param array $filters  Optional filters: severity, event_type, user_id.
	 * @param int   $page     Page number (1-based).
	 * @param int   $per_page Items per page.
	 * @return array {items: array, total: int, pages: int}
	 */
	public static function get_activity_log( $filters = array(), $page = 1, $per_page = 20 ) {
		global $wpdb;

		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $filters['severity'] ) ) {
			$where[]  = 'severity = %s';
			$params[] = sanitize_text_field( $filters['severity'] );
		}

		if ( ! empty( $filters['event_type'] ) ) {
			$where[]  = 'event_type = %s';
			$params[] = sanitize_text_field( $filters['event_type'] );
		}

		if ( ! empty( $filters['user_id'] ) ) {
			$where[]  = 'user_id = %d';
			$params[] = absint( $filters['user_id'] );
		}

		$where_clause = implode( ' AND ', $where );
		$offset       = ( max( 1, (int) $page ) - 1 ) * absint( $per_page );

		$count_params = $params;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$total = (int) $wpdb->get_var(
			// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}sentinel_activity_log WHERE {$where_clause}",
				$count_params
			)
		);

		$query_params = array_merge( $params, array( absint( $per_page ), $offset ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$items = $wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}sentinel_activity_log WHERE {$where_clause} ORDER BY created_at DESC LIMIT %d OFFSET %d",
				$query_params
			)
		);

		return array(
			'items' => $items,
			'total' => $total,
			'pages' => (int) ceil( $total / max( 1, $per_page ) ),
		);
	}

	/**
	 * Get hardening status for all checks.
	 *
	 * @return array
	 */
	public static function get_hardening_status() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}sentinel_hardening_status ORDER BY category, check_name" // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		);
	}

	/**
	 * Delete activity log entries older than a given number of days.
	 *
	 * @param int $days Retention period in days.
	 * @return int|false Number of rows deleted or false on error.
	 */
	public static function cleanup_old_logs( $days ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}sentinel_activity_log WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
				absint( $days )
			)
		);
	}
}
