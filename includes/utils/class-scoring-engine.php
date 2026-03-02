<?php
/**
 * Scoring Engine class.
 *
 * Calculates the overall security risk score and letter grade for the site.
 *
 * @package WP_Sentinel_Security
 * @since   1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Scoring_Engine
 */
class Scoring_Engine {

	/**
	 * Calculate the overall site security score.
	 *
	 * @return array Score data including grade, label, color, and breakdown.
	 */
	public static function calculate_site_score() {
		global $wpdb;

		// Fetch open vulnerabilities grouped by severity.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$severity_counts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT severity, COUNT(*) as cnt FROM {$wpdb->prefix}sentinel_vulnerabilities WHERE status = %s GROUP BY severity",
				'open'
			),
			OBJECT_K
		);

		$by_severity = array(
			'critical' => isset( $severity_counts['critical'] ) ? (int) $severity_counts['critical']->cnt : 0,
			'high'     => isset( $severity_counts['high'] ) ? (int) $severity_counts['high']->cnt : 0,
			'medium'   => isset( $severity_counts['medium'] ) ? (int) $severity_counts['medium']->cnt : 0,
			'low'      => isset( $severity_counts['low'] ) ? (int) $severity_counts['low']->cnt : 0,
			'info'     => isset( $severity_counts['info'] ) ? (int) $severity_counts['info']->cnt : 0,
		);

		// Calculate score penalties.
		$score = 100;
		$score -= $by_severity['critical'] * 20;
		$score -= $by_severity['high'] * 12;
		$score -= $by_severity['medium'] * 6;
		$score -= $by_severity['low'] * 2;

		// Hardening bonus.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$hardening_total = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->prefix}sentinel_hardening_status" // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$hardening_applied = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}sentinel_hardening_status WHERE status = %s",
				'pass'
			)
		);

		$hardening_ratio = $hardening_total > 0 ? $hardening_applied / $hardening_total : 0;
		$score          += (int) round( $hardening_ratio * 15 );

		// Clamp score to 0-100.
		$score = max( 0, min( 100, $score ) );

		$total_vulnerabilities = array_sum( $by_severity );
		$grade_data            = self::score_to_grade( $score );

		return array(
			'score'                  => $score,
			'grade'                  => $grade_data['grade'],
			'grade_label'            => $grade_data['label'],
			'grade_color'            => $grade_data['color'],
			'total_vulnerabilities'  => $total_vulnerabilities,
			'by_severity'            => $by_severity,
			'hardening_applied'      => $hardening_applied,
			'hardening_total'        => $hardening_total,
			'hardening_percentage'   => $hardening_total > 0 ? round( ( $hardening_applied / $hardening_total ) * 100 ) : 0,
		);
	}

	/**
	 * Convert a numeric score to a letter grade with label and color.
	 *
	 * @param int $score Numeric score (0-100).
	 * @return array {grade: string, label: string, color: string}
	 */
	public static function score_to_grade( $score ) {
		if ( $score >= 90 ) {
			return array( 'grade' => 'A+', 'label' => __( 'Excellent', 'wp-sentinel-security' ), 'color' => '#22c55e' );
		} elseif ( $score >= 80 ) {
			return array( 'grade' => 'A', 'label' => __( 'Very Good', 'wp-sentinel-security' ), 'color' => '#4ade80' );
		} elseif ( $score >= 70 ) {
			return array( 'grade' => 'B', 'label' => __( 'Good', 'wp-sentinel-security' ), 'color' => '#a3e635' );
		} elseif ( $score >= 60 ) {
			return array( 'grade' => 'C', 'label' => __( 'Fair', 'wp-sentinel-security' ), 'color' => '#facc15' );
		} elseif ( $score >= 50 ) {
			return array( 'grade' => 'D', 'label' => __( 'Poor', 'wp-sentinel-security' ), 'color' => '#fb923c' );
		} elseif ( $score >= 30 ) {
			return array( 'grade' => 'E', 'label' => __( 'Bad', 'wp-sentinel-security' ), 'color' => '#f87171' );
		} else {
			return array( 'grade' => 'F', 'label' => __( 'Critical Risk', 'wp-sentinel-security' ), 'color' => '#dc2626' );
		}
	}

	/**
	 * Get score history averaged per day over the past N days.
	 *
	 * @param int $days Number of days of history to retrieve.
	 * @return array Array of {date, avg_score} objects.
	 */
	public static function get_score_history( $days = 30 ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE(started_at) as date, AVG(risk_score) as avg_score
				FROM {$wpdb->prefix}sentinel_scans
				WHERE status = %s
				  AND started_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
				GROUP BY DATE(started_at)
				ORDER BY date ASC",
				'completed',
				absint( $days )
			)
		);
	}
}
