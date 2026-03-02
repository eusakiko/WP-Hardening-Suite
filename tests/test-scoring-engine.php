<?php
/**
 * Tests for Scoring_Engine::get_risk_level() and get_top_recommendations().
 *
 * @package WP_Sentinel_Security
 */

require_once __DIR__ . '/bootstrap.php';

// Stub WordPress translation helpers when running outside WP.
if ( ! function_exists( '__' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function __( $text, $domain = 'default' ) {
		return $text;
	}
}

if ( ! function_exists( '_n' ) ) {
	// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound
	function _n( $single, $plural, $number, $domain = 'default' ) {
		return ( 1 === (int) $number ) ? $single : $plural;
	}
}

/**
 * Class Test_Scoring_Engine_Ux
 */
class Test_Scoring_Engine_Ux extends \PHPUnit\Framework\TestCase {

	// ── get_risk_level() ──────────────────────────────────────────────────────

	/**
	 * Score >= 70 maps to 'low' risk.
	 */
	public function test_risk_level_low() {
		$result = Scoring_Engine::get_risk_level( 70 );
		$this->assertSame( 'low', $result['level'] );
		$this->assertNotEmpty( $result['label'] );
		$this->assertNotEmpty( $result['color'] );
	}

	/**
	 * Score 50-69 maps to 'medium' risk.
	 */
	public function test_risk_level_medium() {
		$result = Scoring_Engine::get_risk_level( 55 );
		$this->assertSame( 'medium', $result['level'] );
	}

	/**
	 * Score 30-49 maps to 'high' risk.
	 */
	public function test_risk_level_high() {
		$result = Scoring_Engine::get_risk_level( 40 );
		$this->assertSame( 'high', $result['level'] );
	}

	/**
	 * Score < 30 maps to 'critical' risk.
	 */
	public function test_risk_level_critical() {
		$result = Scoring_Engine::get_risk_level( 0 );
		$this->assertSame( 'critical', $result['level'] );
	}

	/**
	 * Boundary: score exactly 50 should be 'medium'.
	 */
	public function test_risk_level_boundary_50() {
		$result = Scoring_Engine::get_risk_level( 50 );
		$this->assertSame( 'medium', $result['level'] );
	}

	/**
	 * Boundary: score exactly 30 should be 'high'.
	 */
	public function test_risk_level_boundary_30() {
		$result = Scoring_Engine::get_risk_level( 30 );
		$this->assertSame( 'high', $result['level'] );
	}

	// ── get_top_recommendations() ─────────────────────────────────────────────

	/**
	 * Returns no more than 3 recommendations.
	 */
	public function test_recommendations_capped_at_three() {
		$score = $this->make_score( 0, 0, 5, 5, 5, 0 );
		$recs  = Scoring_Engine::get_top_recommendations( $score, true );
		$this->assertLessThanOrEqual( 3, count( $recs ) );
	}

	/**
	 * When no scan exists, first recommendation should point to scanner page.
	 */
	public function test_recommendations_no_scan_first() {
		$score = $this->make_score( 100, 0, 0, 0, 0, 100 );
		$recs  = Scoring_Engine::get_top_recommendations( $score, false );
		$this->assertNotEmpty( $recs );
		$this->assertSame( 'sentinel-scanner', $recs[0]['page'] );
	}

	/**
	 * Critical vuln present → scanner recommendation included.
	 */
	public function test_recommendations_critical_vuln() {
		$score = $this->make_score( 60, 2, 0, 0, 0, 50 );
		$recs  = Scoring_Engine::get_top_recommendations( $score, true );
		$pages = array_column( $recs, 'page' );
		$this->assertContains( 'sentinel-scanner', $pages );
	}

	/**
	 * Low hardening percentage → hardening recommendation included.
	 */
	public function test_recommendations_low_hardening() {
		$score = $this->make_score( 80, 0, 0, 0, 0, 20 );
		$recs  = Scoring_Engine::get_top_recommendations( $score, true );
		$pages = array_column( $recs, 'page' );
		$this->assertContains( 'sentinel-hardening', $pages );
	}

	/**
	 * Each recommendation must have non-empty text, page, and cta keys.
	 */
	public function test_recommendations_structure() {
		$score = $this->make_score( 50, 1, 1, 1, 0, 40 );
		$recs  = Scoring_Engine::get_top_recommendations( $score, true );
		foreach ( $recs as $rec ) {
			$this->assertArrayHasKey( 'text', $rec );
			$this->assertArrayHasKey( 'page', $rec );
			$this->assertArrayHasKey( 'cta', $rec );
			$this->assertNotEmpty( $rec['text'] );
			$this->assertNotEmpty( $rec['page'] );
			$this->assertNotEmpty( $rec['cta'] );
		}
	}

	/**
	 * When site is fully secured, still returns at least one recommendation.
	 */
	public function test_recommendations_all_clear() {
		$score = $this->make_score( 100, 0, 0, 0, 0, 100 );
		$recs  = Scoring_Engine::get_top_recommendations( $score, true );
		$this->assertNotEmpty( $recs );
	}

	// ── Helpers ───────────────────────────────────────────────────────────────

	/**
	 * Build a minimal score array compatible with get_top_recommendations().
	 *
	 * @param int $score          Numeric score.
	 * @param int $critical       Critical vuln count.
	 * @param int $high           High vuln count.
	 * @param int $medium         Medium vuln count.
	 * @param int $low            Low vuln count.
	 * @param int $hardening_pct  Hardening percentage (0-100).
	 * @return array
	 */
	private function make_score( $score, $critical, $high, $medium, $low, $hardening_pct ) {
		return array(
			'score'                => $score,
			'by_severity'          => array(
				'critical' => $critical,
				'high'     => $high,
				'medium'   => $medium,
				'low'      => $low,
				'info'     => 0,
			),
			'hardening_percentage' => $hardening_pct,
		);
	}
}
