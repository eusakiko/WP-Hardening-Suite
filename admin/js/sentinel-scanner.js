/**
 * WP Sentinel Security — Scanner-specific JS
 *
 * Handles severity filter tabs and vuln detail expand/collapse.
 *
 * @package WP_Sentinel_Security
 */
( function ( $ ) {
	'use strict';

	var SentinelScanner = {

		/**
		 * Initialise scanner page interactions.
		 */
		init: function () {
			this.bindEvents();
		},

		/**
		 * Bind UI events.
		 */
		bindEvents: function () {
			// Severity filter tabs.
			$( document ).on( 'click', '.sentinel-tab', this.filterBySeverity.bind( this ) );

			// Expand/collapse vulnerability details.
			$( document ).on( 'click', '.sentinel-vuln-details', this.toggleVulnDetails.bind( this ) );
		},

		/**
		 * Filter vulnerabilities table by severity.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		filterBySeverity: function ( e ) {
			var $tab    = $( e.currentTarget );
			var filter  = $tab.data( 'filter' );

			// Update active tab.
			$( '.sentinel-tab' ).removeClass( 'active' );
			$tab.addClass( 'active' );

			// Filter rows.
			var $rows = $( '#sentinelResultsTable tbody tr[data-severity]' );
			if ( 'all' === filter ) {
				$rows.show();
			} else {
				$rows.hide().filter( '[data-severity="' + filter + '"]' ).show();
			}
		},

		/**
		 * Toggle vulnerability detail row.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		toggleVulnDetails: function ( e ) {
			var $btn     = $( e.currentTarget );
			var $row     = $btn.closest( 'tr' );
			var $details = $row.next( '.sentinel-vuln-detail-row' );

			if ( $details.length ) {
				$details.toggle();
				return;
			}

			// Fetch details via AJAX and insert a new row.
			var vulnId = parseInt( $btn.data( 'id' ), 10 );

			$.ajax( {
				url:    window.sentinelData ? sentinelData.restUrl + 'vulnerabilities/' + vulnId : '',
				method: 'GET',
				beforeSend: function ( xhr ) {
					if ( window.sentinelData && sentinelData.nonces ) {
						xhr.setRequestHeader( 'X-WP-Nonce', sentinelData.nonces.scan );
					}
				},
				success: function ( vuln ) {
					var html = '<tr class="sentinel-vuln-detail-row">' +
						'<td colspan="5" style="background:#f9fafb;padding:16px;">' +
						'<strong>' + sentinelData.i18n.whatThisMeans + '</strong><p>' + $( '<span>' ).text( vuln.description || '' ).html() + '</p>' +
						'<strong>' + sentinelData.i18n.whatToDoNext + '</strong><p>' + $( '<span>' ).text( vuln.recommendation || '' ).html() + '</p>' +
						( vuln.cvss_vector ? '<details><summary><strong>Advanced details</strong></summary><p>' + $( '<span>' ).text( vuln.cvss_vector ).html() + '</p></details>' : '' ) +
						'</td></tr>';
					$row.after( html );
				},
				error: function () {
					var html = '<tr class="sentinel-vuln-detail-row">' +
						'<td colspan="5"><em>' + sentinelData.i18n.detailsUnavailable + '</em></td></tr>';
					$row.after( html );
				},
			} );
		},
	};

	$( function () {
		SentinelScanner.init();
	} );

} )( jQuery );
