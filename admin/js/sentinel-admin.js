/**
 * WP Sentinel Security — Main Admin JS
 *
 * @package WP_Sentinel_Security
 */
/* global sentinelData, Chart */
( function ( $ ) {
	'use strict';

	var Sentinel = {

		currentScanId:     null,
		pollInterval:      null,
		POLL_INTERVAL_MS:  3000,

		/**
		 * Initialise event bindings.
		 */
		init: function () {
			this.bindEvents();
		},

		/**
		 * Bind UI events.
		 */
		bindEvents: function () {
			$( document ).on( 'click', '.sentinel-start-scan',   this.startScan.bind( this ) );
			$( document ).on( 'click', '#sentinelCancelScan',    this.cancelScan.bind( this ) );
			$( document ).on( 'click', '.sentinel-create-backup', this.createBackup.bind( this ) );
			$( document ).on( 'click', '.sentinel-restore-backup', this.restoreBackup.bind( this ) );
			$( document ).on( 'click', '.sentinel-delete-backup',  this.deleteBackup.bind( this ) );
		},

		// ---------------------------------------------------------------
		// Scan
		// ---------------------------------------------------------------

		/**
		 * Start a new scan.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		startScan: function ( e ) {
			var $btn  = $( e.currentTarget );
			var type  = $btn.data( 'scan-type' ) || 'quick';
			var self  = this;

			$btn.prop( 'disabled', true );
			this.showProgress( 0, sentinelData.i18n.scanning );

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action:   'sentinel_start_scan',
					scan_type: type,
					nonce:    sentinelData.nonces.scan,
				},
				success: function ( response ) {
					if ( response.success && response.data.scan_id ) {
						self.currentScanId = response.data.scan_id;
						self.pollInterval  = setInterval(
							self.pollScanProgress.bind( self ),
							self.POLL_INTERVAL_MS
						);
					} else {
						self.hideProgress();
						self.showNotification( response.data.message || sentinelData.i18n.scanFailed, 'error' );
						$btn.prop( 'disabled', false );
					}
				},
				error: function () {
					self.hideProgress();
					self.showNotification( sentinelData.i18n.scanFailed, 'error' );
					$btn.prop( 'disabled', false );
				},
			} );
		},

		/**
		 * Poll scan progress every 3 seconds.
		 */
		pollScanProgress: function () {
			var self = this;

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action:  'sentinel_scan_progress',
					scan_id: self.currentScanId,
					nonce:   sentinelData.nonces.scan,
				},
				success: function ( response ) {
					if ( ! response.success ) {
						return;
					}

					var d = response.data;
					self.showProgress( d.progress || 0, d.status_text || sentinelData.i18n.scanning );

					if ( 'completed' === d.status || 'failed' === d.status || 'cancelled' === d.status ) {
						self.onScanComplete( d );
					}
				},
			} );
		},

		/**
		 * Handle scan completion.
		 *
		 * @param {Object} data Scan result data.
		 */
		onScanComplete: function ( data ) {
			clearInterval( this.pollInterval );
			this.pollInterval  = null;
			this.currentScanId = null;

			this.hideProgress();
			$( '.sentinel-start-scan' ).prop( 'disabled', false );

			if ( 'completed' === data.status ) {
				this.showNotification( sentinelData.i18n.scanComplete, 'success', sentinelData.i18n.scanCompleteNext );
				this.renderScanResults( data.vulnerabilities || [] );
				$( '#sentinel-scan-results' ).show();
			} else {
				this.showNotification( sentinelData.i18n.scanFailed, 'error' );
			}
		},

		/**
		 * Cancel the running scan.
		 */
		cancelScan: function () {
			if ( ! this.currentScanId ) {
				return;
			}

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action:  'sentinel_cancel_scan',
					scan_id: this.currentScanId,
					nonce:   sentinelData.nonces.scan,
				},
			} );

			clearInterval( this.pollInterval );
			this.pollInterval  = null;
			this.currentScanId = null;
			this.hideProgress();
		},

		/**
		 * Render vulnerability results into the results table.
		 *
		 * @param {Array} vulnerabilities Array of vulnerability objects.
		 */
		renderScanResults: function ( vulnerabilities ) {
			var $body = $( '#sentinelResultsBody' );
			$body.empty();

			if ( ! vulnerabilities.length ) {
				$body.html( '<tr><td colspan="5">' + sentinelData.i18n.noVulnerabilities + '</td></tr>' );
				return;
			}

			var urgencyMap = {
				critical: sentinelData.i18n.urgencyCritical,
				high:     sentinelData.i18n.urgencyHigh,
				medium:   sentinelData.i18n.urgencyMedium,
				low:      sentinelData.i18n.urgencyLow,
				info:     sentinelData.i18n.urgencyInfo,
			};

			$.each( vulnerabilities, function ( i, v ) {
				var sev = $( '<span>' ).text( v.severity ).html();
				var urgency = $( '<span>' ).text( urgencyMap[ v.severity ] || v.severity ).html();
				var compType = v.component_type || '';
				var ctaHtml;

				// Determine the most actionable CTA available.
				if ( 'plugin' === compType || 'theme' === compType ) {
					ctaHtml = '<a href="' + sentinelData.updateUrl + '" class="button button-small button-primary">' +
						sentinelData.i18n.fixNow + '</a> ';
				} else {
					ctaHtml = '<a href="' + sentinelData.hardeningUrl + '" class="button button-small button-primary">' +
						sentinelData.i18n.fixNow + '</a> ';
				}

				var safeId = parseInt( v.id, 10 ) || 0;
				ctaHtml += '<button class="button button-small sentinel-vuln-details" data-id="' + safeId + '">' +
					sentinelData.i18n.viewGuide + '</button>';

				var row = '<tr data-severity="' + sev + '">' +
					'<td>' +
						'<span class="sentinel-badge sentinel-badge-' + sev + '">' + sev.toUpperCase() + '</span>' +
						'<span class="sentinel-urgency-label">' + urgency + '</span>' +
					'</td>' +
					'<td>' + $( '<span>' ).text( v.component_name ).html() + ' ' + $( '<span>' ).text( v.component_version ).html() + '</td>' +
					'<td>' + $( '<span>' ).text( v.title ).html() + '</td>' +
					'<td>' + $( '<span>' ).text( v.cvss_score ).html() + '</td>' +
					'<td class="sentinel-finding-actions">' + ctaHtml + '</td>' +
					'</tr>';
				$body.append( row );
			} );
		},

		// ---------------------------------------------------------------
		// Backup
		// ---------------------------------------------------------------

		/**
		 * Create a new backup.
		 */
		createBackup: function () {
			var self = this;
			this.showNotification( sentinelData.i18n.backupCreating, 'info' );

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action: 'sentinel_create_backup',
					nonce:  sentinelData.nonces.backup,
				},
				success: function ( response ) {
					if ( response.success ) {
						self.showNotification( sentinelData.i18n.backupComplete, 'success', sentinelData.i18n.backupCompleteNext );
					} else {
						self.showNotification( response.data.message || sentinelData.i18n.backupFailed, 'error' );
					}
				},
				error: function () {
					self.showNotification( sentinelData.i18n.backupFailed, 'error' );
				},
			} );
		},

		/**
		 * Restore a backup.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		restoreBackup: function ( e ) {
			// phpcs:ignore
			if ( ! window.confirm( sentinelData.i18n.confirmRestore ) ) {
				return;
			}

			var backupId = $( e.currentTarget ).data( 'id' );
			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action:    'sentinel_restore_backup',
					backup_id: parseInt( backupId, 10 ),
					nonce:     sentinelData.nonces.restore,
				},
			} );
		},

		/**
		 * Delete a backup.
		 *
		 * @param {jQuery.Event} e Click event.
		 */
		deleteBackup: function ( e ) {
			// phpcs:ignore
			if ( ! window.confirm( sentinelData.i18n.confirmDelete ) ) {
				return;
			}

			var backupId = $( e.currentTarget ).data( 'id' );
			var self     = this;

			$.ajax( {
				url:    sentinelData.ajaxUrl,
				method: 'POST',
				data:   {
					action:    'sentinel_delete_backup',
					backup_id: parseInt( backupId, 10 ),
					nonce:     sentinelData.nonces.delete,
				},
				success: function ( response ) {
					if ( response.success ) {
						self.showNotification( 'Backup deleted.', 'success' );
						$( e.currentTarget ).closest( 'tr' ).fadeOut();
					}
				},
			} );
		},

		// ---------------------------------------------------------------
		// UI Helpers
		// ---------------------------------------------------------------

		/**
		 * Show the scan progress section.
		 *
		 * @param {number} pct    Progress percentage (0-100).
		 * @param {string} status Status text.
		 */
		showProgress: function ( pct, status ) {
			$( '#sentinel-scan-progress' ).show();
			$( '#sentinelProgressFill' ).css( 'width', Math.min( 100, pct ) + '%' );
			$( '#sentinelProgressText' ).text( Math.min( 100, pct ) + '%' );
			$( '#sentinelProgressStatus' ).text( status || '' );
		},

		/**
		 * Hide the scan progress section.
		 */
		hideProgress: function () {
			$( '#sentinel-scan-progress' ).hide();
		},

		/**
		 * Show a temporary notification.
		 *
		 * @param {string} message  Notification message.
		 * @param {string} type     'success' | 'error' | 'info'
		 * @param {string} nextStep Optional next-step hint shown below the message.
		 */
		showNotification: function ( message, type, nextStep ) {
			type = type || 'info';
			var html = $( '<span>' ).text( message ).html();
			if ( nextStep ) {
				html += '<div class="sentinel-notification-next">' + $( '<span>' ).text( nextStep ).html() + '</div>';
			}
			var $note = $( '<div class="sentinel-notification sentinel-notification-' + type + '">' + html + '</div>' );
			$( 'body' ).append( $note );

			setTimeout( function () {
				$note.fadeOut( 400, function () { $( this ).remove(); } );
			}, 8000 );
		},
	};

	$( function () {
		Sentinel.init();
	} );

} )( jQuery );
