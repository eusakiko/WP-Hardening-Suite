<?php
/**
 * IP Manager — IP blocking, whitelisting and CIDR range support.
 *
 * Manages blocked and whitelisted IPs via WordPress options.
 * Supports single IPs and CIDR notation for range-based rules.
 *
 * @package WP_Sentinel_Security
 * @since   2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class IP_Manager
 */
class IP_Manager {

	/**
	 * Option name for blocked IPs.
	 *
	 * @var string
	 */
	const BLOCKED_OPTION = 'sentinel_blocked_ips';

	/**
	 * Option name for whitelisted IPs.
	 *
	 * @var string
	 */
	const WHITELIST_OPTION = 'sentinel_whitelisted_ips';

	/**
	 * Plugin settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Constructor.
	 *
	 * @param array $settings Plugin settings.
	 */
	public function __construct( $settings = array() ) {
		$this->settings = $settings;
	}

	/**
	 * Check if an IP address is blocked.
	 *
	 * @param string $ip IP address to check.
	 * @return bool True if blocked, false otherwise.
	 */
	public function is_blocked( $ip ) {
		$blocked = $this->get_blocked_ips();
		return $this->ip_in_list( $ip, $blocked );
	}

	/**
	 * Check if an IP address is whitelisted.
	 *
	 * @param string $ip IP address to check.
	 * @return bool True if whitelisted, false otherwise.
	 */
	public function is_whitelisted( $ip ) {
		$whitelist = $this->get_whitelisted_ips();
		return $this->ip_in_list( $ip, $whitelist );
	}

	/**
	 * Add an IP or CIDR range to the blocked list.
	 *
	 * @param string $ip     IP address or CIDR notation.
	 * @param string $reason Optional reason for the block.
	 * @param int    $expiry Optional expiry timestamp (0 = permanent).
	 * @return bool True on success.
	 */
	public function block_ip( $ip, $reason = '', $expiry = 0 ) {
		if ( ! $this->is_valid_ip_or_cidr( $ip ) ) {
			return false;
		}

		$blocked = $this->get_blocked_ips();

		$blocked[ $ip ] = array(
			'reason'     => sanitize_text_field( $reason ),
			'blocked_at' => time(),
			'expiry'     => absint( $expiry ),
		);

		return update_option( self::BLOCKED_OPTION, $blocked );
	}

	/**
	 * Remove an IP or CIDR range from the blocked list.
	 *
	 * @param string $ip IP address or CIDR notation to unblock.
	 * @return bool True on success.
	 */
	public function unblock_ip( $ip ) {
		$blocked = $this->get_blocked_ips();

		if ( ! isset( $blocked[ $ip ] ) ) {
			return false;
		}

		unset( $blocked[ $ip ] );
		return update_option( self::BLOCKED_OPTION, $blocked );
	}

	/**
	 * Add an IP or CIDR range to the whitelist.
	 *
	 * @param string $ip    IP address or CIDR notation.
	 * @param string $label Optional label/description.
	 * @return bool True on success.
	 */
	public function whitelist_ip( $ip, $label = '' ) {
		if ( ! $this->is_valid_ip_or_cidr( $ip ) ) {
			return false;
		}

		$whitelist = $this->get_whitelisted_ips();

		$whitelist[ $ip ] = array(
			'label'    => sanitize_text_field( $label ),
			'added_at' => time(),
		);

		return update_option( self::WHITELIST_OPTION, $whitelist );
	}

	/**
	 * Remove an IP or CIDR range from the whitelist.
	 *
	 * @param string $ip IP address or CIDR notation.
	 * @return bool True on success.
	 */
	public function remove_whitelist( $ip ) {
		$whitelist = $this->get_whitelisted_ips();

		if ( ! isset( $whitelist[ $ip ] ) ) {
			return false;
		}

		unset( $whitelist[ $ip ] );
		return update_option( self::WHITELIST_OPTION, $whitelist );
	}

	/**
	 * Get all blocked IPs (cleaning up expired entries).
	 *
	 * @return array Associative array of IP => metadata.
	 */
	public function get_blocked_ips() {
		$blocked = get_option( self::BLOCKED_OPTION, array() );

		if ( ! is_array( $blocked ) ) {
			return array();
		}

		// Remove expired entries.
		$now     = time();
		$changed = false;
		foreach ( $blocked as $ip => $meta ) {
			if ( ! empty( $meta['expiry'] ) && $meta['expiry'] < $now ) {
				unset( $blocked[ $ip ] );
				$changed = true;
			}
		}

		if ( $changed ) {
			update_option( self::BLOCKED_OPTION, $blocked );
		}

		return $blocked;
	}

	/**
	 * Get all whitelisted IPs.
	 *
	 * @return array Associative array of IP => metadata.
	 */
	public function get_whitelisted_ips() {
		$whitelist = get_option( self::WHITELIST_OPTION, array() );
		return is_array( $whitelist ) ? $whitelist : array();
	}

	/**
	 * Check whether a given IP matches any entry in a list (direct or CIDR).
	 *
	 * @param string $ip   IP address to test.
	 * @param array  $list Associative array keyed by IP or CIDR.
	 * @return bool True if the IP matches any entry.
	 */
	public function ip_in_list( $ip, $list ) {
		if ( ! is_array( $list ) || empty( $list ) ) {
			return false;
		}

		foreach ( array_keys( $list ) as $entry ) {
			if ( $ip === $entry ) {
				return true;
			}

			if ( false !== strpos( $entry, '/' ) && $this->ip_in_cidr( $ip, $entry ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if an IP falls within a CIDR range.
	 *
	 * @param string $ip   IP address to check.
	 * @param string $cidr CIDR notation (e.g. 192.168.1.0/24).
	 * @return bool True if IP is within the CIDR range.
	 */
	public function ip_in_cidr( $ip, $cidr ) {
		$parts = explode( '/', $cidr, 2 );
		if ( 2 !== count( $parts ) ) {
			return false;
		}

		list( $subnet, $mask ) = $parts;
		$mask = (int) $mask;

		$ip_long     = ip2long( $ip );
		$subnet_long = ip2long( $subnet );

		if ( false === $ip_long || false === $subnet_long ) {
			return false;
		}

		if ( $mask < 0 || $mask > 32 ) {
			return false;
		}

		$mask_long = -1 << ( 32 - $mask );

		return ( $ip_long & $mask_long ) === ( $subnet_long & $mask_long );
	}

	/**
	 * Validate an IP address or CIDR notation string.
	 *
	 * @param string $input IP or CIDR string.
	 * @return bool True if valid.
	 */
	public function is_valid_ip_or_cidr( $input ) {
		// Plain IP.
		if ( filter_var( $input, FILTER_VALIDATE_IP ) ) {
			return true;
		}

		// CIDR notation.
		$parts = explode( '/', $input, 2 );
		if ( 2 === count( $parts ) ) {
			$ip   = $parts[0];
			$mask = (int) $parts[1];
			if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) && $mask >= 0 && $mask <= 32 ) {
				return true;
			}
			if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) && $mask >= 0 && $mask <= 128 ) {
				return true;
			}
		}

		return false;
	}
}
