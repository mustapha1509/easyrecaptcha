<?php
/**
 * Pure helpers for the e-mail and IP restriction lists (no PrestaShop dependency).
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

class EasyRecaptchaRules
{
    /**
     * Splits a textarea into clean entries: one per line (commas and semicolons also
     * separate), "#" starts a comment, blank lines dropped, duplicates removed.
     */
    public static function parseList($text)
    {
        $entries = array();
        foreach (preg_split('/[\r\n,;]+/', (string) $text) as $line) {
            $line = trim(preg_replace('/#.*$/', '', $line));
            if ($line !== '' && !in_array($line, $entries, true)) {
                $entries[] = $line;
            }
        }

        return $entries;
    }

    /**
     * Entry formats:
     *   user@example.com   exact address
     *   *@example.com      any user of that domain (also written @example.com)
     *   example.com        that domain AND its sub-domains
     *   *.ru  /  *spam*    wildcard, "*" matches any characters
     */
    public static function emailMatches($email, array $patterns)
    {
        $email = strtolower(trim((string) $email));
        if ($email === '') {
            return false;
        }
        foreach ($patterns as $pattern) {
            $pattern = strtolower(trim($pattern));
            if ($pattern === '') {
                continue;
            }
            if (strpos($pattern, '*') !== false) {
                $regex = '/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/';
                if (preg_match($regex, $email)) {
                    return true;
                }
            } elseif ($pattern[0] === '@') {
                if (self::endsWith($email, $pattern)) {
                    return true;
                }
            } elseif (strpos($pattern, '@') === false) {
                // bare domain: exact domain or any sub-domain
                if (self::endsWith($email, '@' . $pattern) || self::endsWith($email, '.' . $pattern)) {
                    return true;
                }
            } elseif ($email === $pattern) {
                return true;
            }
        }

        return false;
    }

    /** Entries: single IPv4/IPv6 address or CIDR range (192.168.0.0/24, 2001:db8::/32). */
    public static function ipMatches($ip, array $entries)
    {
        $ipBin = self::pack($ip);
        if ($ipBin === null) {
            return false;
        }
        foreach ($entries as $entry) {
            $entry = trim($entry);
            $bits = null;
            if (strpos($entry, '/') !== false) {
                list($entry, $bits) = explode('/', $entry, 2);
            }
            $netBin = self::pack($entry);
            if ($netBin === null || strlen($netBin) !== strlen($ipBin)) {
                continue;
            }
            $max = strlen($ipBin) * 8;
            $bits = ($bits === null) ? $max : max(0, min($max, (int) $bits));
            if (self::sameNetwork($ipBin, $netBin, $bits)) {
                return true;
            }
        }

        return false;
    }

    public static function isValidIpEntry($entry)
    {
        $entry = trim($entry);
        $bits = null;
        if (strpos($entry, '/') !== false) {
            list($entry, $bits) = explode('/', $entry, 2);
            if (!ctype_digit($bits)) {
                return false;
            }
        }
        $bin = self::pack($entry);
        if ($bin === null) {
            return false;
        }

        return $bits === null || (int) $bits <= strlen($bin) * 8;
    }

    private static function endsWith($haystack, $needle)
    {
        $len = strlen($needle);

        return $len > 0 && strlen($haystack) >= $len && substr($haystack, -$len) === $needle;
    }

    /** Binary form of an IP; IPv4-mapped IPv6 (::ffff:1.2.3.4) is folded to IPv4. */
    private static function pack($ip)
    {
        $ip = trim((string) $ip);
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 16 && substr($bin, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
            $bin = substr($bin, 12);
        }

        return $bin;
    }

    private static function sameNetwork($a, $b, $bits)
    {
        $fullBytes = intdiv($bits, 8);
        if ($fullBytes > 0 && substr($a, 0, $fullBytes) !== substr($b, 0, $fullBytes)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;

        return (ord($a[$fullBytes]) & $mask) === (ord($b[$fullBytes]) & $mask);
    }
}
