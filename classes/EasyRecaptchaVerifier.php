<?php
/**
 * Talks to Google's siteverify endpoint and decides whether a request may go through.
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

class EasyRecaptchaVerifier
{
    /** Google's public reCAPTCHA v2 test keys: they always validate (v2 only). */
    const TEST_SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
    const TEST_SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

    /** @var callable|null test seam: function ($url, array $params) => array('status' => int, 'body' => string) */
    public static $transport = null;

    public static function usesTestKeys(array $s)
    {
        return !empty($s['sandbox']) && $s['version'] === 'v2';
    }

    public static function siteKey(array $s)
    {
        return self::usesTestKeys($s) ? self::TEST_SITE_KEY : (string) $s['site_key'];
    }

    public static function secretKey(array $s)
    {
        return self::usesTestKeys($s) ? self::TEST_SECRET_KEY : (string) $s['secret_key'];
    }

    public static function apiHost(array $s)
    {
        return (isset($s['domain']) && $s['domain'] === 'recaptcha') ? 'www.recaptcha.net' : 'www.google.com';
    }

    /**
     * @return array [
     *   'ok'     => bool   may the request proceed?
     *   'result' => string pass|fail|missing_token|network_error|sandbox_pass|sandbox_fail
     *   'score'  => float|null (v3)
     *   'detail' => string
     * ]
     */
    public static function verify($token, $expectedAction, $ip, array $s)
    {
        $sandbox = !empty($s['sandbox']);
        $token = trim((string) $token);

        if ($token === '') {
            return self::outcome(false, 'missing_token', null, 'No reCAPTCHA response was submitted', $sandbox);
        }

        $params = array('secret' => self::secretKey($s), 'response' => $token);
        if ($ip !== '') {
            $params['remoteip'] = $ip;
        }
        $reply = self::post('https://' . self::apiHost($s) . '/recaptcha/api/siteverify', $params);

        if ($reply['status'] !== 200) {
            $allow = !empty($s['fail_open']);

            return array(
                'ok' => $allow || $sandbox,
                'result' => 'network_error',
                'score' => null,
                'detail' => 'Could not reach Google (' . $reply['error'] . '); ' . ($allow ? 'request allowed (fail-open)' : 'request refused'),
            );
        }

        $data = json_decode($reply['body'], true);
        if (!is_array($data)) {
            return self::outcome(false, 'fail', null, 'Unreadable answer from Google', $sandbox);
        }
        if (empty($data['success'])) {
            $codes = isset($data['error-codes']) && is_array($data['error-codes']) ? implode(', ', $data['error-codes']) : 'unknown';

            return self::outcome(false, 'fail', null, 'Google refused the token: ' . $codes, $sandbox);
        }

        if ($s['version'] === 'v3') {
            $score = isset($data['score']) ? (float) $data['score'] : 0.0;
            if (isset($data['action']) && $data['action'] !== $expectedAction) {
                return self::outcome(false, 'fail', $score, 'Action mismatch (got "' . $data['action'] . '", expected "' . $expectedAction . '")', $sandbox);
            }
            if ($score < (float) $s['threshold']) {
                return self::outcome(false, 'fail', $score, 'Score ' . $score . ' is below the threshold ' . $s['threshold'], $sandbox);
            }

            return self::outcome(true, 'pass', $score, 'Score ' . $score, $sandbox);
        }

        return self::outcome(true, 'pass', null, '', $sandbox);
    }

    /** In sandbox mode nothing is ever blocked, but the real verdict is still reported. */
    private static function outcome($ok, $result, $score, $detail, $sandbox)
    {
        if ($sandbox) {
            return array('ok' => true, 'result' => $ok ? 'sandbox_pass' : 'sandbox_fail', 'score' => $score, 'detail' => $detail);
        }

        return array('ok' => $ok, 'result' => $result, 'score' => $score, 'detail' => $detail);
    }

    private static function post($url, array $params)
    {
        if (self::$transport !== null) {
            $r = call_user_func(self::$transport, $url, $params);

            return array('status' => (int) $r['status'], 'body' => (string) $r['body'], 'error' => isset($r['error']) ? $r['error'] : '');
        }

        $body = http_build_query($params);
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, array(
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 4,
                CURLOPT_TIMEOUT => 6,
                CURLOPT_SSL_VERIFYPEER => true,
            ));
            $out = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);
            curl_close($ch);

            return array('status' => $out === false ? 0 : $status, 'body' => $out === false ? '' : (string) $out, 'error' => $error);
        }

        $ctx = stream_context_create(array('http' => array(
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $body,
            'timeout' => 6,
        )));
        $out = @file_get_contents($url, false, $ctx);

        return array('status' => $out === false ? 0 : 200, 'body' => $out === false ? '' : $out, 'error' => $out === false ? 'stream request failed' : '');
    }
}
