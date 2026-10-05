<?php
/**
 * EasyRecaptcha - Google reCAPTCHA v2 / v3 for PrestaShop 8.x / 9.x
 *
 * Protects the login, registration, contact, personal-information and back-office
 * login forms, and can refuse specific e-mail addresses and IP addresses.
 *
 * How it works (no theme edits, no core overrides):
 *  - a small script finds the forms on the page and adds the widget / token itself;
 *  - on submit, the module checks the token BEFORE the controller runs
 *    (actionFrontControllerInitBefore / actionAdminLoginControllerBefore). If the check
 *    fails it removes the submit flag from the request so the form is not processed,
 *    and adds an error message to the page.
 *
 * @author Nasraoui Mustapha
 */
if (!defined('_PS_VERSION_')) {
    exit;
}

require_once dirname(__FILE__) . '/classes/EasyRecaptchaRules.php';
require_once dirname(__FILE__) . '/classes/EasyRecaptchaVerifier.php';

class EasyRecaptcha extends Module
{
    const CONF = 'EASYRECAPTCHA_SETTINGS';
    const LOG_LIMIT = 100;

    public function __construct()
    {
        $this->name = 'easyrecaptcha';
        $this->tab = 'administration';
        $this->version = '1.0.0';
        $this->author = 'Nasraoui Mustapha';
        $this->need_instance = 0;
        $this->bootstrap = true;
        $this->ps_versions_compliancy = array('min' => '8.0.0', 'max' => '9.99.99');

        parent::__construct();

        $this->displayName = $this->l('EasyRecaptcha – Google reCAPTCHA v2 & v3');
        $this->description = $this->l('Protect your forms against spam and bots, and block e-mails and IP addresses.');
    }

    /* ------------------------------------------------------------------ */
    /* Install / uninstall                                                 */
    /* ------------------------------------------------------------------ */

    public function install()
    {
        return parent::install()
            && $this->installDb()
            && $this->registerHook('actionFrontControllerInitBefore')
            && $this->registerHook('actionFrontControllerSetMedia')
            && $this->registerHook('actionAdminLoginControllerBefore')
            && $this->registerHook('actionAdminLoginControllerSetMedia');
    }

    public function uninstall()
    {
        Db::getInstance()->execute('DROP TABLE IF EXISTS `' . _DB_PREFIX_ . 'easyrecaptcha_log`');
        Configuration::deleteByName(self::CONF);

        return parent::uninstall();
    }

    private function installDb()
    {
        return Db::getInstance()->execute(
            'CREATE TABLE IF NOT EXISTS `' . _DB_PREFIX_ . 'easyrecaptcha_log` (
                `id_log` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `form` VARCHAR(24) NOT NULL,
                `ip` VARCHAR(45) NOT NULL DEFAULT \'\',
                `result` VARCHAR(24) NOT NULL,
                `score` VARCHAR(8) NOT NULL DEFAULT \'\',
                `detail` VARCHAR(255) NOT NULL DEFAULT \'\',
                `date_add` DATETIME NOT NULL,
                PRIMARY KEY (`id_log`)
            ) ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=utf8mb4'
        );
    }

    /* ------------------------------------------------------------------ */
    /* Settings                                                            */
    /* ------------------------------------------------------------------ */

    public static function getSettings()
    {
        $defaults = array(
            'version' => 'v3',
            'site_key' => '',
            'secret_key' => '',
            'sandbox' => 0,
            'domain' => 'google',
            'theme' => 'light',
            'size' => 'normal',
            'threshold' => 0.5,
            'badge' => 'bottomright',
            'fail_open' => 1,
            'lazy' => 0,
            'form_login' => 1,
            'form_register' => 1,
            'form_contact' => 1,
            'form_identity' => 0,
            'form_admin_login' => 0,
            'skip_logged_contact' => 0,
            'extra_pages' => '',
            'blocked_emails' => '',
            'blocked_ips' => '',
            'trust_cloudflare' => 0,
        );
        $stored = json_decode((string) Configuration::get(self::CONF), true);

        return array_merge($defaults, is_array($stored) ? $stored : array());
    }

    /** Emergency switch: an empty file named disable.flag in the module folder turns every check off. */
    private function emergencyOff()
    {
        return is_file(dirname(__FILE__) . '/disable.flag');
    }

    private function isReady(array $s)
    {
        if ($this->emergencyOff()) {
            return false;
        }

        return EasyRecaptchaVerifier::siteKey($s) !== '' && EasyRecaptchaVerifier::secretKey($s) !== '';
    }

    private function clientIp(array $s)
    {
        if (!empty($s['trust_cloudflare']) && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])
            && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }

        return (string) Tools::getRemoteAddr();
    }

    /* ------------------------------------------------------------------ */
    /* Which forms are protected on which page                            */
    /* ------------------------------------------------------------------ */

    private function pageOf($controller)
    {
        return (is_object($controller) && isset($controller->php_self)) ? (string) $controller->php_self : '';
    }

    /**
     * Form keys that are protected on this controller. The SAME list drives both the script
     * (which adds the widget) and the server check, so a form is never enforced on a page
     * where the widget was not added.
     */
    private function protectedKeys($controller, array $s)
    {
        $page = $this->pageOf($controller);
        $map = array(
            'authentication' => array('login', 'register'),
            'registration' => array('register'),
            'order' => array('login', 'register'),
            'contact' => array('contact'),
            'identity' => array('identity'),
        );
        $keys = isset($map[$page]) ? $map[$page] : array();

        $extra = array_map('strtolower', EasyRecaptchaRules::parseList($s['extra_pages']));
        if ($page !== '' && in_array(strtolower($page), $extra, true)) {
            $keys = array('login', 'register', 'contact');
        }

        $out = array();
        foreach ($keys as $key) {
            if (empty($s['form_' . $key])) {
                continue;
            }
            if ($key === 'contact' && !empty($s['skip_logged_contact']) && $this->customerLoggedIn()) {
                continue;
            }
            $out[] = $key;
        }

        return $out;
    }

    /**
     * Is a customer logged in? Read from the session cookie, because the server check runs
     * before PrestaShop has built context->customer; the script side (which runs later) and
     * the server side must agree, or logged-in customers could never submit the form.
     */
    private function customerLoggedIn()
    {
        $cookie = isset($this->context->cookie) ? $this->context->cookie : null;
        if (is_object($cookie) && !empty($cookie->logged) && !empty($cookie->id_customer)) {
            return true;
        }

        return isset($this->context->customer) && is_object($this->context->customer) && $this->context->customer->isLogged();
    }

    /* ------------------------------------------------------------------ */
    /* Front office: assets                                                */
    /* ------------------------------------------------------------------ */

    public function hookActionFrontControllerSetMedia($params)
    {
        $s = self::getSettings();
        if (!$this->isReady($s)) {
            return;
        }
        $controller = $this->context->controller;
        $keys = $this->protectedKeys($controller, $s);
        if (!$keys) {
            return;
        }

        $controller->registerJavascript(
            'easyrecaptcha-front',
            'modules/' . $this->name . '/views/js/easyrecaptcha-front.js',
            array('position' => 'bottom', 'priority' => 150)
        );
        $controller->registerStylesheet(
            'easyrecaptcha-front',
            'modules/' . $this->name . '/views/css/easyrecaptcha-front.css',
            array('media' => 'all', 'priority' => 150)
        );

        Media::addJsDef(array('easyRecaptchaConfig' => array(
            'version' => $s['version'],
            'siteKey' => EasyRecaptchaVerifier::siteKey($s),
            'host' => EasyRecaptchaVerifier::apiHost($s),
            'theme' => $s['theme'],
            'size' => $s['size'],
            'badge' => $s['badge'],
            'lazy' => (bool) $s['lazy'],
            'hl' => isset($this->context->language->iso_code) ? $this->context->language->iso_code : 'en',
            'page' => $this->pageOf($controller),
            'forms' => $keys,
            'msgRequired' => $this->l('Please tick the reCAPTCHA box.'),
            'legal' => ($s['version'] === 'v3' && $s['badge'] === 'hidden') ? $this->legalHtml() : '',
        )));
    }

    private function legalHtml()
    {
        return sprintf(
            $this->l('This site is protected by reCAPTCHA and the Google %1$s and %2$s apply.'),
            '<a href="https://policies.google.com/privacy" target="_blank" rel="noopener">' . $this->l('Privacy Policy') . '</a>',
            '<a href="https://policies.google.com/terms" target="_blank" rel="noopener">' . $this->l('Terms of Service') . '</a>'
        );
    }

    /* ------------------------------------------------------------------ */
    /* Front office: server-side enforcement                               */
    /* ------------------------------------------------------------------ */

    public function hookActionFrontControllerInitBefore($params)
    {
        if (empty($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'POST'
            || $this->emergencyOff() || empty($params['controller'])) {
            return;
        }
        $controller = $params['controller'];
        $page = $this->pageOf($controller);

        // Which form is being submitted? (same field names on every theme)
        if (isset($_POST['submitLogin'])) {
            $key = 'login';
            $flag = 'submitLogin';
        } elseif (isset($_POST['submitCreate'])) {
            $key = ($page === 'identity') ? 'identity' : 'register';
            $flag = 'submitCreate';
        } elseif (isset($_POST['submitMessage'])) {
            $key = 'contact';
            $flag = 'submitMessage';
        } else {
            return;
        }

        $s = self::getSettings();
        $ip = $this->clientIp($s);

        // 1. blocked IP / e-mail (login, registration, personal information)
        if ($key !== 'contact') {
            if ($key !== 'identity' && EasyRecaptchaRules::ipMatches($ip, EasyRecaptchaRules::parseList($s['blocked_ips']))) {
                $this->logCheck($key, $ip, 'blocked_ip', null, '');
                $this->blockRequest($controller, $flag, $this->l('Access from your network is not allowed.'));

                return;
            }
            $email = trim((string) Tools::getValue('email'));
            if ($email !== '' && EasyRecaptchaRules::emailMatches($email, EasyRecaptchaRules::parseList($s['blocked_emails']))) {
                $this->logCheck($key, $ip, 'blocked_email', null, '');
                $this->blockRequest($controller, $flag, $this->l('This email address is not allowed.'));

                return;
            }
        }

        // 2. reCAPTCHA
        if (!$this->isReady($s) || !in_array($key, $this->protectedKeys($controller, $s), true)) {
            return;
        }
        $verdict = EasyRecaptchaVerifier::verify((string) Tools::getValue('g-recaptcha-response'), $key, $ip, $s);
        $this->logCheck($key, $ip, $verdict['result'], $verdict['score'], $verdict['detail']);
        if (!$verdict['ok']) {
            $this->blockRequest($controller, $flag, $this->l('Captcha verification failed. Please try again.'));
        }
    }

    /** Stops the controller from processing the form, and shows the reason. */
    private function blockRequest($controller, $flag, $message)
    {
        unset($_POST[$flag], $_GET[$flag], $_REQUEST[$flag]);
        if (is_object($controller) && isset($controller->errors) && is_array($controller->errors)) {
            $controller->errors[] = $message;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Back office login                                                   */
    /* ------------------------------------------------------------------ */

    public function hookActionAdminLoginControllerSetMedia($params)
    {
        $s = self::getSettings();
        if (empty($s['form_admin_login']) || !$this->isReady($s) || empty($params['controller'])) {
            return;
        }
        $query = http_build_query(array(
            'sk' => EasyRecaptchaVerifier::siteKey($s),
            'v' => $s['version'],
            'th' => $s['theme'],
            'sz' => $s['size'],
            'host' => EasyRecaptchaVerifier::apiHost($s),
            'hl' => isset($this->context->language->iso_code) ? $this->context->language->iso_code : 'en',
            'msg' => $this->l('Please tick the reCAPTCHA box.'),
        ));
        // The script reads its settings from its own URL, so nothing else has to be injected
        // into the login page. (2nd argument = skip the local-file check, the URL has a query.)
        $params['controller']->addJS(_MODULE_DIR_ . $this->name . '/views/js/easyrecaptcha-admin.js?' . $query, false);
    }

    public function hookActionAdminLoginControllerBefore($params)
    {
        $s = self::getSettings();
        if (empty($s['form_admin_login']) || !$this->isReady($s) || empty($params['controller'])
            || !isset($_POST['submitLogin'])) {
            return;
        }
        $ip = $this->clientIp($s);
        $verdict = EasyRecaptchaVerifier::verify((string) Tools::getValue('g-recaptcha-response'), 'admin_login', $ip, $s);
        $this->logCheck('admin_login', $ip, $verdict['result'], $verdict['score'], $verdict['detail']);
        if (!$verdict['ok']) {
            $this->blockRequest($params['controller'], 'submitLogin', $this->l('Captcha verification failed. Please try again.'));
        }
    }

    /* ------------------------------------------------------------------ */
    /* Log                                                                 */
    /* ------------------------------------------------------------------ */

    private function logCheck($form, $ip, $result, $score, $detail)
    {
        $table = _DB_PREFIX_ . 'easyrecaptcha_log';
        Db::getInstance()->insert('easyrecaptcha_log', array(
            'form' => pSQL($form),
            'ip' => pSQL(Tools::substr((string) $ip, 0, 45)),
            'result' => pSQL($result),
            'score' => $score === null ? '' : pSQL(number_format((float) $score, 2, '.', '')),
            'detail' => pSQL(Tools::substr((string) $detail, 0, 250)),
            'date_add' => date('Y-m-d H:i:s'),
        ));
        // keep only the most recent rows
        Db::getInstance()->execute(
            "DELETE FROM `$table` WHERE id_log NOT IN (
                SELECT id_log FROM (SELECT id_log FROM `$table` ORDER BY id_log DESC LIMIT " . (int) self::LOG_LIMIT . ') t
            )'
        );
    }

    /* ------------------------------------------------------------------ */
    /* Admin page                                                          */
    /* ------------------------------------------------------------------ */

    private function esc($value)
    {
        return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    }

    private function formAction()
    {
        return AdminController::$currentIndex . '&configure=' . $this->name
            . '&token=' . Tools::getAdminTokenLite('AdminModules');
    }

    public function getContent()
    {
        $html = '';

        if (Tools::isSubmit('clearEasyRecaptchaLog')) {
            Db::getInstance()->execute('TRUNCATE TABLE `' . _DB_PREFIX_ . 'easyrecaptcha_log`');
            $html .= $this->displayConfirmation($this->l('Log cleared.'));
        }
        if (Tools::isSubmit('submitEasyRecaptcha')) {
            $errors = $this->saveSettings();
            foreach ($errors as $error) {
                $html .= $this->displayError($this->esc($error));
            }
            if (!$errors) {
                $html .= $this->displayConfirmation($this->l('Settings saved.'));
            }
        }

        return $html . $this->renderStatus() . $this->renderForm() . $this->renderLog() . $this->renderHelp();
    }

    private function saveSettings()
    {
        $old = self::getSettings();
        $errors = array();

        $choice = function ($name, array $allowed, $default) {
            $v = (string) Tools::getValue($name);

            return in_array($v, $allowed, true) ? $v : $default;
        };
        $flag = function ($name) {
            return Tools::getValue($name) ? 1 : 0;
        };
        $key = function ($name) {
            return preg_replace('/[^A-Za-z0-9_\-]/', '', (string) Tools::getValue($name));
        };

        $new = $old;
        $new['version'] = $choice('version', array('v2', 'v3'), 'v3');
        $new['site_key'] = $key('site_key');
        $secret = $key('secret_key');
        $new['secret_key'] = $secret !== '' ? $secret : $old['secret_key']; // empty = keep the saved one
        $new['sandbox'] = $flag('sandbox');
        $new['domain'] = $choice('domain', array('google', 'recaptcha'), 'google');
        $new['theme'] = $choice('theme', array('light', 'dark'), 'light');
        $new['size'] = $choice('size', array('normal', 'compact'), 'normal');
        $new['threshold'] = max(0.1, min(0.9, round((float) str_replace(',', '.', (string) Tools::getValue('threshold')), 2)));
        $new['badge'] = $choice('badge', array('bottomright', 'bottomleft', 'hidden'), 'bottomright');
        $new['fail_open'] = $flag('fail_open');
        $new['lazy'] = $flag('lazy');
        foreach (array('login', 'register', 'contact', 'identity', 'admin_login') as $form) {
            $new['form_' . $form] = $flag('form_' . $form);
        }
        $new['skip_logged_contact'] = $flag('skip_logged_contact');
        // page names (php_self): letters, digits, - and _ only; separated by comma, semicolon or space
        $pages = array();
        foreach (preg_split('/[\s,;]+/', (string) Tools::getValue('extra_pages')) as $page) {
            $page = preg_replace('/[^A-Za-z0-9_\-]/', '', $page);
            if ($page !== '' && !in_array($page, $pages, true)) {
                $pages[] = $page;
            }
        }
        $new['extra_pages'] = implode(',', $pages);
        $new['trust_cloudflare'] = $flag('trust_cloudflare');

        // e-mails: anything sensible is accepted
        $emails = array();
        foreach (EasyRecaptchaRules::parseList(Tools::getValue('blocked_emails')) as $e) {
            if (strlen($e) <= 254) {
                $emails[] = strtolower($e);
            }
        }
        $new['blocked_emails'] = implode("\n", $emails);

        // IPs: validate, and never let an administrator lock themselves out
        $ips = EasyRecaptchaRules::parseList(Tools::getValue('blocked_ips'));
        $invalid = array();
        foreach ($ips as $ip) {
            if (!EasyRecaptchaRules::isValidIpEntry($ip)) {
                $invalid[] = $ip;
            }
        }
        $myIp = $this->clientIp($new);
        if ($invalid) {
            $errors[] = $this->l('Not saved: these IP entries are not valid:') . ' ' . implode(', ', $invalid);
        } elseif ($ips && EasyRecaptchaRules::ipMatches($myIp, $ips)) {
            $errors[] = sprintf($this->l('Not saved: your own IP address (%s) is in the blocked list.'), $myIp);
        } else {
            $new['blocked_ips'] = implode("\n", $ips);
        }

        if (EasyRecaptchaVerifier::siteKey($new) === '' || EasyRecaptchaVerifier::secretKey($new) === '') {
            $errors[] = $this->l('Enter both the site key and the secret key, or enable sandbox mode with reCAPTCHA v2. Nothing is protected until then.');
        }

        // Everything except an invalid IP list is saved even when a warning is shown.
        Configuration::updateValue(self::CONF, json_encode($new));

        return $errors;
    }

    /* ---- HTML helpers ---------------------------------------------------- */

    private function optionsHtml(array $options, $selected)
    {
        $html = '';
        foreach ($options as $value => $label) {
            $html .= '<option value="' . $this->esc($value) . '"' . ((string) $value === (string) $selected ? ' selected' : '')
                . '>' . $this->esc($label) . '</option>';
        }

        return $html;
    }

    private function selectHtml($name, array $options, $selected)
    {
        return '<select name="' . $this->esc($name) . '" class="form-control">' . $this->optionsHtml($options, $selected) . '</select>';
    }

    private function yesNo($name, $current)
    {
        return $this->selectHtml($name, array(1 => $this->l('Yes'), 0 => $this->l('No')), (int) $current ? 1 : 0);
    }

    private function textHtml($name, $value, $placeholder = '')
    {
        return '<input type="text" class="form-control" autocomplete="off" name="' . $this->esc($name) . '" value="' . $this->esc($value)
            . '" placeholder="' . $this->esc($placeholder) . '">';
    }

    private function textareaHtml($name, $value, $placeholder = '')
    {
        return '<textarea class="form-control" rows="5" name="' . $this->esc($name) . '" placeholder="' . $this->esc($placeholder) . '">'
            . $this->esc($value) . '</textarea>';
    }

    private function rowHtml($label, $input, $help = '')
    {
        return '<div class="form-group row"><label class="control-label col-lg-3">' . $label . '</label>'
            . '<div class="col-lg-6">' . $input . ($help !== '' ? '<p class="help-block">' . $help . '</p>' : '') . '</div></div>';
    }

    /* ---- panels ----------------------------------------------------------- */

    private function renderStatus()
    {
        $s = self::getSettings();
        if ($this->emergencyOff()) {
            return $this->displayWarning($this->l('EMERGENCY SWITCH ACTIVE: the file disable.flag exists in the module folder, so every check is off. Delete it to re-enable protection.'));
        }
        if (!$this->isReady($s)) {
            return $this->displayWarning($this->l('Not configured yet: enter your reCAPTCHA keys below. Until then nothing is protected and nothing is blocked (except e-mail / IP restrictions).'));
        }
        if (!empty($s['sandbox'])) {
            return $this->infoBox(
                $s['version'] === 'v2'
                    ? $this->l('Sandbox mode: Google\'s test keys are used and nothing is ever blocked. Perfect for checking the widget is displayed.')
                    : $this->l('Sandbox mode: verification runs with your keys and is logged, but nothing is ever blocked (Google offers no test keys for v3).')
            );
        }

        return $this->displayConfirmation($this->l('Protection is active.'));
    }

    private function infoBox($msg)
    {
        return '<div class="alert alert-info">' . $this->esc($msg) . '</div>';
    }

    private function renderForm()
    {
        $s = self::getSettings();
        $html = '<form method="post" action="' . $this->formAction() . '" class="form-horizontal">';

        // --- keys & behaviour
        $html .= '<div class="panel"><div class="panel-heading">' . $this->l('reCAPTCHA keys and behaviour') . '</div>';
        $html .= $this->rowHtml($this->l('Version'), $this->selectHtml('version', array('v3' => 'reCAPTCHA v3 (invisible, score based)', 'v2' => 'reCAPTCHA v2 ("I\'m not a robot" checkbox)'), $s['version']),
            $this->l('Keys are specific to a version: v2 keys do not work with v3 and vice versa. Create them at google.com/recaptcha/admin.'));
        $html .= $this->rowHtml($this->l('Site key'), $this->textHtml('site_key', $s['site_key']));
        $html .= $this->rowHtml($this->l('Secret key'), $this->textHtml('secret_key', '', $s['secret_key'] !== '' ? $this->l('(saved: leave empty to keep it)') : ''),
            $this->l('Never share this key.'));
        $html .= $this->rowHtml($this->l('Sandbox mode'), $this->yesNo('sandbox', $s['sandbox']),
            $this->l('Nothing is ever blocked, results are only logged. With v2, Google\'s public test keys are used automatically. Use it to check the widget, then switch it off.'));
        $html .= $this->rowHtml($this->l('Theme'), $this->selectHtml('theme', array('light' => $this->l('Light'), 'dark' => $this->l('Dark')), $s['theme']),
            $this->l('Applies to the v2 checkbox. The v3 badge cannot be themed.'));
        $html .= $this->rowHtml($this->l('Widget size (v2)'), $this->selectHtml('size', array('normal' => $this->l('Normal'), 'compact' => $this->l('Compact')), $s['size']));
        $html .= $this->rowHtml($this->l('v3 minimum score'), $this->textHtml('threshold', $s['threshold']),
            $this->l('0.1 to 0.9. Google suggests 0.5. Raise it to be stricter; lower it if real customers get blocked (see the log below).'));
        $html .= $this->rowHtml($this->l('v3 badge'), $this->selectHtml('badge', array(
            'bottomright' => $this->l('Bottom right'),
            'bottomleft' => $this->l('Bottom left'),
            'hidden' => $this->l('Hidden (adds Google\'s required notice under each form)'),
        ), $s['badge']));
        $html .= $this->rowHtml($this->l('Load Google only on first interaction'), $this->yesNo('lazy', $s['lazy']),
            $this->l('Faster pages and fewer third-party requests for visitors who never touch a form.'));
        $html .= $this->rowHtml($this->l('Google domain'), $this->selectHtml('domain', array('google' => 'google.com', 'recaptcha' => 'recaptcha.net'), $s['domain']),
            $this->l('Use recaptcha.net if google.com is blocked for some of your visitors.'));
        $html .= $this->rowHtml($this->l('If Google cannot be reached'), $this->selectHtml('fail_open', array(1 => $this->l('Let the request through (recommended)'), 0 => $this->l('Refuse the request')), $s['fail_open']),
            $this->l('Only applies when the server cannot contact Google. A missing or invalid token is always refused.'));
        $html .= '</div>';

        // --- forms
        $html .= '<div class="panel"><div class="panel-heading">' . $this->l('Protected forms') . '</div>';
        $html .= $this->rowHtml($this->l('Customer login'), $this->yesNo('form_login', $s['form_login']));
        $html .= $this->rowHtml($this->l('Registration'), $this->yesNo('form_register', $s['form_register']),
            $this->l('Also covers account creation during checkout.'));
        $html .= $this->rowHtml($this->l('Contact us'), $this->yesNo('form_contact', $s['form_contact']));
        $html .= $this->rowHtml($this->l('Skip for logged-in customers (contact form)'), $this->yesNo('skip_logged_contact', $s['skip_logged_contact']));
        $html .= $this->rowHtml($this->l('Personal information'), $this->yesNo('form_identity', $s['form_identity']),
            $this->l('The "Your account > Information" form.'));
        $html .= $this->rowHtml($this->l('Back office login'), $this->yesNo('form_admin_login', $s['form_admin_login']),
            $this->l('Test it in sandbox mode first, keep this page open in another tab, and read the "locked out?" note at the bottom.'));
        $html .= $this->rowHtml($this->l('Extra pages'), $this->textHtml('extra_pages', $s['extra_pages'], 'cms'),
            $this->l('Advanced. Page names (as in the page\'s php_self, e.g. "cms") where a login, registration or contact form is embedded and must also be protected.'));
        $html .= '</div>';

        // --- restrictions
        $myIp = $this->clientIp($s);
        $html .= '<div class="panel"><div class="panel-heading">' . $this->l('Restrictions (login and registration)') . '</div>';
        $html .= $this->rowHtml($this->l('Blocked e-mails'), $this->textareaHtml('blocked_emails', $s['blocked_emails'], "bad@example.com\n@spam.com\n*.ru\n*viagra*"),
            $this->l('One per line. Formats: an exact address, @domain.com (or just domain.com, sub-domains included), or a pattern with * as wildcard. These addresses can neither log in, register nor change their e-mail to one of them.'));
        $html .= $this->rowHtml($this->l('Blocked IP addresses'), $this->textareaHtml('blocked_ips', $s['blocked_ips'], "203.0.113.7\n198.51.100.0/24\n2001:db8::/32"),
            $this->l('One per line: an IPv4 / IPv6 address or a CIDR range. Visitors from these addresses can neither log in nor register. You are currently seen as:') . ' <code>' . $this->esc($myIp) . '</code>');
        $html .= $this->rowHtml($this->l('Behind Cloudflare'), $this->yesNo('trust_cloudflare', $s['trust_cloudflare']),
            $this->l('Read the visitor IP from the CF-Connecting-IP header. Enable ONLY if your site really is behind Cloudflare, otherwise visitors could fake their IP.'));
        $html .= '</div>';

        return $html . '<button type="submit" name="submitEasyRecaptcha" value="1" class="btn btn-primary btn-lg">' . $this->l('Save') . '</button></form><br>';
    }

    private function renderLog()
    {
        $rows = Db::getInstance()->executeS('SELECT * FROM `' . _DB_PREFIX_ . 'easyrecaptcha_log` ORDER BY id_log DESC LIMIT 25');
        $html = '<div class="panel"><div class="panel-heading">' . $this->l('Recent checks (last 25)') . '</div>';
        if (!$rows) {
            return $html . '<p>' . $this->l('Nothing yet. Submit a protected form to see the result here.') . '</p></div>';
        }
        $html .= '<table class="table"><thead><tr><th>' . $this->l('Date') . '</th><th>' . $this->l('Form') . '</th><th>' . $this->l('IP') . '</th><th>'
            . $this->l('Result') . '</th><th>' . $this->l('Score') . '</th><th>' . $this->l('Detail') . '</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            $good = in_array($r['result'], array('pass', 'sandbox_pass'), true);
            $html .= '<tr><td>' . $this->esc($r['date_add']) . '</td><td>' . $this->esc($r['form']) . '</td><td>' . $this->esc($r['ip']) . '</td><td>'
                . '<span class="label label-' . ($good ? 'success' : 'danger') . '">' . $this->esc($r['result']) . '</span></td><td>'
                . $this->esc($r['score']) . '</td><td><small>' . $this->esc($r['detail']) . '</small></td></tr>';
        }
        $html .= '</tbody></table>';
        $html .= '<form method="post" action="' . $this->formAction() . '"><button type="submit" name="clearEasyRecaptchaLog" value="1" class="btn btn-default btn-sm">'
            . $this->l('Clear the log') . '</button> <small>' . $this->l('The log keeps the last 100 checks (form, IP, result, score) so you can tune the v3 score. Mention it in your privacy policy.') . '</small></form>';

        return $html . '</div>';
    }

    private function renderHelp()
    {
        $html = '<div class="panel"><div class="panel-heading">' . $this->l('Good to know') . '</div><ul>';
        $items = array(
            $this->l('No template edits are needed: a script adds the widget (v2) or the invisible token (v3) to your forms, and the server refuses a submission whose check fails.'),
            $this->l('If a customer\'s theme has a heavily customised form the script cannot find, that form simply shows no widget. Check each protected form after saving.'),
            $this->l('Locked out of the back office? Create an empty file named disable.flag in the module folder (modules/easyrecaptcha/) using FTP or your hosting file manager. Every check is switched off immediately. Delete the file to switch protection back on.'),
            $this->l('reCAPTCHA sets cookies and shares data with Google: declare it in your privacy / cookie policy, and adapt your consent banner if you use one.'),
        );
        foreach ($items as $item) {
            $html .= '<li style="margin-bottom:6px">' . $this->esc($item) . '</li>';
        }

        return $html . '</ul></div>';
    }
}
