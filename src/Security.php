<?php

namespace Mixset\Security;

use Mixset\Security\Exceptions\SecurityException;

require_once 'src/exceptions/SecurityException.php';

class Security
{
    /**
     * @var int
     */
    protected $errorReporting = 'E_ALL';

    /**
     * @var int
     */
    protected $displayErrors = 0;

    /**
     * @var string
     */
    protected $libraryPath = '/libs/';

    /**
     * @var string
     */
    protected $phpVersion;

    /**
     * @var string
     */
    const PASSWORD_LIB_REQUIRED_PHP = '5.5.0';

    /**
     * @param $value
     */
    public function setErrorReporting($value)
    {
        $this->errorReporting = $value;
    }

    /**
     * @param $value
     */
    public function setDisplayErrors($value)
    {
        $this->displayErrors = $value;
    }

    /**
     * @param $path
     */
    public function setLibraryPath($path)
    {
        $this->libraryPath = $path;
    }

    /**
     * @return int
     */
    public function getErrorReporting()
    {
        return $this->errorReporting;
    }

    /**
     * @return int
     */
    public function getDisplayErrors()
    {
        return $this->displayErrors;
    }

    /**
     * @return string
     */
    public function getLibraryPath()
    {
        return pathinfo(__DIR__)['dirname'] . $this->libraryPath;
    }

    /**
     * @param $version
     */
    public function setPHPVersion($version)
    {
        $this->phpVersion = $version;
    }

    /**
     * @return string
     */
    public function getPHPVersion()
    {
        return $this->phpVersion;
    }

    /**
     * Initialize some basic settings
     */
    public function __construct()
    {
        $this->configureSessionConstants();

        if (version_compare(PHP_VERSION, self::PASSWORD_LIB_REQUIRED_PHP) <= 0) {
            require $this->getLibraryPath() . 'password.php';
        }
    }

    /**
     * @throws SecurityException
     */
    public function checkPHPVersion()
    {
        if (is_null($this->getPHPVersion())) {
            throw new SecurityException('Required PHP Version is not specified. Cannot check required version.');
        }

        if (version_compare(phpversion(), $this->getPHPVersion(), '>')) {
            throw new SecurityException('System requires PHP in ' . $this->getPHPVersion() . ' version or greater.');
        }

        return true;
    }

    /**
     * Set error reporting configuration
     */
    public function configureErrorReporting()
    {
        // Error reporting
        error_reporting($this->getErrorReporting());

        // Error display configuration
        ini_set('display_errors', $this->getDisplayErrors());
    }

    /**
     * Set session configuration
     */
    private function configureSessionConstants()
    {
        // Session fixation prevention
        if (ini_get('session.use_cookies') !== 1) {
            ini_set('session.use_cookies', 1);
        }

        if (ini_get('session.use_only_cookies') !== 1) {
            ini_set('session.use_only_cookies', 1);
        }

        if (ini_get('session.use_trans_sid') !== 0) {
            ini_set('session.use_trans_sid', 0);
        }
    }

    /**
     * Checks, if ajax is called
     *
     * @param none
     * @return bool true | false
     */
    public function isAjax()
    {
        return isset($_SERVER['HTTP_X_REQUESTED_WITH'])
               && !empty($_SERVER['HTTP_X_REQUESTED_WITH'])
               && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';
    }

    /**
     * Clean input to prevent XSS attacks
     *
     * @param  string $data
     * @return string $data
     * @Link: https://gist.github.com/mbijon/1098477
     */
    public function xssClean($data)
    {
        // Fix &entity\n;
        $data = str_replace(array('&amp;', '&lt;', '&gt;'), array('&amp;amp;', '&amp;lt;', '&amp;gt;'), $data);
        $data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
        $data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
        $data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');

        // Remove any attribute starting with "on" or xmlns
        $data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);

        // Remove javascript: and vbscript: protocols
        $data = preg_replace(
            '#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu',
            '$1=$2nojavascript...',
            $data
        );

        $data = preg_replace(
            '#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu',
            '$1=$2novbscript...',
            $data
        );

        $data = preg_replace(
            '#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u',
            '$1=$2nomozbinding...',
            $data
        );

        // Only works in IE: <span style="width: expression(alert('Ping!'));"></span>
        $data = preg_replace(
            '#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i',
            '$1>',
            $data
        );

        $data = preg_replace(
            '#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i',
            '$1>',
            $data
        );

        $data = preg_replace(
            '#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu',
            '$1>',
            $data
        );

        // Remove namespaced elements (we do not need them)
        $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);

        do {
            // Remove really unwanted tags
            $old_data = $data;
            $data = preg_replace(
                '#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i',
                '',
                $data
            );
        } while ($old_data !== $data);

        return $data;
    }

    /**
     * Checks, if request is passed by given $request
     *
     * @param  string $request
     * @return bool true | false
     */
    public function request($request)
    {
        return strtolower($_SERVER['REQUEST_METHOD']) === strtolower($request);
    }

    /**
     * @param $toFilter
     *
     * @return array|mixed
     */
    public function clean($toFilter)
    {
        if (!is_array($toFilter)) {
            return $this->secure($toFilter);
        } else {
            $array = [];

            foreach ($toFilter as $key => $value) {
                $array[$key] = $this->clean($value);
            }

            return $array;
        }
    }

    /**
     * @param $string
     * @param int $sanitize
     *
     * @return mixed
     */
    private function secure($string, $sanitize = FILTER_SANITIZE_STRING)
    {
        return filter_var($string, $sanitize);
    }

    /**
     * @param  string $url
     * @return string $url
     */
    public function urlClean($url)
    {
        return $this->cleanInput($url, FILTER_SANITIZE_URL);
    }

    /**
     * @param $email
     *
     * @return mixed|null
     */
    public function emailClean($email)
    {
        return $this->cleanInput($email, FILTER_SANITIZE_EMAIL);
    }

    /**
     * @param $input
     * @param $filter
     *
     * @return mixed|null
     */
    public function cleanInput($input, $filter)
    {
        if (!function_exists('filter_var')) {
            return null;
        }

        return filter_var($input, $filter);
    }

    /**
     * @param string  $string
     * @param string  $algorithm
     * @return string password_hash
     */
    public function hashPassword($string, $algorithm)
    {
        if (empty($algorithm)) {
            $algorithm = PASSWORD_BCRYPT;
        }

        return password_hash($string, $algorithm);
    }

    /**
     * @param string  $password
     * @param string  $hash
     * @return string password_hash
     */
    public function checkPassword($password, $hash)
    {
        if (empty($password) || empty($hash)) {
            return null;
        }

        return password_verify($password, $hash);
    }

    /**
     * @param string $hash
     * @param string $algorithm
     * @param array  $options
     * @return true | false
     */
    public function passwordNeedsRehash($hash, $algorithm, $options)
    {
        if (empty($hash)
            || empty($algorithm)
            || empty($options)
            || !is_array($options)
        ) {
            return null;
        }

        return password_needs_rehash($hash, $algorithm, $options);
    }

    /**
     * @param string $hash
     * @return null | array
     */
    public function getPasswordInfo($hash)
    {
        return empty($hash)
            ? null
            : password_get_info($hash);
    }
}
