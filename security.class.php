<?php
/**
 *
 * @author Dominik Ryńko <http://rynko.pl/>
 * @version 1.0.0
 * @copyright 2015 Dominik Ryńko
 * @license http://creativecommons.org/licenses/by-sa/3.0/pl/
 */
class Security
{
    /**
    @var array $config property with config data
    */
    public $config = [
     'domain' => null,
     'error_reporting' => ['E_ALL', 1], // E_ALL -> error_reporting, 1/0 -> ini_set('display_errors')
     'path' => '/'
    ];

    /**
     @var array $result property, which contains result of actions
    */
    public $result = [];

    /**
     * @param none
    */
    public function __construct()
    {
        return null;
    }

    /**
     * @param none
     * @return null | password.php
    */
    public function init()
    {
        // Grab URL address of website
        preg_match('@^(?:http://)?([^/]+)@i', $this->config['domain'], $matches);

        if (strtolower($_SERVER['HTTP_HOST']) == strtolower($matches[1])) {
            $this->result['url_address'] = true;
        } else {
            $this->result['url_address'] = false;
        }

        // Error reporting
        error_reporting($this->config['error_reporting'][0]);

        // Error display configuration
        ini_set('display_errors', $this->config['error_reporting'][1]);

        // Session fixation prevention
        if (ini_get('session.use_cookies') !== 1) {
            ini_set('session.use_cookies', 1);
        }

        if (ini_get('session.use_only_cookies') !== 0) {
            ini_set('session.use_only_cookies', 1);
        }

        if (ini_get('session.use_trans_sid') !== 0) {
            ini_set('session.use_trans_sid', 1);
        }

        if (version_compare(PHP_VERSION, '5.5.0') <= 0) {
            require $this->config['path'] . 'password.php';
        }

        if (in_array('false', array_values($this->result))) {
            return null;
        }
    }

    /**
     * @param none
     * @return bool true | false
     */
    public function isAjax()
    {
        // Return true if AJAX if called otherwise return false
        return (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest');
   }

    /**
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
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
        $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);

        // Only works in IE: <span style="width: expression(alert('Ping!'));"></span>
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
        $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);

        // Remove namespaced elements (we do not need them)
        $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);

        do {
            // Remove really unwanted tags
            $old_data = $data;
            $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
        } while ($old_data !== $data);

        return $data;
    }

    /**
     * @param  string $type
     * @return bool true | false
     */
    public function request($type)
    {
        return (strtolower($_SERVER['REQUEST_METHOD']) == strtolower($type) ? true : false);
    }

    /**
     * @param string | array $data
     * @param bool           $multiple
     * @return  string $data
     */
    public function clean($data, $multiple = false)
    {
        if ($multiple == false) {
            if (is_array($data))
                return 0;
            else {
                $data = trim($data);
                $data = stripslashes($data);
                $data = htmlspecialchars($data);

                return $data;
            }
        } else {
            if (!is_array($data))
                return 0;
            else {
                /**
                 * Array must have format:
                 * array('key' => 'value', 'key2' => 'value2', etc.)
                 * */
                foreach ($data as $key => $value) {
                    $this->result[$key] = $this->clean($value);
                }

                return $this->result;
            }
        }
    }

    /**
     * @param  string $url
     * @return string $url
     */
    public function cleanUrl($url)
    {
        if (!function_exists('filter_var')) {
            return 0;
       }

        if (filter_var($url, FILTER_VALIDATE_URL) == false) {
            return 1;
        }

         return filter_var($url, FILTER_SANITIZE_URL);
    }

    /**
     * @param string  $string
     * @param string  $algorithm
     * @return string password_hash
     */
    public function hashPassword($string, $algorithm)
    {
        if (empty($algorithm))
            $algorithm = PASSWORD_BCRYPT;

        return password_hash($string, $algorithm);
    }

    /**
     * @param string  $password
     * @param string  $hash
     * @return string password_hash
     */
    public function checkPassword($password, $hash)
    {
        if (empty($password) || empty($hash))
            return null;
        else {
            $this->result['password'] = password_verify($password, $hash);
            if ($this->result['password'] == true)
                return true;
            else
                return false;
        }
    }


    /**
     * @param string $hash
     * @param string $algorithm
     * @param array  $options
     * @return true | false
     */
    public function passwordNeedsRehash($hash, $algorithm, $options)
    {
        if (empty($hash) || empty($algorithm) || empty($options))
            return null;
        elseif (!is_array($options))
            return null;
        else {
            $this->result['rehash'] = password_needs_rehash($hash, $algorithm, $options);
            if ($this->result['rehash'] == true)
                return true;
            else
                return false;
        }
    }

    /**
     * @param string $hash
     * @return null | array
     */
    public function getPasswordInfo($hash)
    {
        if (empty($hash))
            return null;
        else
            return password_get_info($hash);
    }


}

?>