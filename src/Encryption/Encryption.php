<?php
/**
 * Aufa Encryption
 * This Library create encryption string and reverse it using mCrypt if possble
 *     if mCrypt not exists wil be use alternative encryption
 *     decryption will be check string as characters sign.
 *
 * @copyright   Copyright (c) 2015 awan
 * @link        https://github.com/aufa
 * @version     1.0
 * @author      awan <nawa@yahoo.com>
 * @package     aufa\encryption
 * @license     GPLv3 or later <https://www.gnu.org/licenses/gpl-3.0.txt>
 */

namespace Aufa\Encryption;

use Aufa\Encryption\Cryptography\Util;
use Aufa\Encryption\Cryptography\sha256;

/**
 * Encryption Instance class
 *
 * usage :
 *     (using mCrypt if possible)
 *     Aufa\Encryption\Encryption::encrypt('string to encrypt', 'saltkey');
 *     (using alternative mCrypt)
 *     Aufa\Encryption\Encryption::altEncrypt('string to encrypt', 'saltkey');
 *     (decryption)
 *     Aufa\Encryption\Encryption::decrypt('string to decrypt', 'saltkey');
 *
 */
class Encryption
{
    /* --------------------------------------------------------------------------------*
     |                              Encryption mCrypt                                  |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Current version
     */
    const VERSION = '1.0';

    /**
     * Encrypt the string
     * with mCrypt, make sure lib mCrypt is active by your php
     *
     * @param  mixed  $string the value of string to encryption
     * @param  mixed  $hash
     *
     * @return string
     */
    public static function encrypt($string, $hash = false)
    {
        /**
         * if empty values return null
         */
        if (!$string) {
            return null;
        }
        /**
         * Using Alternative Encryption
         * if mCrypt not loaded
         */
        if (! extension_loaded('mCrypt')) {
            return static::altEncrypt($string, $hash);
        }

        /**
         * ------------------------------------
         * Safe Sanitized hash
         * ------------------------------------
         */
        (is_null($hash) || $hash === false) && $hash = '';
        // safe is use array or object as hash
        $hash      = Util::maybeSerialize($hash);

        /**
         * ------------------------------------
         * Set Key
         * ------------------------------------
         */
        $key       = pack('H*', sha1(sha256::hash($hash)));
        /**
         * pad to 24 length
         * on PHP 5.5 + need keylength 16, 24 or 32
         */
        $key       = str_pad($key, 24, "\0", STR_PAD_RIGHT);

        /**
         * create array as content
         * this is for great opinion that values has already encrypted
         * to easily check values
         */
        $string    = serialize(array('mcb' => $string));

        /**
         * ------------------------------------
         * Doing encryption
         * ------------------------------------
         */
        $iv_size   = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
        $iv        = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        $crypt_text = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $string, MCRYPT_MODE_ECB, $iv);

        // freed the memory
        unset($string, $key, $iv);
        // save as bse64 encode safe
        $crypt_text = trim(Util::safeBase64Encode($crypt_text));

        /**
         * ------------------------------------
         * Inject Result of with sign
         * ------------------------------------
         */
        if (strlen($crypt_text) > 10) {
            return substr_replace($crypt_text, '_mCb=', 10, 0);
        } else {
            return substr_replace($crypt_text, '_mCb=', 2, 0);
        }
    }

    /**
     * Decrypt the string encryption
     * with mCrypt, make sure lib mCrypt is active by your php
     *
     * @param  mixed $string the value of cookies value
     * @param  mixed $hash
     *
     * @return mixed real cookie value
     */
    public static function decrypt($string, $hash = false)
    {
        // if has $string or invalid no value or not as string stop here
        if (!is_string($string) || strlen(trim($string)) < 4
            || (strlen($string) > 10 ? (substr($string, 10, 5) !== '_mCb=') : (substr($string, 2, 5) !== '_mCb='))
        ) {

            // check if mCrypt is not loaded and decrypt using alt decrypt
            if (is_string($string)
                && strlen(trim($string)) > 3
                && (strlen($string) > 10 ? (substr($string, 10, 5) === '_aCb=') : (substr($string, 2, 5) === '_aCb='))
            ) {
                return static::altDecrypt($string, $hash);
            }

            return null;
        }

        if (! extension_loaded('mCrypt')) {
            return null;
        }

        /**
         * Replace Injection 3 characters sign
         */
        $string = (strlen($string) > 10
            ? substr_replace($string, '', 10, 5)
            : substr_replace($string, '', 2, 5)
        );
        // this is base64 safe encoded?
        if (preg_match('/[^a-z0-9\+\/\=\-\_]/i', $string)) {
            return null;
        }

        /**
         * ------------------------------------
         * Safe Sanitized hash
         * ------------------------------------
         */
        (is_null($hash) || $hash === false) && $hash = '';
        // safe is use array or object as hash
        $hash        = Util::maybeSerialize($hash);

        /**
         * ------------------------------------
         * Set Key
         * ------------------------------------
         */
        $key         = pack('H*', sha1(sha256::hash($hash)));
        /**
         * pad to 24 length
         * on PHP 5.5 + need keylength 16, 24 or 32
         */
        $key         = str_pad($key, 24, "\0", STR_PAD_RIGHT);

        /**
         * Doing decode of input encryption
         */
        $crypted_text   = Util::safeBase64Decode($string);
        
        /**
         * ------------------------------------
         * Doing deryption
         * ------------------------------------
         */
        $iv_size     = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
        $iv          = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        $decrypted_text = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $crypted_text, MCRYPT_MODE_ECB, $iv);

        /**
         * unserialize the string, that before has been serialize
         */
        $decrypted_text = Util::maybeUnSerialize(trim($decrypted_text));

        /**
         * Check if value is array
         */
        if (is_array($decrypted_text) && array_key_exists('mcb', $decrypted_text)) {
            unset($string, $key, $iv);
            return $decrypted_text['mcb'];
        }

        // freed the memory
        unset($decrypted_text, $crypted_text, $string, $key, $iv);

        return null;
    }

    /* --------------------------------------------------------------------------------*
     |                             Alternative Encryption                              |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Alternative encryption using Pure PHP Libraries
     * @http://px.sklar.com/code.html/id=1287
     * Fix and added More Secure Method
     *
     * @param  mixed  $str  string to be encode
     * @param  string $pass the hash key
     * @return string       encryption string output
     */
    public static function altEncrypt($str, $pass = '')
    {
        /**
         * if empty values return null
         */
        if (!$str) {
            return null;
        }

        /**
         * ------------------------------------
         * Safe Sanitized hash
         * ------------------------------------
         */
        (is_null($pass) || $pass === false) && $pass = '';
        // safe is use array or object as hash
        $pass = Util::maybeSerialize($pass);
        if (!$pass) {
            $pass = sha1($pass);
        }

        // make an array values -> use key acb
        $str = serialize(array('acb' => $str));
        // rotate 13
        $str = pack('a*', Util::rotate($str.sha1(sha256::hash($pass)), 13));

        /**
         * Doing safe encode base 64
         */
        $str = Util::safeBase64Encode($str);

        /**
         * ------------------------------------
         * Doing convert string
         * ------------------------------------
         */
        $str_arr  = str_split($str);
        $add = 0;
        $div = strlen($str) / strlen($pass);
        $new_pass = '';
        while ($add <= $div) {
            $new_pass .= $pass;
            $add++;
        }
        $pass_arr = str_split($new_pass);
        $ascii = '';
        foreach ($str_arr as $key => $asc) {
            $pass_int = ord($pass_arr[$key]);
            $str_int = ord($asc);
            $int_add = $str_int + $pass_int;
            $ascii .= chr(($int_add+strlen($str)));
        }
        $ascii = trim(Util::safeBase64Encode($ascii));

        /**
         * ------------------------------------
         * Inject Result of with sign
         * ------------------------------------
         */
        if (strlen($ascii) > 10) {
            return substr_replace($ascii, '_aCb=', 10, 0);
        } else {
            return substr_replace($ascii, '_aCb=', 2, 0);
        }
    }

    /**
     * Alternative decryption using Pure PHP Libraries
     * @http://px.sklar.com/code.html/id=1287
     * Fix and added More Secure Method
     *
     * @param  string $string  string to be decode
     * @param  mixed  $pass     the hash key
     * @return mixed        decryption value output
     */
    public static function altDecrypt($string, $pass = '')
    {
        // if has $enc or invalid no value or not as string stop here
        if (!is_string($string) || strlen(trim($string)) < 4
            || (strlen($string) > 10 ? (substr($string, 10, 5) !== '_aCb=') : (substr($string, 2, 5) !== '_aCb='))
        ) {
            // check if mCrypt loaded and crypt using mCrypt
            if (is_string($string)
                && strlen(trim($string)) > 3
                && extension_loaded('mCrypt')
                && (strlen($string) > 10 ? (substr($string, 10, 5) === '_mCb=') : (substr($string, 2, 5) === '_mCb='))
            ) {
                return static::decrypt($string, $pass);
            }

            return null;
        }

        /**
         * Replace Injection 3 characters sign
         */
        $string = (strlen($string) > 10
            ? substr_replace($string, '', 10, 5)
            : substr_replace($string, '', 2, 5)
        );

        // this is base64 safe encoded?
        if (preg_match('/[^a-z0-9\+\/\=\-\_]/i', $string)) {
            return null;
        }

        /**
         * ------------------------------------
         * Safe Sanitized
         * ------------------------------------
         */
        (is_null($pass) || $pass === false) && $pass = '';
        // safe is use array orobject as hash
        $pass = Util::maybeSerialize($pass);
        if (!$pass) {
            $pass = sha1($pass);
        }
        
        /**
         * Doing decode of input encryption
         */
        $string = Util::safeBase64Decode($string);

        /**
         * ------------------------------------
         * Doing convert encrypted string
         * ------------------------------------
         */
        $enc_arr  = str_split($string);
        $add = 0;
        $div = strlen($string) / strlen($pass);
        $new_pass = '';
        while ($add <= $div) {
            $new_pass .= $pass;
            $add++;
        }
        $pass_arr = str_split($new_pass);
        $ascii ='';
        foreach ($enc_arr as $key => $asc) {
            $pass_int = ord($pass_arr[$key]);
            $enc_int = ord($asc);
            $str_int = $enc_int - $pass_int;
            $ascii .= chr(($str_int-strlen($string)));
        }

        /* --------------------------------
         * reversing
         * ------------------------------ */
        // unpack
        $unpack = unpack('a*', trim($ascii));
        /**
         * if empty return here
         */
        if (!$unpack) {
            return null;
        }

        // implode the unpacking array
        $unpack = implode('', (array) $unpack);
        /**
         * Doing decode of input encryption from unpacked
         */
        $unpack = Util::safeBase64Decode($unpack);

        /**
         * Reverse Rotate
         */
        $retval = Util::rotate($unpack, 13);
        /**
         * For some case packing returning invisible characters
         * remove it
         */
        $retval = Util::removeInvisibleCharacters($retval, false);
        // check if string less than 40 && match end of hash
        if (strlen($retval) < 40 || substr($retval, -40) !== sha1(sha256::hash($pass))) {
            return null;
        }
        // remove last 40 characters
        $retval = substr($retval, 0, (strlen($retval)-40));
        // check if result is not string it will be need to be unserialize
        $retval = Util::maybeUnSerialize($retval);

        /**
         * Check if value is array
         */
        if (is_array($retval) && array_key_exists('acb', $retval)) {
            return $retval['acb'];
        }

        // freed the memory
        unset($retval);

        return null;
    }
}
