<?php
/**
 * Aufa Encryption
 * This Library create encryption string and reverse it using mcrypt if possble
 *     if mcrypt not exists wil be use alternative encryption
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
use Aufa\Encryption\Cryptography\sha1;

/**
 * Encryption Instance class
 *
 * usage :
 *     (using mcrypt if possible)
 *     Aufa\Encryption\Encryption::encrypt('string to encrypt', 'saltkey');
 *     (using alternative mcrypt)
 *     Aufa\Encryption\Encryption::altEncrypt('string to encrypt', 'saltkey');
 *     (decryption)
 *     Aufa\Encryption\Encryption::decrypt('string to decrypt', 'saltkey');
 *
 */
class Encryption
{
    /* --------------------------------------------------------------------------------*
     |                              Encryption Mcrypt                                  |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Current version
     */
    const VERSION = '1.0';

    /**
     * Encrypt the string
     * with mcrypt, make sure lib mcrypt is active by your php
     *
     * @param  mixed  $value the value of string to encryption
     * @return string
     */
    public static function encrypt($string, $hash = false)
    {
        if (!$string) {
            return null;
        }

        /**
         * Using Alternative Encryption
         */
        if (! extension_loaded('mcrypt')) {
            return static::altEncrypt($string, $hash);
        }

        /**
         * ------------------------------------
         * Safe Sanitized
         * ------------------------------------
         */
        (is_null($hash) || $hash === false) && $hash = '';
        // safe is use array or object as hash
        $hash      = Util::maybeSerialize($hash);
        // serialize the string , avoid array / object being saved
        $string    = $string; // check if is array or object
        $key       = pack('H*', sha1::hash(sha256::hash($hash)));
        // pad to 24 length
        $key       = str_pad($key, 24, "\0", STR_PAD_RIGHT);
        $iv_size   = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
        $iv        = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        // create array as content
        // this is for great opinion that values has already encrypted
        $string    = serialize(array('mcb' => $string));
        $crypttext = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $string, MCRYPT_MODE_ECB, $iv);
        unset($string, $key, $iv);
        $crypttext = trim(Util::safeBase64Encode($crypttext));
        if (strlen($crypttext) > 10) {
            return substr_replace($crypttext, 'mCb', 10, 0);
        } else {
            return substr_replace($crypttext, 'mCb', 2, 0);
        }
    }

    /**
     * Decrypt the string encryption
     * with mcrypt, make sure lib mcrypt is active by your php
     *
     * @param  mixed $value the value of cookies value
     * @return mixed real cookie value
     */
    public static function decrypt($string, $hash = false)
    {
        // if has $string or invalid no value or not as string stop here
        if (!is_string($string) || strlen(trim($string)) < 4
            || (strlen($string) > 10 ? (strpos($string, 'mCb') !== 10) : (strpos($string, 'mCb') !== 2))
        ) {
            // check if mcrypt is not loaded and decrypt using alt decrypt
            if (is_string($string)
                && strlen(trim($string)) > 3
                && extension_loaded('mcrypt')
                && (strlen($string) > 10 ? (strpos($string, 'aCb') === 10) : (strpos($string, 'aCb') === 2))
            ) {
                return static::altDecrypt($string, $hash);
            }

            return null;
        }

        // replace
        $string = (strlen($string) > 10
            ? substr_replace($string, '', 10, 3)
            : substr_replace($string, '', 2, 3)
        );

        // this is base64base safeencoded
        if (preg_match('/[^a-z0-9\+\/\=\-\_]/i', $string)) {
            return null;
        }

        /**
         * ------------------------------------
         * Safe Sanitized
         * ------------------------------------
         */
        (is_null($hash) || $hash === false) && $hash = '';
        // safe is use array or object as hash
        $hash        = Util::maybeSerialize($hash);

        $crypttext   = Util::safeBase64Decode($string);
        $key         = pack('H*', sha1::hash(sha256::hash($hash)));
        // pad to 24 length
        $key         = str_pad($key, 24, "\0", STR_PAD_RIGHT);
        $iv_size     = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
        $iv          = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        $decrypttext = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $crypttext, MCRYPT_MODE_ECB, $iv);

        // unserialize the string, that before has been serialize
        $decrypttext = Util::maybeUnserialize(trim($decrypttext));
        /**
         * Check if value is array
         */
        if (is_array($decrypttext) && array_key_exists('mcb', $decrypttext)) {
            unset($string, $key, $iv);
            return $decrypttext['mcb'];
        }
        unset($decrypttext, $crypttext, $string, $key, $iv);
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
        // if empty string $str return null
        if (!$str) {
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
            $pass = sha1::hash($pass);
        }

        // check if string is not string or need to be serialize
        $str = serialize(array('acb' => $str));
        // rotate 13
        $str = pack('a*', Util::rotate($str.sha1::hash(sha256::hash($pass)), 13));
        $str = Util::safeBase64Encode($str);
        $str_arr  = str_split($str);
        $pass_arr = str_split($pass);
        $add = 0;
        $div = strlen($str) / strlen($pass);
        $newpass = '';
        while ($add <= $div) {
            $newpass .= $pass;
            $add++;
        }
        $pass_arr = str_split($newpass);
        $ascii = '';
        foreach ($str_arr as $key => $asc) {
            $pass_int = ord($pass_arr[$key]);
            $str_int = ord($asc);
            $int_add = $str_int + $pass_int;
            $ascii .= chr(($int_add+strlen($str)));
        }
        $ascii = trim(Util::safeBase64Encode($ascii));
        if (strlen($ascii) > 10) {
            return substr_replace($ascii, 'aCb', 10, 0);
        } else {
            return substr_replace($ascii, 'aCb', 2, 0);
        }
    }

    /**
     * Alternative decryption using Pure PHP Libraries
     * @http://px.sklar.com/code.html/id=1287
     * Fix and added More Secure Method
     *
     * @param  string $str  string to be decode
     * @param  string $pass the hash key
     * @return mixed        decryption value output
     */
    public static function altDecrypt($enc, $pass = '')
    {
        // if has $enc or invalid no value or not as string stop here
        if (!is_string($enc) || strlen(trim($enc)) < 4
            || (strlen($enc) > 10 ? (strpos($enc, 'aCb') !== 10) : (strpos($enc, 'aCb') !== 2))
        ) {
            // check if mcrypt loaded and crypt using mcrypt
            if (is_string($enc)
                && strlen(trim($enc)) > 3
                && extension_loaded('mcrypt')
                && (strlen($enc) > 10 ? (strpos($enc, 'mCb') === 10) : (strpos($enc, 'mCb') === 2))
            ) {
                return static::decrypt($enc, $pass);
            }
            return null;
        }

        // replace
        $enc = (strlen($enc) > 10
            ? substr_replace($enc, '', 10, 3)
            : substr_replace($enc, '', 2, 3)
        );

        // this is base64base safeencoded
        if (preg_match('/[^a-z0-9\+\/\=\-\_]/i', $enc)) {
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
            $pass = sha1::hash($pass);
        }
        // decode
        $enc = Util::safeBase64Decode($enc);

        $enc_arr  = str_split($enc);
        $pass_arr = str_split($pass);
        $add = 0;
        $div = strlen($enc) / strlen($pass);
        $newpass = '';
        while ($add <= $div) {
            $newpass .= $pass;
            $add++;
        }
        $pass_arr = str_split($newpass);
        $ascii ='';
        foreach ($enc_arr as $key => $asc) {
            $pass_int = ord($pass_arr[$key]);
            $enc_int = ord($asc);
            $str_int = $enc_int - $pass_int;
            $ascii .= chr(($str_int-strlen($enc)));
        }

        /* --------------------------------
         * reversing
         * ------------------------------ */
        // unpack
        $unpack = unpack('a*', trim($ascii));

        // if empty
        if (!$unpack) {
            return null;
        }
        // implode the unpacking array
        $unpack = implode('', (array) $unpack);
        // return $unpack;
        $unpack = Util::safeBase64Decode($unpack);
        // rotate 13
        $retval = Util::rotate($unpack, 13);
        // check if string less than 40 && match end of hash
        if (strlen($retval) < 40 || substr($retval, -40) !== sha1::hash(sha256::hash($pass))) {
            return;
        }
        $retval = substr($retval, 0, (strlen($retval)-40));
        // check if string is not string or need to be serialize
        $retval = Util::maybeUnserialize($retval);
        if (is_array($retval) && array_key_exists('acb', $retval)) {
            return $retval['acb'];
        }
        unset($retval);

        return null;
    }
}
