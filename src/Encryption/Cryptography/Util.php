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

namespace Aufa\Encryption\Cryptography;

/**
 * Crypt Hash Utility
 * This is also use as Parent class for hash method sha1 & sha256
 */
class Util
{
    /**
     * Fills the zero values
     * @return int
     */
    public static function zeroFill($a, $b)
    {
        $z = hexdec(80000000);
        if ($z & $a) {
            $a = ($a>>1);
            $a &= (~$z & 0xffffffff);
            $a |= 0x40000000;
            $a = ($a >> ($b-1));
        } else {
            $a = ($a >> $b);
        }
        return $a;
    }

    /* --------------------------------------------------------------------------------*
     |                              Binary Convertion                                  |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Converting string into binary
     *
     * @param  string $string the string to convert
     * @return string
     */
    public static function str2bin($string)
    {
        if (is_array($string) || is_object($string)) {
            $type   = gettype($string);
            $caller =  next(debug_backtrace());
            $eror['line']  = $caller['line'];
            $eror['file']  = strip_tags($caller['file']);
            $error['type'] = E_USER_ERROR;
            trigger_error(
                "str2bin() expects parameter 1 to be string, "
                . $type
                . " given in <b>{$file}</b> on line <b>{$line}</b><br />\n",
                E_USER_ERROR
            );

            return;
        }

        if (strlen($string) <= 0) {
            return;
        }

        $string = str_split($string, 1);
        for ($i = 0, $n = count($string); $i < $n; ++$i) {
            $string[$i] = decbin(ord($string[$i]));
            $string[$i] = str_repeat("0", 8 - strlen($string[$i])) . $string[$i];
        }

        return implode("", $string);
    }

    /**
     * Converting binary string into normal string
     *
     * @param  string $string the string to convert
     * @return string
     */
    public static function bin2str($string)
    {
        if (is_array($string) || is_object($string)) {
            $type   = gettype($string);
            $caller =  next(debug_backtrace());
            $eror['line']  = $caller['line'];
            $eror['file']  = strip_tags($caller['file']);
            $error['type'] = E_USER_ERROR;
            trigger_error(
                "bin2str() expects parameter 1 to be string, "
                . $type
                . " given in <b>{$file}</b> on line <b>{$line}</b><br />\n",
                E_USER_ERROR
            );

            return;
        }

        if (strlen($string) <= 0) {
            return;
        }

        $string = str_split($string, 8); // NOTE: this function is PHP5 only
        for ($i = 0, $n = count($string); $i < $n; ++$i) {
            $string[$i] = chr(bindec($string[$i]));
        }

        return implode('', $string);
    }

    /**
     * split a byte-string into integer array values
     *
     * @return string
     */
    public static function byte2intSplit($input)
    {
        $l = strlen($input);
        if ($l <= 0) {
            // right...
            return 0;
        } elseif (($l % 4) != 0) {
            // invalid input
            return false;
        }
        $result = array();
        for ($i = 0; $i < $l; $i += 4) {
            $intbuild  = (ord($input[$i]) << 24);
            $intbuild += (ord($input[$i+1]) << 16);
            $intbuild += (ord($input[$i+2]) << 8);
            $intbuild += (ord($input[$i+3]));
            $result[] = $intbuild;
        }

        return $result;
    }

    /**
     * Abstract Create Hash
     *
     * @param string $str string to hash by child
     */
    public static function create($str)
    {
        return static::hash($str);
    }

    /**
     * Default hash method
     *
     * @param  string $string input string tobe hash
     * @return string         hash
     */
    public static function hash($string)
    {
    }

    /* --------------------------------------------------------------------------------*
     |                                  Serialized                                     |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Serialize data, if needed. @uses for ( uncompress serialize values )
     *
     * @param  mixed $data Data that might be serialized.
     * @return mixed A scalar data
     */
    public static function maybeSerialize($data)
    {
        if (is_array($data) || is_object($data)) {
            return @serialize($data);
        }

        // Double serialization is required for backward compatibility.
        if (static::isSerialized($data, false)) {
            return serialize($data);
        }

        return $data;
    }

    /**
     * Unserialize value only if it was serialized.
     *
     * @param  string $original Maybe unserialized original, if is needed.
     * @return mixed  Unserialized data can be any type.
     */
    public static function maybeUnserialize($original)
    {
        // don't attempt to unserialize data that wasn't serialized going in
        if (static::isSerialized($original)) {
            return @unserialize($original);
        }

        return $original;
    }

    /**
     * Check value to find if it was serialized.
     * If $data is not an string, then returned value will always be false.
     * Serialized data is always a string.
     *
     * @param  mixed $data   Value to check to see if was serialized.
     * @param  bool  $strict Optional. Whether to be strict about the end of the string. Defaults true.
     * @return bool  False if not serialized and true if it was.
     */
    public static function isSerialized($data, $strict = true)
    {
        /* if it isn't a string, it isn't serialized
         ------------------------------------------- */
        if (! is_string($data)) {
            return false;
        }

        $data = trim($data);

        if ('N;' == $data) {
            return true;
        }

        if (strlen($data) < 4 || ':' !== $data[1]) {
            return false;
        }

        if ($strict) {
            $lastc = substr($data, -1);
            if (';' !== $lastc && '}' !== $lastc) {
                return false;
            }

        } else {
            $semicolon = strpos($data, ';');
            $brace     = strpos($data, '}');

            // Either ; or } must exist.
            if (false === $semicolon && false === $brace
                || false !== $semicolon && $semicolon < 3
                || false !== $brace && $brace < 4
            ) {
                return false;
            }
        }

        $token = $data[0];
        switch ($token) {
            case 's':
                if ($strict) {
                    if ('"' !== substr($data, -2, 1)) {
                        return false;
                    }
                } elseif (false === strpos($data, '"')) {
                    return false;
                }
                // or else fall through
            case 'a':
            case 'O':
                return (bool) preg_match("/^{$token}:[0-9]+:/s", $data);

            case 'b':
            case 'i':
            case 'd':
                $end = $strict ? '$' : '';

                return (bool) preg_match("/^{$token}:[0-9.E-]+;$end/", $data);
        }

        return false;
    }

    /* --------------------------------------------------------------------------------*
     |                                  Encryption                                     |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Encode the values using base64_encode and replace some string
     * and could decode @uses safe_b64decode()
     *
     * @param  string $string
     * @return string
     */
    public static function safeBase64Encode($string)
    {
        $data = static::base64Encode($string);
        $data = str_replace(array('+','/','='), array('-', '_', ''), $data);

        return $data;
    }

    /**
     * Decode the safe_b64encode() of the string values
     *
     * @see safe_b64encode()
     *
     * @param  string $string
     * @return string
     */
    public static function safeBase64Decode($string)
    {
        $data = str_replace(array('-', '_'), array('+','/'), $string);
        $mod4 = strlen($data) % 4;
        if ($mod4) {
            $data .= substr('====', $mod4);
        }

        return static::base64Decode($data);
    }


    /**
     * Encode 64 Function as alternate function of base64_encode() if not exists
     *
     * @param  string $string
     * @return string
     */
    public static function base64Encode($string = '')
    {
        if (is_array($string) || is_object($string)) {
            $type   = gettype($string);
            $caller =  next(debug_backtrace());
            $eror['line']  = $caller['line'];
            $eror['file']  = strip_tags($caller['file']);
            $error['type'] = E_USER_ERROR;
            trigger_error(
                "base64Encode() expects parameter 1 to be string, "
                . $type
                . " given in <b>{$file}</b> on line <b>{$line}</b><br />\n",
                E_USER_ERROR
            );

            return;
        }
        /**
         * Use Internal
         */
        if (function_exists('base64_encode')) {
            return base64_encode($string);
        }
        if (strlen($string) <= 0) {
            return '';
        }

        $binval  = static::str2bin($string);
        $final = "";
        $start = 0;
        while ($start < strlen($binval)) {
            if (strlen(substr($binval, $start)) < 6) {
                $binval .= str_repeat("0", 6 - strlen(substr($binval, $start)));
            }
            $tmp = bindec(substr($binval, $start, 6));
            if ($tmp < 26) {
                $final .= chr($tmp + 65);
            } elseif ($tmp > 25 && $tmp < 52) {
                $final .= chr($tmp + 71);
            } elseif ($tmp == 62) {
                $final .= "+";
            } elseif ($tmp == 63) {
                $final .= "/";
            } elseif (!$tmp) {
                $final .= "A";
            } else {
                $final .= chr($tmp - 4);
            }
            $start += 6;
        }
        if (strlen($final) % 4 > 0) {
            $final .= str_repeat("=", 4 - strlen($final) % 4);
        }

        return $final;
    }

    /**
     * Decode 64 Function as alternate function of base64_decode() if not exists
     *     Maybe some result it will be different for some case
     *
     * @param  string $string
     * @return string
     */
    public static function base64Decode($string)
    {
        if (is_array($string) || is_object($string)) {
            $type   = gettype($string);
            $caller =  next(debug_backtrace());
            $eror['line']  = $caller['line'];
            $eror['file']  = strip_tags($caller['file']);
            $error['type'] = E_USER_ERROR;
            trigger_error(
                "base64Decode() expects parameter 1 to be string, "
                . $type
                . " given in <b>{$file}</b> on line <b>{$line}</b><br />\n",
                E_USER_ERROR
            );

            return;
        }

        /**
         * Use Internal
         */
        if (function_exists('base64_decode')) {
            return base64_decode($string);
        }

        if (strlen($string) <= 0) {
            return '';
        }

        $keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        $chr1 = $chr2 = $chr3 = "";
        $enc1 = $enc2 = $enc3 = $enc4 = "";
        $i = 0;
        $output = "";
        // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
        $string = preg_replace("[^A-Za-z0-9\+\/\=]", "", $string);
        do {
            $enc1 = strpos($keyStr, substr($string, $i++, 1));
            $enc2 = strpos($keyStr, substr($string, $i++, 1));
            $enc3 = strpos($keyStr, substr($string, $i++, 1));
            $enc4 = strpos($keyStr, substr($string, $i++, 1));
            $chr1 = ($enc1 << 2) | ($enc2 >> 4);
            $chr2 = (($enc2 & 15) << 4) | ($enc3 >> 2);
            $chr3 = (($enc3 & 3) << 6) | $enc4;
            $output = $output . chr((int) $chr1);
            if ($enc3 != 64) {
                $output = $output . chr((int) $chr2);
            }
            if ($enc4 != 64) {
                $output = $output . chr((int) $chr3);
            }
            $chr1 = $chr2 = $chr3 = "";
            $enc1 = $enc2 = $enc3 = $enc4 = "";
        } while ($i < strlen($string));

        return urldecode($output);
    }

    /* --------------------------------------------------------------------------------*
     |                              Extended Helpers                                   |
     |---------------------------------------------------------------------------------|
     */

    /**
     * Rotate each string characters by n positions in ASCII table
     * To encode use positive n, to decode - negative.
     * With n = 13 (ROT13), encode and decode n can be positive.
     * @see  {@link http://php.net/str_rot13}
     *
     * @param  string  $string
     * @param  integer $n
     * @return string
     */
    public static function rotate($string, $n = 13)
    {
        $length = strlen($string);
        $result = '';

        for ($i = 0; $i < $length; $i++) {
            $ascii = ord($string{$i});

            $rotated = $ascii;

            if ($ascii > 64 && $ascii < 91) {
                $rotated += $n;
                $rotated > 90 && $rotated += -90 + 64;
                $rotated < 65 && $rotated += -64 + 90;
            } elseif ($ascii > 96 && $ascii < 123) {
                $rotated += $n;
                $rotated > 122 && $rotated += -122 + 96;
                $rotated < 97 && $rotated  += -96 + 122;
            }

            $result .= chr($rotated);
        }

        return $result;
    }

    /**
     * Remove Invisible Characters
     *
     * This prevents sandwiching null characters
     * between ascii characters, like Java\0script.
     *
     * @access  public
     * @param   string
     * @return string
     */
    public static function removeInvisibleCharacters($str, $url_encoded = true)
    {
        $non_displayables = array();

        // every control character except newline (dec 10)
        // carriage return (dec 13), and horizontal tab (dec 09)

        if ($url_encoded) {
            $non_displayables[] = '/%0[0-8bcef]/';  // url encoded 00-08, 11, 12, 14, 15
            $non_displayables[] = '/%1[0-9a-f]/';   // url encoded 16-31
        }

        $non_displayables[] = '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/S';   // 00-08, 11, 12, 14-31, 127

        do {
            $str = preg_replace($non_displayables, '', $str, -1, $count);
        } while ($count);

        return $str;
    }
}
