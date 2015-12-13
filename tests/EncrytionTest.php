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

class EncryptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Default salt
     * @var string
     */
    public $salt = 'salt';

    /**
     * Default Test String to encrypt
     * @var string
     */
    public $string_encrypt = 'test';

    /**
     * Using default mcrypt Encryption
     * @return string
     */
    public function testEncryptionDefault()
    {
        return Encryption::encrypt($this->string_encrypt);
    }

    /**
     * Using default mcrypt Encryption with salt key
     * @return string
     */
    public function testEncryptionDefaultWithSalt()
    {
        return Encryption::encrypt($this->string_encrypt, $this->salt);
    }

    /**
     * Using Alternative Encryption
     * @return string
     */
    public function testEncryptionAlternative()
    {
        return Encryption::altEncrypt($this->string_encrypt);
    }

    /**
     * Using Alternative Encryption with salt
     * @return string
     */
    public function testEncryptionAlternativeWithSalt()
    {
        return Encryption::altEncrypt($this->string_encrypt, $this->salt);
    }

    /**
     * Decrypt the default encryption
     */
    public function testDecryptionDefault()
    {
        return Encryption::decrypt(
            $this->testEncryptionDefault()
        );
    }

    /**
     * Decrypt the alternative encryption
     */
    public function testDecryptionAlternative()
    {
        return Encryption::decrypt(
            $this->testEncryptionAlternative()
        );
    }

    /**
     * Decrypt the default encryption with salt
     */
    public function testDecryptionDefaultWithSalt()
    {
        return Encryption::decrypt(
            $this->testEncryptionDefaultWithSalt(),
            $this->salt
        );

    }

    /**
     * Decrypt the alternative encryption with salt
     */
    public function testDecryptionAlternativeWithSalt()
    {
        return Encryption::decrypt(
            $this->testEncryptionAlternativeWithSalt(),
            $this->salt
        );
    }

    /**
     * Test Decryption Equalities
     */
    public function testDecryptionAllEqualities()
    {
        $decrypt1 = $this->testDecryptionDefault();
        $decrypt2 = $this->testDecryptionAlternative();
        $decrypt3 = $this->testDecryptionDefaultWithSalt();
        $decrypt4 = $this->testDecryptionAlternativeWithSalt();

        /**
         * Asserting Equals
         */
        $this->assertEquals(
            $decrypt1,
            $this->string_encrypt
        );

        /**
         * Asserting Equals
         */
        $this->assertEquals(
            $decrypt1,
            $decrypt2
        );

        /**
         * Asserting Equals
         */
        $this->assertEquals(
            $decrypt1,
            $decrypt3
        );

        /**
         * Asserting Equals
         */
        $this->assertEquals(
            $decrypt1,
            $decrypt4
        );
    }

    /**
     * Invalid decryption
     * @return null
     */
    public function testDecryptionNull()
    {
        $decrypt = Encryption::decrypt(
            $this->testEncryptionAlternativeWithSalt(),
            'invalid salt'
        );

        /**
         * Asserting Null
         */
        $this->assertNull(
            $decrypt
        );

        return $decrypt;
    }

    /**
     * Test Not equalities
     */
    public function testNotEquals()
    {
        $this->assertNotEquals(
             $this->testEncryptionAlternativeWithSalt(),
             $this->testDecryptionNull()
        );
    }
}
