package com.midcielab;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaChaFe - simple implementation of file encryption/decryption with
 * ChaCha20-Poly1305 algorithm.
 */
public final class ChaChaFe {

    private static final int KEY_ITERATION = 90001;
    private static final int KEY_BIT_LENGTH = 256;
    private static final int NONCE_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 32;
    private static final int BUFFER_SIZE = 16384;
    private static final int ACTION_INDEX = 1;
    private static final int PASSWORD_INDEX = 2;
    private static final int SOURCE_PATH_INDEX = 3;
    private static final int DESTINATION_INDEX = 4;
    private static final int PARAMETER_NUMBER = 4;
    private String action;
    private String password;
    private String srcFile;
    private String destFile;
    private Cipher cipher;

    /**
     * ChaChaFe constructor.
     * @param args
     *             String array with four element inside
     *             args[0] is action, should be "e" or "d"
     *             args[1] is password
     *             args[2] is source file path
     *             args[3] is destination file path
     */
    public ChaChaFe(String[] args) {
        if (args.length == PARAMETER_NUMBER) {
            this.action = args[ACTION_INDEX];
            this.password = args[PASSWORD_INDEX];
            this.srcFile = args[SOURCE_PATH_INDEX];
            this.destFile = args[DESTINATION_INDEX];
            try {
                this.cipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Please check input parameters.");
        }
    }

    /**
     * Process file encryption/decryption.
     */
    public void process() {
        if (this.cipher == null) {
            System.out.println("Nothing happened.");
            return;
        }
        if ("e".equals(this.action)) {
            encryption();
        } else if ("d".equals(this.action)) {
            decryption();
        } else {
            System.out.println("First parameter should be 'e' or 'd'.");
        }
    }

    private SecretKey getKey(String passwd, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        KeySpec spec = new PBEKeySpec(passwd.toCharArray(), salt, KEY_ITERATION, KEY_BIT_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "ChaCha20");
    }

    private byte[] getRandomBytes(int length) {
        byte[] bt = new byte[length]; // 12 byte (96 bit) for nonce, 32 (256 bit) byte for salt
        new SecureRandom().nextBytes(bt);
        return bt;
    }

    private void initCipher(byte[] nonce, byte[] salt, int mode) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {

        SecretKey key = getKey(password, salt);
        IvParameterSpec iv = new IvParameterSpec(nonce);
        this.cipher.init(mode, key, iv);
    }

    private void encryption() {

        try (FileInputStream fis = new FileInputStream(srcFile);
                FileOutputStream fos = new FileOutputStream(destFile);
                CipherOutputStream cos = new CipherOutputStream(fos, this.cipher);) {

            byte[] nonce = getRandomBytes(NONCE_LENGTH_BYTE);
            byte[] salt = getRandomBytes(SALT_LENGTH_BYTE);

            System.out.println("encryption nonce: " + convertBytesToHex(nonce));
            System.out.println("encryption salt: " + convertBytesToHex(salt));

            fos.write(nonce);
            fos.write(salt);

            initCipher(nonce, salt, Cipher.ENCRYPT_MODE);

            byte[] buffer = new byte[BUFFER_SIZE];
            int nread;
            while ((nread = fis.read(buffer)) > 0) {
                cos.write(buffer, 0, nread);
            }
            cos.flush();
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException
                | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private void decryption() {

        // Don't use CipherInputStream for large file
        // performance is poor due to 512 byte internal buffer
        // private byte[] ibuffer = new byte[512]

        try (FileInputStream fis = new FileInputStream(srcFile);
                // CipherInputStream cis = new CipherInputStream(fis, this.cipher);
                FileOutputStream fos = new FileOutputStream(destFile);
                CipherOutputStream cos = new CipherOutputStream(fos, this.cipher);) {

            byte[] nonce = new byte[NONCE_LENGTH_BYTE];
            byte[] salt = new byte[SALT_LENGTH_BYTE];

            fis.read(nonce);
            fis.read(salt);

            System.out.println("decryption nonce: " + convertBytesToHex(nonce));
            System.out.println("decryption salt: " + convertBytesToHex(salt));

            initCipher(nonce, salt, Cipher.DECRYPT_MODE);

            byte[] buffer = new byte[BUFFER_SIZE];
            int nread;
            while ((nread = fis.read(buffer)) > 0) {
                cos.write(buffer, 0, nread);
            }
            cos.flush();
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException
                | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }

    private String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }

    /** Main. */
    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        new ChaChaFe(args).process();
        long end = System.currentTimeMillis();
        System.out.println("Process with " + (end - start) + " miniseconds.");
    }
}
