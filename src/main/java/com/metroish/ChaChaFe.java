package com.metroish;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
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
    private static final int CHECKSUM_LENGTH_BYTE = 32;
    private static final int BUFFER_SIZE = 16384;
    private static final int ACTION_INDEX = 0;
    private static final int PASSWORD_INDEX = 1;
    private static final int SOURCE_PATH_INDEX = 2;
    private static final int DESTINATION_INDEX = 3;
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
                System.out.println("Not found ChaCha20 algorithm. Java version needs above than 11.");
                e.printStackTrace();
            }
        } else {
            System.out.println("Input parameters should be: e/d password soure_path destnation_path");
        }
    }

    /**
     * Process file encryption/decryption.
     */
    public boolean process() {
        boolean result = false;
        if (this.cipher == null) {
            System.out.println("Nothing happened.");
        }
        if ("e".equals(this.action)) {
            result = encryption();
        } else if ("d".equals(this.action)) {
            result = decryption();
        } else {
            System.out.println("First parameter should be 'e' or 'd'.");
        }
        if (result) {
            System.out.println("Process completion. Everything is ok.");
        } else {
            System.out.println("Process fail.");
        }
        return result;
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

    private boolean encryption() {
        System.out.println("Encryption start: " + srcFile);
        byte[] checksum;
        try {
            checksum = sha256(srcFile);
        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("Gather file checksum fail.");
            e.printStackTrace();
            return false;
        }

        try (FileInputStream fis = new FileInputStream(srcFile);
                FileOutputStream fos = new FileOutputStream(destFile);
                CipherOutputStream cos = new CipherOutputStream(fos, this.cipher);) {

            byte[] nonce = getRandomBytes(NONCE_LENGTH_BYTE);
            byte[] salt = getRandomBytes(SALT_LENGTH_BYTE);

            System.out.println("Encryption nonce: " + convertBytesToHex(nonce));
            System.out.println("Encryption salt: " + convertBytesToHex(salt));
            System.out.println("Encryption checksum: " + convertBytesToHex(checksum));

            fos.write(nonce);
            fos.write(salt);
            fos.write(checksum);

            initCipher(nonce, salt, Cipher.ENCRYPT_MODE);

            byte[] buffer = new byte[BUFFER_SIZE];
            int nread;
            while ((nread = fis.read(buffer)) > 0) {
                cos.write(buffer, 0, nread);
            }
            cos.flush();
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException
                | InvalidAlgorithmParameterException e) {
            System.out.println("Encryption fail.");
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private boolean decryption() {
        System.out.println("Decryption start: " + srcFile);
        byte[] checksum = new byte[CHECKSUM_LENGTH_BYTE];

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
            fis.read(checksum);

            System.out.println("Decryption nonce: " + convertBytesToHex(nonce));
            System.out.println("Decryption salt: " + convertBytesToHex(salt));
            System.out.println("Decryption checksum: " + convertBytesToHex(checksum));

            initCipher(nonce, salt, Cipher.DECRYPT_MODE);

            byte[] buffer = new byte[BUFFER_SIZE];
            int nread;
            while ((nread = fis.read(buffer)) > 0) {
                cos.write(buffer, 0, nread);
            }
            cos.flush();
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException
                | InvalidAlgorithmParameterException e) {
            System.out.println("Decrypt fail.");
            e.printStackTrace();
            return false;
        }

        try {
            byte[] decFileChecksum = sha256(destFile);
            return Arrays.equals(checksum, decFileChecksum);
        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("Verify checksum fail.");
            e.printStackTrace();
            return false;
        }
    }

    private String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }

    private byte[] sha256(String digestFile) throws IOException, NoSuchAlgorithmException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int count;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(digestFile));
        while ((count = bis.read(buffer)) > 0) {
            md.update(buffer, 0, count);
        }
        bis.close();
        return md.digest();
    }

    /** Main. */
    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        new ChaChaFe(args).process();
        long end = System.currentTimeMillis();
        System.out.println("Process with " + (end - start) + " ms.");
    }
}
