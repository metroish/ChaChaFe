package com.midcielab;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ChaChaFeTest.
 */
class ChaChaFeTest {

    private static final int BUFFER_SIZE = 8192;

    @Test
    void testChaChaFe() throws IOException, NoSuchAlgorithmException {
        String plain = "plan.txt";
        String enc = "enc.txt";
        String dec = "dec.txt";

        Files.deleteIfExists(new File(plain).toPath());
        Files.deleteIfExists(new File(enc).toPath());
        Files.deleteIfExists(new File(dec).toPath());

        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] data = new byte[BUFFER_SIZE];
        sr.nextBytes(data);
        Files.write(Paths.get(plain), data, StandardOpenOption.CREATE);

        String[] encPara = {"e", "password5566", plain, enc};
        assertTrue(new ChaChaFe(encPara).process());

        String[] decPara = {"d", "password5566", enc, dec};
        assertTrue(new ChaChaFe(decPara).process());
    }
}
