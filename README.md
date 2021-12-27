# ChaChaFe

Simple implementation of file encryption/decryption with ChaCha20-Poly1305 algorithm

## Note

Be aware that decrypting large file may cause OOM due to internal implementation of ChaCha20-Poly1305

EngineAEADDec class use an ByteArrayOutputStream with 1024 bytes buffer to write out decrypted bytes internal

- ByteArrayOutputStream objects are created with a default buffer of size 32
  - when call the write method
    - call ensureCapacity to check that the buffer has enough space to write the bytes
    - If there is not enough space
      - call grow to enlarge the space of the buffer
        - defines the size (current + new to write) to allocates a new buffer and calls Arrays.copyOf from old buffer to the new one
          - this will exhaust the available memory
- if chunck buffer is 2048
  - 1st call -> ByteArrayOutputStream internal buffer will be from 32 to 2048
  - 2nd call -> ByteArrayOutputStream internal buffer will be 2*2048
  - 3rd call -> ByteArrayOutputStream internal buffer will be 2^2*2048

```java
Exception in thread "main" java.lang.OutOfMemoryError: Java heap space
        at java.base/java.util.Arrays.copyOf(Arrays.java:3537)
        at java.base/java.io.ByteArrayOutputStream.ensureCapacity(ByteArrayOutputStream.java:100)
        at java.base/java.io.ByteArrayOutputStream.write(ByteArrayOutputStream.java:130)
        at java.base/com.sun.crypto.provider.ChaCha20Cipher$EngineAEADDec.doUpdate(ChaCha20Cipher.java:1351)
        at java.base/com.sun.crypto.provider.ChaCha20Cipher.engineUpdate(ChaCha20Cipher.java:641)
        at java.base/javax.crypto.Cipher.update(Cipher.java:1872)
        at com.midcielab.ChaChaFe.decryption(ChaChaFe.java:197)
        at com.midcielab.ChaChaFe.process(ChaChaFe.java:85)
        at com.midcielab.ChaChaFe.main(ChaChaFe.java:247)
```

```java
// snippet for cipher update dofinal
while ((length = fis.read(buffer)) != -1) {
    byte[] tmp = cipher.update(buffer, 0, length);
    if (tmp != null) {
        fos.write(tmp);
    }        
}
byte[] finalTmp = cipher.doFinal();
if (finalTmp != null) {
    fos.write(finalTmp);
}
```
