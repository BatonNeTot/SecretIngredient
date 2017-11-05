package com.notjuststudio.secretingredient;

import com.sun.istack.internal.NotNull;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Recipe {

    public static final String RSA = "RSA/ECB/PKCS1Padding";
    public static final String AES = "AES/ECB/PKCS5Padding";

    private static final String RSA_SHORT = "RSA";
    private static final String AES_SHORT = "AES";

    public static KeyPair generateRSAPair() {
        final int size = 2048;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_SHORT);
            keyPairGenerator.initialize(size);
            return keyPairGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey createRSAPublicKey(@NotNull final byte[] key) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_SHORT);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new GeneratingKeyException(e);
        }
    }

    public static PrivateKey createRSAPrivateKey(@NotNull final byte[] key) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_SHORT);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new GeneratingKeyException(e);
        }
    }

    public static byte[] encryptRSA(@NotNull final Key key, @NotNull final byte[] message) {
        try {
            final Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            if (message.length <= 245) {
                return cipher.doFinal(message);
            } else {

                final int count = message.length / 245 + (message.length % 245 != 0 ? 1 : 0);

                final byte[] result = new byte[count * 256];

                final int taillessCount = count - 1;

                final byte[] tmp = new byte[245];

                System.arraycopy(message, 0, tmp, 0, 245);
                System.arraycopy(cipher.doFinal(tmp), 0, result, 0, 256);

                for (int i = 1; i < taillessCount; i++) {
                    System.arraycopy(message, i * 245, tmp, 0, 245);
                    System.arraycopy(cipher.doFinal(tmp), 0, result, i * 256, 256);
                }

                final int mass = taillessCount * 245;
                final byte[] tailTmp = new byte[message.length - mass];
                System.arraycopy(message, mass, tailTmp, 0, tailTmp.length);
                System.arraycopy(cipher.doFinal(tailTmp),0, result, taillessCount * 256, 256);

                return result;
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CryptographicException(e);
        }
    }

    public static byte[] decryptRSA(@NotNull final Key key, @NotNull final byte[] message) {
        try {
            final Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.DECRYPT_MODE, key);

            if (message.length <= 256) {
                return cipher.doFinal(message);
            } else {
                final int taillessCount = message.length / 256 - 1;

                final byte[] taillessResult = new byte[taillessCount * 245];

                final byte[] tmp = new byte[256];

                System.arraycopy(message, 0, tmp, 0, 256);
                System.arraycopy(cipher.doFinal(tmp), 0, taillessResult, 0, 245);

                for (int i = 1; i < taillessCount; i++) {
                    System.arraycopy(message, i * 256, tmp, 0, 256);
                    System.arraycopy(cipher.doFinal(tmp), 0, taillessResult, i * 245, 245);
                }

                System.arraycopy(message, taillessCount * 256, tmp, 0,256);

                final byte[] tail = cipher.doFinal(tmp);

                final byte[] result = new byte[taillessResult.length + tail.length];

                System.arraycopy(taillessResult, 0, result, 0, taillessResult.length);
                System.arraycopy(tail, 0, result, taillessResult.length, tail.length);

                return result;
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CryptographicException(e);
        }
    }

    public static SecretKey generateAESKey() {
        final int size = 128;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_SHORT);
            keyGenerator.init(size);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey createAESKey(@NotNull final byte[] key) {
        return new SecretKeySpec(key, RSA_SHORT);
    }

    public static byte[] encryptAES(@NotNull final Key key, @NotNull final byte[] message) {
        try {
            final Cipher cipher = Cipher.getInstance(AES);

            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(message);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CryptographicException(e);
        }
    }

    public static byte[] decryptAES(@NotNull final Key key, @NotNull final byte[] message) {
        try {
            final Cipher cipher = Cipher.getInstance(AES);

            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(message);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CryptographicException(e);
        }
    }

}
