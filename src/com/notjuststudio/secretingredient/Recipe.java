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

    public static final int RSA_KEY_SIZE = 2048;

    public static KeyPair generateRSAPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_SHORT);
            keyPairGenerator.initialize(RSA_KEY_SIZE);
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

    public static final int RSA_DECRYPTED_BLOCK_SIZE = 245;
    public static final int RSA_ENCRYPTED_BLOCK_SIZE = 256;

    public static byte[] encryptRSA(@NotNull final Key key, @NotNull final byte[] message) {
        try {
            final Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.ENCRYPT_MODE, key);

            if (message.length <= RSA_DECRYPTED_BLOCK_SIZE) {
                return cipher.doFinal(message);
            } else {

                final int count = (message.length + RSA_DECRYPTED_BLOCK_SIZE - 1) / RSA_DECRYPTED_BLOCK_SIZE;

                final byte[] result = new byte[count * RSA_ENCRYPTED_BLOCK_SIZE];

                final int taillessCount = count - 1;

                final byte[] tmp = new byte[RSA_DECRYPTED_BLOCK_SIZE];

                System.arraycopy(message, 0, tmp, 0, RSA_DECRYPTED_BLOCK_SIZE);
                System.arraycopy(cipher.doFinal(tmp), 0, result, 0, RSA_ENCRYPTED_BLOCK_SIZE);

                for (int i = 1; i < taillessCount; i++) {
                    System.arraycopy(message, i * RSA_DECRYPTED_BLOCK_SIZE, tmp, 0, RSA_DECRYPTED_BLOCK_SIZE);
                    System.arraycopy(cipher.doFinal(tmp), 0, result, i * RSA_ENCRYPTED_BLOCK_SIZE, RSA_ENCRYPTED_BLOCK_SIZE);
                }

                final int mass = taillessCount * RSA_DECRYPTED_BLOCK_SIZE;
                final byte[] tailTmp = new byte[message.length - mass];
                System.arraycopy(message, mass, tailTmp, 0, tailTmp.length);
                System.arraycopy(cipher.doFinal(tailTmp),0, result, taillessCount * RSA_ENCRYPTED_BLOCK_SIZE, RSA_ENCRYPTED_BLOCK_SIZE);

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

            if (message.length <= RSA_ENCRYPTED_BLOCK_SIZE) {
                return cipher.doFinal(message);
            } else {
                final int taillessCount = message.length / RSA_ENCRYPTED_BLOCK_SIZE - 1;

                final byte[] taillessResult = new byte[taillessCount * RSA_DECRYPTED_BLOCK_SIZE];

                final byte[] tmp = new byte[RSA_ENCRYPTED_BLOCK_SIZE];

                System.arraycopy(message, 0, tmp, 0, RSA_ENCRYPTED_BLOCK_SIZE);
                System.arraycopy(cipher.doFinal(tmp), 0, taillessResult, 0, RSA_DECRYPTED_BLOCK_SIZE);

                for (int i = 1; i < taillessCount; i++) {
                    System.arraycopy(message, i * RSA_ENCRYPTED_BLOCK_SIZE, tmp, 0, RSA_ENCRYPTED_BLOCK_SIZE);
                    System.arraycopy(cipher.doFinal(tmp), 0, taillessResult, i * RSA_DECRYPTED_BLOCK_SIZE, RSA_DECRYPTED_BLOCK_SIZE);
                }

                System.arraycopy(message, taillessCount * RSA_ENCRYPTED_BLOCK_SIZE, tmp, 0,RSA_ENCRYPTED_BLOCK_SIZE);

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

    public static final int AES_KEY_SIZE = 128;

    public static SecretKey generateAESKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_SHORT);
            keyGenerator.init(AES_KEY_SIZE);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey createAESKey(@NotNull final byte[] key) {
        return new SecretKeySpec(key, AES_SHORT);
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
