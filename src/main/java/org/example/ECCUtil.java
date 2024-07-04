package org.example;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.security.*;

public class ECCUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static KeyPair generateECCKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ECNamedCurveTable.getParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    public static String encryptECC(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return new String(Base64.encode(encryptedBytes));
    }

    public static String decryptECC(String cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedCipherText = Base64.decode(cipherText.getBytes());
        byte[] decryptedBytes = cipher.doFinal(decodedCipherText);
        return new String(decryptedBytes);
    }

    public static String publicKeyToBase64(PublicKey publicKey) {
        return new String(Base64.encode(publicKey.getEncoded()));
    }

    public static PublicKey base64ToPublicKey(String base64PublicKey) throws Exception {
        byte[] publicKeyBytes = Base64.decode(base64PublicKey.getBytes());
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(spec.getCurve().decodePoint(publicKeyBytes), spec);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static String privateKeyToBase64(PrivateKey privateKey) {
        return new String(Base64.encode(privateKey.getEncoded()));
    }

    public static PrivateKey base64ToPrivateKey(String base64PrivateKey) throws Exception {
        byte[] privateKeyBytes = Base64.decode(base64PrivateKey.getBytes());
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new java.math.BigInteger(1, privateKeyBytes), spec);
        return keyFactory.generatePrivate(privateKeySpec);
    }
}
