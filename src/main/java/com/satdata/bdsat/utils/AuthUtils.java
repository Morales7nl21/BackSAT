package com.satdata.bdsat.utils;

import lombok.experimental.UtilityClass;
import org.apache.commons.io.FileUtils;
import org.apache.commons.ssl.PKCS8Key;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

@Service
public class AuthUtils {
    public static String CreateDigest(String passtosha)
    {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        }
        catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return Base64.getEncoder().encodeToString((new String(md.digest(passtosha.getBytes()))).getBytes());
    }
    public static String Sign(String sourceData, PrivateKey key) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {


        byte[] data = sourceData.getBytes();

        Signature sig = Signature.getInstance("SHA1WithRSA");
        sig.initSign(key);
        sig.update(data);
        byte[] signatureBytes = sig.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }
    public static PrivateKey getPrivateKey(File pkeyFile, String passphrase){
        try {
            byte[] keyBytes = FileUtils.readFileToByteArray(pkeyFile);
            return getPrivateKey(keyBytes, passphrase);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey getPrivateKey(byte[] encryptedKey, String passphrase){
        try {
            PKCS8Key pkcs8 = new PKCS8Key(encryptedKey, passphrase.toCharArray());
            return  pkcs8.getPrivateKey();
        } catch (Exception e) {
            throw new RuntimeException("Clave inválida");
        }
    }

}
