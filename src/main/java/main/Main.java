package main;

import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadConfig;

import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class Main {
    private static final String secret = "secret.test";
    private static final String fileName = "generated_key.json";

    public static void main(String[] args) throws GeneralSecurityException {
        AeadConfig.register();
        KeysetHandle keyset = generateKey();
        String input = JOptionPane.showInputDialog(null, "Text zum Encrypten hier eingeben:");
        byte[] schas = encryptWithKey(input, keyset);
        JOptionPane.showMessageDialog(null, new String(schas) + "\n" + new String(decrypt(schas)));
    }

    private static byte[] encryptWithKey(String text, KeysetHandle keysetHandle) throws GeneralSecurityException {
        return keysetHandle.getPrimitive(Aead.class).encrypt(text.getBytes(), secret.getBytes());
    }

    private static byte[] decrypt(byte[] text) {
        try {
            KeysetHandle keysetHandle = CleartextKeysetHandle.read(
                    JsonKeysetReader.withFile(new File(fileName)));
            return keysetHandle.getPrimitive(Aead.class).decrypt(text, secret.getBytes());
        } catch (IOException | GeneralSecurityException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private static KeysetHandle generateKey() throws GeneralSecurityException {
        KeysetHandle keysetHandle = KeysetHandle.generateNew(
                KeyTemplates.get("AES128_GCM"));
        try {
            CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(
                    new File(fileName)));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return keysetHandle;
    }
}
