package main;

import com.google.crypto.tink.*;

import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class Main {
    private static final String secret = "secret.test";
    private static final String fileName = "generated_key.json";

    public static void main(String[] args) throws GeneralSecurityException {
        KeysetHandle keyset = generateKey();
        String input = JOptionPane.showInputDialog(null, "Text zum Encrypten hier eingeben:");
        JOptionPane.showConfirmDialog(null, encryptWithKey(input, keyset));
        input = JOptionPane.showInputDialog(null, "Text zum Decrypten hier eingeben:");
        JOptionPane.showConfirmDialog(null, decrypt(input));
    }

    private static String encryptWithKey(String text, KeysetHandle keysetHandle) throws GeneralSecurityException {
        byte[] data = keysetHandle.getPrimitive(Aead.class).encrypt(text.getBytes(), secret.getBytes());
        return Arrays.toString(data);
    }

    private static String decrypt(String text) {
        try {
            KeysetHandle keysetHandle = CleartextKeysetHandle.read(
                    JsonKeysetReader.withFile(new File(fileName)));
            keysetHandle.getPrimitive(Aead.class).decrypt(text.getBytes(), secret.getBytes());
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
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
