import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class AES {

    private long shiftL = 0;
    private long shiftH = 1000000;


    @DataProvider(parallel = true)
    public Iterator<Object> getRockIterator() {
        return getRock().iterator();
    }

    @Test(dataProvider = "getRockIterator")
    public void getBruteAes(String password) {
        String result = encrypt("mark", password);
        if (result.equals("q/A1g9srH8tDHHVz8HNWVQ==")) {//"q/A1g9srH8tDHHVz8HNWVQ=="
            savePassword(result);
            System.exit(1);
        }
        //(result).isEqualTo("q/A1g9srH8tDHHVz8HNWVQ==");
    }

    public void savePassword(String pass) {
        try (FileWriter writer = new FileWriter("passes\\aes.txt", true)) {
            writer.write(pass);
            writer.flush();
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }

    public SecretKeySpec setKey(String myKey) {
        MessageDigest sha = null;
        SecretKeySpec keyy = null;
        try {
            byte[] key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16); // use only first 128 bit
            keyy = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return keyy;
    }

    public String encrypt(String strToEncrypt, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, setKey(key));
            return Base64.encodeBase64String(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    private List<Object> getRock() {
        List<Object> pswds = new LinkedList<>();
        try (BufferedReader br = new BufferedReader(new FileReader("dictionaries\\rockyou.txt"))) {
            String line;
            int shift = 0;
            while ((line = br.readLine()) != null) {
                shift++;
                if (shift > shiftL)
                    pswds.add(line);
                if (shift > shiftH)
                    break;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return pswds;
    }
}