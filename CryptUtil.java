import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class CryptUtil {
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String SALT = "I2phNF][{:U,~`Mt*=\\&F#@>W SmQHmL-;<FE )ff\\!gt,R:5_63\":HK,0e,Ri@~";

    /**
     * 암호화
     * @param plainText 암호화 할 텍스트
     * @param secretKey 비밀번호
     * @return 암호화 된 텍스트
     */
    public static String encrypt(String plainText, String secretKey)  {
        try {
            byte[] clearBytes = getBytes(plainText);
            byte[] pbeParameters = getPBEParameters(secretKey);

            byte[] key = getKeyBytes(pbeParameters, 32);
            byte[] iv = getIvBytes(pbeParameters, 16);

            byte[] encryptedBytes = getTransformBytes(clearBytes, key, iv, Cipher.ENCRYPT_MODE);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * 복호화
     * @param cipherText 암호화 된 텍스트
     * @param secretKey 비밀번호
     * @return 복호화 된 텍스트
     */
    public static String decrypt(String cipherText, String secretKey) {
        try {
            byte[] cipherBytes = Base64.getDecoder().decode(cipherText);
            byte[] pbeParameters = getPBEParameters(secretKey);

            byte[] key = getKeyBytes(pbeParameters, 32);
            byte[] iv = getIvBytes(pbeParameters, 16);

            byte[] decryptedBytes = getTransformBytes(cipherBytes, key, iv, Cipher.DECRYPT_MODE);

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static byte[] getPBEParameters(String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), SALT.getBytes(StandardCharsets.UTF_8), 100, 512);

        return factory.generateSecret(spec).getEncoded();
    }

    private static byte[] getTransformBytes(byte[] cipherBytes, byte[] keyBytes, byte[] ivBytes, int operationMode) {
        byte[] result = null;
        try {
            SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(operationMode, secret, new IvParameterSpec(ivBytes));
            result = cipher.doFinal(cipherBytes);
        } catch (Exception ignored) {

        }
        return result;
    }

    private static byte[] getBytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] getKeyBytes(byte[] pdb, int cb) {
        byte[] keyByte = new byte[cb];
        System.arraycopy(pdb, 0, keyByte, 0, 32);

        return keyByte;
    }

    private static byte[] getIvBytes(byte[] pdb, int cb) {
        byte[] ivByte = new byte[cb];
        System.arraycopy(pdb, 9, ivByte, 0, 8);
        System.arraycopy(pdb, 38, ivByte, 8, 8);
        return ivByte;
    }
}