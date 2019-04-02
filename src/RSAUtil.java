import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author wbh
 * @create 2019-04-01 17:31
 */
public class RSAUtil {
    private static int MAXENCRYPTSIZE = 117;
    private static int MAXDECRYPTSIZE = 128;

    /**
     * @param publicKeyByte
     * @return RSAPublicKey
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static RSAPublicKey getPublicKey(byte[] publicKeyByte) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(publicKeyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509);
        return publicKey;
    }

    public static RSAPrivateKey getPrivateKey(byte[] privateKeyByte) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }


    /**
     * encrypt
     *
     * @param source
     * @param publicKey
     * @return Bute[] encryptData
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(PublicKey publicKey, byte[] source)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        //此处填充方式选择部填充 NoPadding，当然模式和填充方式选择其他的，在Java端可以正确加密解密，
        //但是解密后的密文提交给C#端，解密的得到的数据将产生乱码
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return getResule(cipher, source);


    }

    public static byte[] encryptByPrivateKey(PrivateKey privateKey, byte[] source) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return getResule(cipher, source);
    }

    /**
     * RSA decrypt
     *
     * @param privateKey
     * @param encryptData
     * @return decryptData
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] decryptByPrivateKey(PrivateKey privateKey, byte[] encryptData)
            throws IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        //此处模式选择与加密对应，但是需要添加第二个参数new org.bouncycastle.jce.provider.BouncyCastleProvider()
        //若不添加第二个参数的话，解密后的数据前面出现大段空格符
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return getResule(cipher, encryptData);

    }


    public static byte[] decryptByPublicKey(PublicKey publicKey, byte[] encryptData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return getResule(cipher, encryptData);

    }


    private static byte[] getResule(Cipher cipher, byte[] source) throws BadPaddingException, IllegalBlockSizeException {
        int length = source.length;
        int offset = 0;
        int i = 0;
        byte[] cache;
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        while (length - offset > 0) {
            if (length - offset > MAXDECRYPTSIZE) {
                cache = cipher.doFinal(source, offset, MAXDECRYPTSIZE);
            } else {
                cache = cipher.doFinal(source, offset, length - offset);
            }
            outStream.write(cache, 0, cache.length);
            i++;
            offset = i * MAXDECRYPTSIZE;
        }
        return outStream.toByteArray();
    }

    /**
     * base64编码
     *
     * @param input
     * @return output with base64 encoded
     * @throws Exception
     */
    public static String encodeBase64(byte[] input) throws Exception {
        Class clazz = Class
                .forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");
        Method mainMethod = clazz.getMethod("encode", byte[].class);
        mainMethod.setAccessible(true);
        Object retObj = mainMethod.invoke(null, new Object[]{input});
        return (String) retObj;
    }

    /**
     * base64解码
     *
     * @param input
     * @return
     * @throws Exception
     */
    public static byte[] decodeBase64(String input) throws Exception {
        Class clazz = Class
                .forName("com.sun.org.apache.xerces.internal.impl.dv.util.Base64");
        Method mainMethod = clazz.getMethod("decode", String.class);
        mainMethod.setAccessible(true);
        Object retObj = mainMethod.invoke(null, input);
        return (byte[]) retObj;
    }

}
