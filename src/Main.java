import sun.security.krb5.internal.crypto.RsaMd5CksumType;

import java.nio.charset.Charset;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Main {



    public static void main(String[] args) throws Exception {

        // net 公钥
        String netPublicKey = "MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCAu5/Z+ciUwCB/OkbDfN//IYGBudCN37efh8kil0SjWJbN5/Z8O5jckJbndNlnzltXvyBW14OrQmH9Oa9HEXt7B/ptUkNATMZLQJUJWfmHxvW9iAjZgZsNJmThjAjaa3DE5fKlVaNiC6Chc7GN9WtXZe6ZospX3E9qaHNkztJAMQIBAw==";
        // net 私钥
        String netPrivateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIC7n9n5yJTAIH86RsN83/8hgYG50I3ft5+HySKXRKNYls3n9nw7mNyQlud02WfOW1e/IFbXg6tCYf05r0cRe3sH+m1SQ0BMxktAlQlZ+YfG9b2ICNmBmw0mZOGMCNprcMTl8qVVo2ILoKFzsY31a1dl7pmiylfcT2poc2TO0kAxAgEDAoGAFXSapFRMGMqwFTRhIJTP/9rq6vRNbPqempahhcPgxeQZIlFTv19EJMLD0T4kO/e54/UwDnlAnIsQVN7yi9g/Pu9bvPQLqv9RUJDN2UMnKFI1zeQFO/a4jiE0Pr64GSkzwNIhgvn//Efwk8vp/WFyHqY/1J/jB2V8I1shn/8CSRMCQQDBn4Cf0QeE9Tsh9Ej7DZYOghBJxWcQGBM6ZIk2V55NYh5+94vSXTGbEbEgnYBczVkpcvdNvn9kHjhz0g9rrtB1AkEAqjR++iw2y+ksuc2ozAD/yzDZ5iQKqS+lJMbf3WClJtghejIHp0ZGwOt5i5gdT/FGVvymlbmsF0hd0deVaRW5TQJBAIEVAGqLWlijfMFNhfyzuV8BYDEuRLVlYibtsM7lFDOWvv9Psow+IRILy2sTquiI5huh+jPUVO1pevfhX50fNaMCQHF4VKbIJIfwyHvecIgAqod15pltXHDKbhiElT5Abhnla6bMBRou2dXyUQe6vjVLhDn9xGPRHWTa6TaPuPC5JjMCQQCA7AUT6fZBWsBrnuDUogcZNzvKywy8Hf2TAGnBalmEAs9UndlU0tTXS1wGRJZzWlt7mw7TUYNTkIPebYx3AK0v";
        // net 私钥加密的密文
        String netEncryptContent = "aY+eIEqmVgaaV0WZHJhDhVkbXVEZSsYgcyfE58S5ZfHO9nRvNf25M4wc0IeUak7eJhA1wdapiWVddPd6gyHZ9lRIoeOxw/UBiDgcG3BmjGSROtOVemMeBiJAOounjTQzKK4KPHAKozFnGiQE6O2aFLtQE/PCfMig0wZZXgkgub0=";


        try {

            RSAPublicKey rsaPublicKey = RSAUtil.getPublicKey(RSAUtil.decodeBase64(netPublicKey));

            String mingData = "内容123ABC";

            byte[] encryptDataByte = RSAUtil.encryptByPublicKey(rsaPublicKey, mingData.getBytes(Charset.forName("utf-8")));
            String encryptData = RSAUtil.encodeBase64(encryptDataByte);
            System.out.println("Java 公钥加密，密文可以用 NET 私钥解密：\n" + encryptData);

            RSAPrivateKey privateKey = RSAUtil.getPrivateKey(RSAUtil.decodeBase64(netPrivateKey));
            byte[] result = RSAUtil.decryptByPrivateKey(privateKey, encryptDataByte);
            System.out.println("Java 私钥解密：" + new String(result, "utf-8") + "\n");


            System.out.println("解密来自 NET 的密文，原明文= 123123\n");
            byte[] waiteDecryptByte = RSAUtil.decodeBase64(netEncryptContent);
            System.out.println("Java 公钥解密：" + new String(RSAUtil.decryptByPublicKey(rsaPublicKey, waiteDecryptByte),"utf-8"));

        }catch (Exception e){
            e.printStackTrace();
        }
    }



}
