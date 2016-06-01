package com.arthas.security.asymmetric.aes;

import com.arthas.security.common.Constant;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.Security;

/**
 * Created by Arthas on 16/5/30.
 * <p>
 *  DES存在漏洞，不安全，3DES效率较低，处理速度较慢
 *  AES：目前应用最多的加解密方式；
 *  目前为止未爆出漏洞;
 *  key长度：128，192，256
 */
public class SecurityAES {
    private boolean isJdkDES;//是使用jdkDES还是BCDES

    public SecurityAES(boolean isJdkDES) {
        this.isJdkDES = isJdkDES;
    }


    /**
     * 生成密钥
     * @return 密钥
     */
    public Key generateKey() {
        Key convertSecretKey = null;
        try {
            //生成Key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(Constant.AES_TYPE);
            if (!isJdkDES) {
                Security.addProvider(new BouncyCastleProvider());
                keyGenerator = KeyGenerator.getInstance(Constant.AES_TYPE, Constant.BC_TYPE);
            }

            //keyGenerator.init(new SecureRandom()):BC时异常Illegal key size or default parameters
            //By default Java supports only 128-bit encryption
            keyGenerator.init(128);//密钥长度
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();

            //转换Key
            convertSecretKey = new SecretKeySpec(bytesKey,Constant.AES_TYPE);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return convertSecretKey;
    }

    /**
     * jdk DES
     *
     * @param text     需要加密或解密的文本
     * @param isEncode true:加密，false:解密
     * @return 加密或解密的结果
     */
    public String desOpt(String text, boolean isEncode, Key convertSecretKey) {
        try {
            //加密或解密
            Cipher cipher = Cipher.getInstance(Constant.AES_MODE);//填充方式
            if (isEncode) {
                cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
                byte[] result = cipher.doFinal(text.getBytes());

                return Hex.encodeHexString(result);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);

                return new String(cipher.doFinal(Hex.decodeHex(text.toCharArray())));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

}
