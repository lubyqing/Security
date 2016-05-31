package com.arthas.security.common;


/**
 * Created by Arthas on 16/5/30.
 */
public interface Constant {

    /**
     * BC 实现方式
     */
    String BC_TYPE = "BC";

    /**
     * DES 加密类型
     */
    String DES_TYPE = "DES";
    /**
     * DES 加密方式
     */
    String DES_MODE = "DES/ECB/PKCS5Padding";

    /**
     * DESede 加密类型
     */
    String DESEDE_TYPE = "DESede";
    /**
     * DESede 加密方式
     */
    String DESEDE_MODE = "DESede/ECB/PKCS5Padding";

    /**
     * AES 加密类型
     */
    String AES_TYPE = "AES";
    /**
     * AES 加密方式
     */
    String AES_MODE = "AES/ECB/PKCS5Padding";
}
