package com.wiley.bir.util;

import org.apache.commons.lang3.StringUtils;

import com.thortech.xl.crypto.tcCryptoException;
import com.thortech.xl.crypto.tcCryptoUtil;

public class DecryptPassword {

	public static String decrypt(final String encryptedPassword) throws tcCryptoException {
		String decryptedPassword = null;

		decryptedPassword = StringUtils.strip(tcCryptoUtil.decrypt(encryptedPassword, "DBSecretKey"), "\"");
		return decryptedPassword;
	}

}
