package com.dreamsecurity.ocsplib;

import com.dreamsecurity.ocsputility.CryptoUtil;

public class Initializer {

	public static void initBCProvider() {
		
		CryptoUtil.installBCProviderIfNotAvailable();
		
	}
	
}
