package com.dreamsecurity.ocsplib.extension;

import java.io.IOException;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;

/**
 * The invalidity date is a non-critical CRL entry extension that provides the
 * date on which it is known or suspected that the private key was compromised
 * or that the certificate otherwise became invalid. Note: These extension can
 * be used as singleResponseExtensions in response
 * 
 * @author dream
 *
 */
public class CrlEntryInvalidityDateExt {
	Logger logger = LogManager.getLogger(CrlEntryInvalidityDateExt.class);

	/**
	 * Note: These extension can be used as singleResponseExtensions in response
	 * 
	 * @param invalidityDate
	 *            Date on which key/certificate became invalid
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public Extension build(Date invalidityDate, boolean isCritical) {
		Extension ext = null;
		try {
			ext = new Extension(new ASN1ObjectIdentifier("2.5.29.24"), isCritical,
					new ASN1GeneralizedTime(invalidityDate).getEncoded());
			return ext;
		} catch (IOException e) {
			logger.error("Failed to create CRL Entry invalidity extension: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
}
