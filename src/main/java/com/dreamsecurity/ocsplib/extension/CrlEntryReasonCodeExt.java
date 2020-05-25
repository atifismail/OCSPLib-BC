package com.dreamsecurity.ocsplib.extension;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;

/**
 * The reasonCode is a non-critical CRL entry extension that identifies the
 * reason for the certificate revocation.
 * 
 * @author dream
 *
 */
public class CrlEntryReasonCodeExt {
	Logger logger = LogManager.getLogger(CrlEntryReasonCodeExt.class);

	/**
	 * Note: These extensions can be used as singleResponseExtensions in response
	 * 
	 * @param crlReason
	 *            CRLReason code
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public Extension build(int crlReason, boolean isCritical) {
		Extension ext = null;
		try {
			ext = new Extension(new ASN1ObjectIdentifier("2.5.29.21"), isCritical,
					CRLReason.lookup(crlReason).getEncoded());
			return ext;
		} catch (IOException e) {
			logger.error("Failed to create CRL Entry reason code extension: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
	}
}
