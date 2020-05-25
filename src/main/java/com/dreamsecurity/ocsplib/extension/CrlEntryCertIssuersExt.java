package com.dreamsecurity.ocsplib.extension;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;

/**
 * This CRL entry extension identifies the certificate issuer associated with
 * an entry in an indirect CRL, that is, a CRL that has the indirectCRL
 * indicator set in its issuing distribution point extension.
 * 
 * @author dream
 *
 */
public class CrlEntryCertIssuersExt {
	Logger logger = LogManager.getLogger(CrlEntryCertIssuersExt.class);
	/**
	 * Note: These extensions can be used as singleResponseExtensions in
	 * response.
	 * 
	 * @param issuersList
	 *            Array of issuers DN
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public Extension build(String[] issuersList, boolean isCritical) {

		Extension ext = null;

		GeneralNamesBuilder gnb = new GeneralNamesBuilder();

		for (String issuer : issuersList) {
			gnb.addName(new GeneralName(GeneralName.directoryName,issuer));
		}

		try {
			ext = new Extension(new ASN1ObjectIdentifier("2.5.29.29"), 
					isCritical, gnb.build().getEncoded());			
			return ext;
		} catch (IOException e) {
			logger.error("Failed to create CRL Entry Certificate Issuers extension: " 
		+ e.getMessage());
			e.printStackTrace();
			return null;
		}
	}

}
