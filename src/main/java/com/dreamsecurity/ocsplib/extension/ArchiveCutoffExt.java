package com.dreamsecurity.ocsplib.extension;

import java.io.IOException;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;

/**
 * OCSP-enabled applications would use an OCSP archive cutoff date to contribute
 * to a proof that a digital signature was (or was not) reliable on the date it
 * was produced even if the certificate needed to validate the signature has
 * long since expired.
 * 
 * OCSP servers that provide support for such a historical reference SHOULD
 * include an archive cutoff date extension in responses. If included, this
 * value SHALL be provided as an OCSP singleExtensions extension identified by
 * id-pkix-ocsp-archive-cutoff and of syntax GeneralizedTime.
 * 
 * id-pkix-ocsp-archive-cutoff OBJECT IDENTIFIER ::= {id-pkix-ocsp 6}
 * 
 * ArchiveCutoff ::= GeneralizedTime
 * 
 * To illustrate, if a server is operated with a 7-year retention interval
 * policy and status was produced at time t1, then the value for ArchiveCutoff
 * in the response would be (t1 - 7 years).
 * 
 * @author dream
 *
 */
public class ArchiveCutoffExt {
	Logger logger = LogManager.getLogger(ArchiveCutoffExt.class);

	/**
	 * Note: This extension can be used as Extension in OCSP response.
	 * 
	 * @param cutoffTime
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public Extension build(Date cutoffTime, boolean isCritical) {
		Extension ext = null;
		try {
			ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff, isCritical,
					new DERGeneralizedTime(cutoffTime).getEncoded());
			return ext;
		} catch (IOException e) {
			logger.error("Failed to create Archive Cutoff extension: " + e.getMessage());
			e.printStackTrace();
			return null;
		}
	}

}
