package com.dreamsecurity.ocsplib.extension;

import java.math.BigInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;

/**
 * The nonce cryptographically binds a request and a response to prevent replay
 * attacks. If included in OCSP request, responder may include it in its OCSP
 * response
 * 
 * @author dream
 * 
 */
public class NonceExt {

	Logger logger = LogManager.getLogger(NonceExt.class);

	public Extension build(BigInteger nonce, boolean isCritical) {

		return new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, isCritical,
				new DEROctetString(nonce.toByteArray()));

	}
}
