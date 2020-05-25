package com.dreamsecurity.ocsplib.extension;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;

/**
 * Create/add OCSP extensions
 * 
 * @author dream
 *
 */
public class ExtensionsUtil {

	Logger logger = LogManager.getLogger(ExtensionsUtil.class);
	private ExtensionsGenerator extGen;

	public ExtensionsUtil() {
		extGen = new ExtensionsGenerator();
	}

	/**
	 * The nonce cryptographically binds a request and a response to prevent
	 * replay attacks. If included in OCSP request, responder may include it in
	 * its OCSP response
	 * 
	 * @param nonce
	 *            Nonce value
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public void addNonceExt(BigInteger nonce, boolean isCritical) {
		Extension ext = new NonceExt().build(nonce, isCritical);

		if (ext != null) {
			extGen.addExtension(ext);
		}
	}

	/**
	 * It may be desirable for the OCSP responder to indicate the CRL on which a
	 * revoked or onHold certificate is found. Note: These extensions can be
	 * used as singleResponseExtensions in response
	 * 
	 * @param crlUrl
	 *            The URL at which the CRL is available
	 * @param crlNum
	 *            CRL number
	 * @param crlTime
	 *            The time at which the relevant CRL was created
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public void addCrlRefExt(String crlUrl, Integer crlNum, Date crlTime, boolean isCritical) {

		Extension ext = new CRLReferenceExt().build(crlUrl, crlNum, crlTime, isCritical);

		if (ext != null) {
			extGen.addExtension(ext);
		}
	}

	/**
	 * An OCSP client MAY wish to specify the kinds of response types it
	 * understands. This extension can be included as one of the
	 * requestExtensions in OCSP request.
	 * 
	 * @param oidList
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public void addAcceptableRespTypeExt(String[] oidList, boolean isCritical) {

		Extension ext = new AcceptableRespTypeExt().build(oidList, isCritical);

		if (ext != null) {
			extGen.addExtension(ext);
		}
	}

	/**
	 * An OCSP responder MAY choose to retain revocation information beyond a
	 * certificate’s expiration. The date obtained by subtracting this retention
	 * interval value from the producedAt time in a response is defined as the
	 * certificate’s "archive cutoff" date. e.g. if a server is operated with a
	 * 7-year retention interval policy and status was produced at time t1, then
	 * the value for ArchiveCutoff in the response would be (t1 - 7 years).
	 * Note: This extension can be used as singleResponseExtensions.
	 * 
	 * @param cutoffTime
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public void addAchiveCutoffExt(Date cutoffTime, boolean isCritical) {
		Extension ext = new ArchiveCutoffExt().build(cutoffTime, isCritical);

		if (ext != null) {
			extGen.addExtension(ext);
		}
	}

	/**
	 * The reasonCode is a non-critical CRL entry extension that identifies the
	 * reason for the certificate revocation. Note: These extensions can be used
	 * as singleResponseExtensions in response
	 * 
	 * @param crlReason
	 *            CRLReason code
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public void addCrlEntryReasonCodeExt(int crlReason, boolean isCritical) {
		Extension ext = new CrlEntryReasonCodeExt().build(crlReason, isCritical);

		if (ext != null) {
			extGen.addExtension(ext);
		}
	}

	/**
	 * The invalidity date is a non-critical CRL entry extension that provides
	 * the date on which it is known or suspected that the private key was
	 * compromised or that the certificate otherwise became invalid. Note: These
	 * extension can be used as singleResponseExtensions in response
	 * 
	 * @param invalidityDate
	 *            Date on which key/certificate became invalid
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public void addCrlEntryInvalidityDateExt(Date invalidityDate, boolean isCritical) {
		Extension ext = new CrlEntryInvalidityDateExt().build(invalidityDate, isCritical);
		if (ext != null) {
			extGen.addExtension(ext);
		}
	}

	/**
	 * This CRL entry extension identifies the certificate issuer associated
	 * with an entry in an indirect CRL, that is, a CRL that has the indirectCRL
	 * indicator set in its issuing distribution point extension. Note: These
	 * extensions can be used as singleResponseExtensions in response.
	 * 
	 * @param issuersList
	 *            Array of issuers DN
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public void addCrlEntryCertIssuersExt(String[] issuersList, boolean isCritical) {

		Extension ext = new CrlEntryCertIssuersExt().build(issuersList, isCritical);

		if (ext != null) {
			extGen.addExtension(ext);
		}
	}

	/**
	 * An OCSP server may be operated in a mode whereby the server receives a
	 * request and routes it to the OCSP server that is known to be
	 * authoritative for the identified certificate. The serviceLocator request
	 * extension is defined for this purpose. Note: This extension can be
	 * included as one of the singleRequestExtensions in requests.
	 * 
	 * @param issuer
	 *            Issuer of Issuer name (DN from subject certificate)
	 * @param locator
	 *            AuthorityInfoAccessSyntax OPTIONAL (AIA info from subject
	 *            certificate)
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public void addServiceLocatorExt(String issuer, AuthorityInformationAccess locator, boolean isCritical) {

		Extension ext = new ServiceLocatorExt().build(issuer, locator, isCritical);

		if (ext != null) {
			extGen.addExtension(ext);
		}
	}

	/**
	 * A client MAY declare a preferred set of algorithms in a request by
	 * including a preferred signature algorithms extension in requestExtensions
	 * of the OCSPRequest. Note: This extension can be included as one of the
	 * OCSP Request Extensions.
	 * 
	 * @param preferredAlgos
	 *            List of preferred signing and signing public key algorithms by
	 *            client
	 * @param isCritical
	 *            Specify if the extension is critical
	 * @return
	 */
	public void addPreferredSigAlgoExt(List<PreferredSigAlgo> preferredSigAlgos, boolean isCritical) {

		Extension ext = new PreferredSigAlgoExt().build(preferredSigAlgos, isCritical);

		extGen.addExtension(ext);
	}

	/**
	 * This extension indicates that the responder supports the extended
	 * definition of the "revoked" status to also include non-issued
	 * certificates according to Section 2.2. One of its main purposes is to
	 * allow audits to determine the responder’s type of operation. Clients do
	 * not have to parse this extension in order to determine the status of
	 * certificates in responses. MUST be included in the OCSP response when
	 * that response contains a "revoked" status for a non-issued certificate.
	 * This extension MAY be present in other responses to signal that the
	 * responder implements the extended revoked definition.
	 * 
	 * Note: When included, this extension MUST be placed in responseExtensions,
	 * and it MUST NOT appear in singleExtensions.
	 * 
	 * @param isCritical
	 * @return
	 */
	public void addExtendedRevokedExt(boolean isCritical) {
		Extension ext = new ExtendedRevokedDefExt().build(isCritical);
		if (ext != null) {
			extGen.addExtension(ext);
		}
	}

	/**
	 * Build Extensions from all added extensions
	 * 
	 * @return
	 */
	public Extensions build() {
		return extGen.generate();
	}

	public Extension getExtension(String extOid) {
		return extGen.getExtension(new ASN1ObjectIdentifier(extOid));
	}

	public void removeExtension(String extOid) {
		extGen.removeExtension(new ASN1ObjectIdentifier(extOid));
	}

	public void reset() {
		extGen.reset();
	}

	public void addExtension(Extension ext) {
		extGen.addExtension(ext);
	}
}
