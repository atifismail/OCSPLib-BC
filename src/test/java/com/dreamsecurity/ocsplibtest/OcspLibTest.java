package com.dreamsecurity.ocsplibtest;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringFormattedMessage;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.dreamsecurity.ocsplib.extension.ExtensionsUtil;
import com.dreamsecurity.ocsplib.extension.PreferredSigAlgo;
import com.dreamsecurity.ocsplib.core.OcspRequestBuilder;
import com.dreamsecurity.ocsplib.core.OcspResponseBuilder;
import com.dreamsecurity.ocsplib.core.OcspStatus;
import com.dreamsecurity.ocsplib.core.OcspStatus.OCSP_STATUS;
import com.dreamsecurity.ocsputility.Constants;
import com.dreamsecurity.ocsputility.Constants.SigningAlgo;
import com.dreamsecurity.ocsputility.CryptoUtil;
import com.dreamsecurity.ocsputility.FileUtils;
import com.dreamsecurity.ocsputility.KeyGenerator;

/**
 * Unit test for OCSP library
 */
public class OcspLibTest {

	static Logger logger = LogManager.getLogger(OcspLibTest.class);

	static X509Certificate rootCert = null;
	static X509Certificate ocspCert = null;
	static X509Certificate requestorCert = null;
	static PrivateKey rootPri = null;
	static PrivateKey ocspPri = null;
	static PrivateKey requestorPri = null;

	@BeforeClass
	public static void createCerts() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Creating root and ocsp certificate and keys");

		new File("temp").mkdir();

		CryptoUtil.installBCProviderIfNotAvailable();

		KeyPair rootKeyPair = KeyGenerator.getInstance()
				.generateECPair(Constants.ECCurves.secp256r1.getValue());
		rootPri = rootKeyPair.getPrivate();

		KeyPair ocspKeyPair = KeyGenerator.getInstance()
				.generateECPair(Constants.ECCurves.secp256r1.getValue());
		ocspPri = ocspKeyPair.getPrivate();

		KeyPair reqKeyPair = KeyGenerator.getInstance()
				.generateECPair(Constants.ECCurves.secp256r1.getValue());
		requestorPri = reqKeyPair.getPrivate();

		try {
			// create root cert
			rootCert = createCert("cn=root,ou=test,o=dream,c=KR", rootKeyPair,
					true);
			logger.info("Issuing root certificate (temp/root.der)");

			FileUtils.saveFile("temp/root.der", rootCert.getEncoded());

			FileUtils.saveFile("temp/root.key",
					rootKeyPair.getPrivate().getEncoded());

			// create ocsp cert
			logger.info("Issuing ocsp certificate (temp/ocsp.der)");
			ocspCert = createCert("cn=ocsp,ou=test,o=dream,c=KR", ocspKeyPair,
					false);
			FileUtils.saveFile("temp/ocsp.der", ocspCert.getEncoded());

			FileUtils.saveFile("temp/ocsp.key",
					ocspKeyPair.getPrivate().getEncoded());

			// create requester cert
			logger.info("Issuing requester certificate (temp/req.der)");
			requestorCert = createCert("cn=req,ou=test,o=dream,c=KR",
					reqKeyPair, false);

			FileUtils.saveFile("temp/req.der", requestorCert.getEncoded());

			FileUtils.saveFile("temp/req.key",
					reqKeyPair.getPrivate().getEncoded());

		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
	}

	@AfterClass
	public static void deleteCerts() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Deleting root and ocsp certificate and keys");
		FileUtils.deleteDir(new File("temp"));
	}

	@Test
	public void testCertsNKeys() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Test - assert certs and keys exist");

		assertTrue("root.der does not found",
				FileUtils.isFileAccessible("temp/root.der"));
		assertTrue("root.key does not found",
				FileUtils.isFileAccessible("temp/root.key"));
		assertTrue("ocsp.der does not found",
				FileUtils.isFileAccessible("temp/ocsp.der"));
		assertTrue("ocsp.key does not found",
				FileUtils.isFileAccessible("temp/ocsp.key"));
		assertTrue("req.der does not found",
				FileUtils.isFileAccessible("temp/req.der"));
		assertTrue("req.key does not found",
				FileUtils.isFileAccessible("temp/req.key"));
	}

	@Test
	public void testOcspRequest() {

		String ocspReqName = "OCSP Client";
		BigInteger serialNum = ocspCert.getSerialNumber();

		OCSPReq req = buildOcspRequest(ocspReqName, serialNum, false, false, 2);

		// check request
		assertFalse("Failed to create OCSP request", req == null);
		assertTrue("Failed to get ocsp requestor name", req.getRequestorName()
				.getName().toString().equalsIgnoreCase(ocspReqName));
		assertTrue("Number of requests does not match",
				req.getRequestList().length == 2);

		for (Req r : req.getRequestList()) {
			assertTrue("Certificate serial number does not match",
					r.getCertID().getSerialNumber().equals(serialNum));
			try {
				assertTrue("Issuer does not match", r.getCertID().matchesIssuer(
						new X509CertificateHolder(rootCert.getEncoded()),
						new JcaDigestCalculatorProviderBuilder().build()));
			} catch (OperatorCreationException | OCSPException | IOException
					| CertificateEncodingException e) {
				fail("Issuer does not match: " + e.getMessage());
			}
		}
	}

	@Test
	public void testOcspRequestWithExts() {

		String ocspReqName = "OCSP Client";
		BigInteger serialNum = ocspCert.getSerialNumber();

		OCSPReq ocspReq = buildOcspRequest(ocspReqName, serialNum, false, true,
				2);

		// check request
		assertFalse("Failed to create OCSP request", ocspReq == null);
		assertTrue("Failed to get ocsp requestor name",
				ocspReq.getRequestorName().getName().toString()
						.equalsIgnoreCase(ocspReqName));
		assertTrue("Number of requests does not match",
				ocspReq.getRequestList().length == 2);

		for (Req r : ocspReq.getRequestList()) {
			assertTrue("Certificate serial number does not match",
					r.getCertID().getSerialNumber().equals(serialNum));
			try {
				assertTrue("Issuer does not match", r.getCertID().matchesIssuer(
						new X509CertificateHolder(rootCert.getEncoded()),
						new JcaDigestCalculatorProviderBuilder().build()));
			} catch (OperatorCreationException | OCSPException | IOException
					| CertificateEncodingException e) {
				fail("Issuer does not match: " + e.getMessage());
			}
		}
	}

	@Test
	public void testOcspResponse() {
		// create test ocsp request
		String ocspReqName = "OCSP Client";
		BigInteger serialNum = ocspCert.getSerialNumber();
		int numberOfReqs = 3;

		OCSPReq ocspReq = buildOcspRequest(ocspReqName, serialNum, false, false,
				numberOfReqs);

		OcspResponseBuilder ocspRespBuilder = new OcspResponseBuilder(
				ocspCert.getPublicKey());

		assertTrue(
				new StringFormattedMessage(
						"Number of requests does not match Reqs(%d) != 3",
						ocspReq.getRequestList().length).getFormattedMessage(),
				ocspReq.getRequestList().length == numberOfReqs);

		Req[] reqs = ocspReq.getRequestList();

		assertTrue("Requestd cert serial number does not match",
				reqs[0].getCertID().getSerialNumber().equals(serialNum));
		assertTrue("Error in adding single ocsp response",
				ocspRespBuilder.addSingleResponse(
						reqs[0].getCertID().toASN1Primitive(),
						new OcspStatus(OCSP_STATUS.OCSP_GOOD), new Date(),
						new Date()) == 0);

		assertTrue("Requestd cert serial number does not match",
				reqs[1].getCertID().getSerialNumber().equals(serialNum));
		assertTrue("Error in adding single ocsp response",
				ocspRespBuilder.addSingleResponse(
						reqs[1].getCertID().toASN1Primitive(),
						new OcspStatus(OCSP_STATUS.OCSP_UNKNOWN), new Date(),
						new Date()) == 0);

		assertTrue("Requestd cert serial number does not match",
				reqs[2].getCertID().getSerialNumber().equals(serialNum));
		assertTrue("Error in adding single ocsp response",
				ocspRespBuilder.addSingleResponse(
						reqs[2].getCertID().toASN1Primitive(),
						new OcspStatus(OCSP_STATUS.OCSP_REVOKED, new Date(),
								CRLReason.aACompromise),
						new Date(), new Date()) == 0);

		OCSPResp ocspResp = ocspRespBuilder.build(ocspPri,
				SigningAlgo.SHA256WITHECDSA.getAlgo(),
				CryptoUtil.X509ToHolder(new X509Certificate[] { ocspCert }),
				new Date(), null, OCSPResp.SUCCESSFUL);

		// check response
		assertTrue("Response status does not match",
				ocspResp.getStatus() == OCSPResp.SUCCESSFUL);

		BasicOCSPResp basicResp = null;
		try {
			basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
		} catch (OCSPException e) {
			fail("Invalid basic ocsp response");
			e.printStackTrace();
		}

		assertTrue(basicResp.getResponderId() != null);

		assertTrue(
				new StringFormattedMessage(
						"Number of responses does not match requests Reqs(%d) != Resps(%d)",
						ocspReq.getRequestList().length,
						basicResp.getResponses().length).getFormattedMessage(),
				ocspReq.getRequestorName().getName().toString()
						.equalsIgnoreCase(ocspReqName));

		SingleResp[] sr = basicResp.getResponses();

		assertTrue(sr[0].getCertID().getSerialNumber().equals(serialNum));
		assertTrue(sr[0].getCertStatus() == CertificateStatus.GOOD);

		assertTrue(sr[1].getCertID().getSerialNumber().equals(serialNum));
		assertTrue(sr[1].getCertStatus().getClass().getName()
				.equalsIgnoreCase("org.bouncycastle.cert.ocsp.UnknownStatus"));

		assertTrue(sr[1].getCertID().getSerialNumber().equals(serialNum));
		assertTrue(((RevokedStatus) sr[2].getCertStatus())
				.getRevocationReason() == CRLReason.aACompromise);
	}

	@Test
	public void testOcspResponseWithExts() {
		// create test ocsp request
		String ocspReqName = "OCSP Client";
		BigInteger serialNum = ocspCert.getSerialNumber();
		int numberOfReqs = 3;

		OCSPReq ocspReq = buildOcspRequest(ocspReqName, serialNum, false, true,
				numberOfReqs);

		// check ocsp request extension
		BigInteger nonceVal = null;
		PreferredSigAlgo preSignAlgos = null;

		// nonce
		Extension ext = ocspReq
				.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		nonceVal = new BigInteger(ext.getExtnValue().getOctets());
		assertTrue("Nonce value does not match", 1L == nonceVal.longValue());

		// supported response type
		ext = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_response);
		ASN1Sequence asn1 = DERSequence.getInstance(ext.getParsedValue());
		ASN1Sequence seq = DERSequence.getInstance(ext.getParsedValue());
		assertTrue("Object Identifier didnt matched",
				OCSPObjectIdentifiers.id_pkix_ocsp_basic.getId()
						.equalsIgnoreCase(seq.getObjectAt(0).toString()));

		// preferred algo
		ext = ocspReq
				.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_pref_sig_algs);
		asn1 = DERSequence.getInstance(ext.getParsedValue());
		preSignAlgos = PreferredSigAlgo
				.getInstance(asn1.getObjectAt(0).toASN1Primitive());
		assertFalse("PreferredSignAlgos does not exist", preSignAlgos == null);
		assertTrue("SigningAlgoId does not match",
				preSignAlgos.getSigIdentifier().getAlgorithm().toString()
						.equals("1.2.3.4.5"));
		assertTrue("PublicKeyAlgo does not match",
				preSignAlgos.getPubKeyAlgIdentifier().getCapabilityID().getId()
						.equals(SMIMECapability.aES128_CBC.getId()));

		// check single request extensions
		for (Req req : ocspReq.getRequestList()) {
			Extensions exts = req.getSingleRequestExtensions();
			ext = exts.getExtension(
					OCSPObjectIdentifiers.id_pkix_ocsp_service_locator);
			asn1 = DERSequence.getInstance(ext.getParsedValue());

			assertTrue("Isser value does not match",
					"cn=root,ou=test,o=dream,c=KR".equalsIgnoreCase(X500Name
							.getInstance(asn1.getObjectAt(0)).toString()));

			AuthorityInformationAccess AIA = AuthorityInformationAccess
					.getInstance(asn1.getObjectAt(1));

			assertTrue("Access method does not match",
					AIA.getAccessDescriptions()[0].getAccessMethod().getId()
							.toString().equals("1.2.3.4.5"));
			assertTrue("Access location does not match",
					AIA.getAccessDescriptions()[0].getAccessLocation().getName()
							.toString().equalsIgnoreCase(
									"cn=root,ou=test,o=dream,c=KR"));
		}

		// build response
		OcspResponseBuilder ocspRespBuilder = new OcspResponseBuilder(
				ocspCert.getPublicKey());

		assertTrue(
				new StringFormattedMessage(
						"Number of requests does not match Reqs(%d) != 3",
						ocspReq.getRequestList().length).getFormattedMessage(),
				ocspReq.getRequestList().length == numberOfReqs);

		try {
			FileUtils.saveFile("ocsp_request.ber", ocspReq.getEncoded());
		} catch (IOException e) {
			logger.error("Error in saving ocsp request", e.getMessage());
			e.printStackTrace();
		}

		Req[] reqs = ocspReq.getRequestList();

		// create single response extensions
		ExtensionsUtil util = new ExtensionsUtil();

		util.addAchiveCutoffExt(new Date(), false);
		util.addCrlEntryCertIssuersExt(
				new String[] { "cn=root,ou=test,o=dream,c=KR" }, false);
		util.addCrlEntryInvalidityDateExt(new Date(), false);
		util.addCrlEntryReasonCodeExt(CRLReason.cACompromise, false);
		util.addCrlRefExt("ldap://test/root", 1, new Date(), false);

		Extensions singleExts = util.build();

		assertTrue("Error in adding single ocsp response",
				ocspRespBuilder.addSingleResponse(
						reqs[0].getCertID().toASN1Primitive(),
						new OcspStatus(OCSP_STATUS.OCSP_GOOD), new Date(),
						new Date(), singleExts) == 0);

		assertTrue("Error in adding single ocsp response",
				ocspRespBuilder.addSingleResponse(
						reqs[1].getCertID().toASN1Primitive(),
						new OcspStatus(OCSP_STATUS.OCSP_UNKNOWN), new Date(),
						new Date(), singleExts) == 0);

		assertTrue("Error in adding single ocsp response",
				ocspRespBuilder.addSingleResponse(
						reqs[2].getCertID().toASN1Primitive(),
						new OcspStatus(OCSP_STATUS.OCSP_REVOKED, new Date(),
								CRLReason.aACompromise),
						new Date(), new Date(), singleExts) == 0);
	
		// create response extension
		util.reset();
		util.addNonceExt(nonceVal, false);
		util.addExtendedRevokedExt(false);
		Extensions respExts = util.build();

		OCSPResp ocspResp = ocspRespBuilder.build(ocspPri,
				SigningAlgo.SHA256WITHECDSA.getAlgo(),
				CryptoUtil.X509ToHolder(new X509Certificate[] { ocspCert }),
				new Date(), respExts, OCSPResp.SUCCESSFUL);

		// save ocsp response
		try {
			FileUtils.saveFile("ocsp_response.ber", ocspResp.getEncoded());
		} catch (IOException e) {
			logger.error("Error in saving ocsp response: " + e.getMessage());
			e.printStackTrace();
		}

		// check response
		assertTrue("Response status does not match",
				ocspResp.getStatus() == OCSPResp.SUCCESSFUL);

		BasicOCSPResp basicResp = null;
		try {
			basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
		} catch (OCSPException e) {
			fail("Invalid basic ocsp response");
			e.printStackTrace();
		}

		assertTrue(basicResp.getResponderId() != null);

		// check response extensions
		for (Object obj : basicResp.getExtensionOIDs()) {
			ext = basicResp.getExtension((ASN1ObjectIdentifier) obj);
			assertTrue("Extension error with OID: " + ext.getExtnId().getId(),
					ext.getExtnValue() != null);
		}

		assertTrue(
				new StringFormattedMessage(
						"Number of responses does not match requests Reqs(%d) != Resps(%d)",
						ocspReq.getRequestList().length,
						basicResp.getResponses().length).getFormattedMessage(),
				ocspReq.getRequestList().length == basicResp
						.getResponses().length);

		SingleResp[] sr = basicResp.getResponses();

		assertTrue(sr[0].getCertID().getSerialNumber().equals(serialNum));
		assertTrue(sr[0].getCertStatus() == CertificateStatus.GOOD);

		// check single response extensions
		for (SingleResp r : basicResp.getResponses()) {
			for (Object obj : r.getExtensionOIDs()) {
				ext = r.getExtension((ASN1ObjectIdentifier) obj);
				assertTrue(
						"Extension error with OID: " + ext.getExtnId().getId(),
						ext.getExtnValue() != null);
			}
		}

		assertTrue(sr[1].getCertID().getSerialNumber().equals(serialNum));
		assertTrue(sr[1].getCertStatus().getClass().getName()
				.equalsIgnoreCase("org.bouncycastle.cert.ocsp.UnknownStatus"));

		assertTrue(sr[1].getCertID().getSerialNumber().equals(serialNum));
		assertTrue(((RevokedStatus) sr[2].getCertStatus())
				.getRevocationReason() == CRLReason.aACompromise);
	}

	@SuppressWarnings("serial")
	@Test
	public void testOcspRequestVerify() {
		// create test ocsp request
		String ocspReqName = "OCSP Client";
		BigInteger serialNum = ocspCert.getSerialNumber();
		int numberOfReqs = 1;

		OCSPReq ocspReq = buildOcspRequest(ocspReqName, serialNum, true, false,
				numberOfReqs);

		// cert chain verify
		try {
			assertTrue("Certificate chain Error",
					CryptoUtil.verifyCertificateBoolean(
							CryptoUtil.byteToX509Certificate(
									ocspReq.getCerts()[0].getEncoded()),
							new ArrayList<X509Certificate>() {
								{
									add(rootCert);
								}
							}, null));
		} catch (IOException e) {
			fail("Certificate chain cannot be build: " + e.getMessage());
			e.printStackTrace();
		}

		// signature verify
		try {
			assertTrue("OCSP request signature verification failed",
					ocspReq.isSignatureValid(
							new JcaX509ContentVerifierProviderBuilder()
									.build(ocspReq.getCerts()[0])));
		} catch (OperatorCreationException | OCSPException e) {
			fail("OCSP request signature verification failed: "
					+ e.getMessage());
			e.printStackTrace();
		}
	}

	@SuppressWarnings("serial")
	@Test
	public void testOcspRespVerify() {
		OcspResponseBuilder ocspRespBuilder = new OcspResponseBuilder(
				ocspCert.getPublicKey());

		OCSPResp ocspResp = ocspRespBuilder.build(ocspPri,
				SigningAlgo.SHA256WITHECDSA.getAlgo(),
				CryptoUtil.X509ToHolder(new X509Certificate[] { ocspCert }),
				new Date(), null, OCSPResp.SUCCESSFUL);
		
		BasicOCSPResp basicResp = null;
		try {
			basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
		} catch (OCSPException e) {
			fail("Invalid basic ocsp response");
			e.printStackTrace();
		}
		
		// cert chain verify
		try {
			assertTrue("Certificate chain Error",
					CryptoUtil.verifyCertificateBoolean(
							CryptoUtil.byteToX509Certificate(
									basicResp.getCerts()[0].getEncoded()),
							new ArrayList<X509Certificate>() {
								{
									add(rootCert);
								}
							}, null));
		} catch (IOException e) {
			fail("OCSP Response certificate chain cannot be build: " + e.getMessage());
			e.printStackTrace();
		}

		// signature verify
		try {
			assertTrue("OCSP request signature verification failed",
					basicResp.isSignatureValid(
							new JcaX509ContentVerifierProviderBuilder()
									.build(basicResp.getCerts()[0])));
		} catch (OperatorCreationException | OCSPException e) {
			fail("OCSP request signature verification failed: "
					+ e.getMessage());
			e.printStackTrace();
		}
	}

	

	private static X509Certificate createCert(String dn, KeyPair keyPair,
			boolean selfsign) {

		BigInteger serialNumber = BigInteger
				.valueOf(System.currentTimeMillis());
		X500Name subject = new X500Name(dn);

		ContentSigner contentSigner = null;
		PrivateKey signKey = null;
		try {
			if (selfsign) {
				signKey = keyPair.getPrivate();
			} else {
				signKey = rootPri;
			}
			contentSigner = new JcaContentSignerBuilder(
					Constants.SigningAlgo.SHA256WITHECDSA.getAlgo())
							.build(signKey);
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		}

		X509v3CertificateBuilder certificateBuilder = null;

		if (selfsign) {
			certificateBuilder = new JcaX509v3CertificateBuilder(subject,
					serialNumber, new Date(),
					Date.from(Instant.now().plus(Duration.ofDays(30))), subject,
					keyPair.getPublic());
		} else {
			certificateBuilder = new JcaX509v3CertificateBuilder(
					FileUtils.readX509Certificate("temp/root.der"),
					serialNumber, new Date(),
					Date.from(Instant.now().plus(Duration.ofDays(30))), subject,
					keyPair.getPublic());

			try {
				certificateBuilder.addExtension(Extension.extendedKeyUsage,
						true,
						new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
			} catch (CertIOException e) {
				e.printStackTrace();
			}
		}
		try {
			return new JcaX509CertificateConverter()
					.setProvider(new BouncyCastleProvider())
					.getCertificate(certificateBuilder.build(contentSigner));
		} catch (CertificateException e) {
			e.printStackTrace();
		}

		return null;
	}

	private OCSPReq buildOcspRequest(String ocspReqName, BigInteger serialNum,
			boolean signed, boolean exts, int numberOfRequests) {

		OcspRequestBuilder req = new OcspRequestBuilder();

		for (int i = 0; i < numberOfRequests; i++) {
			try {
				if (exts) {
					// add single request exts
					ExtensionsUtil util = new ExtensionsUtil();

					String issuer = "cn=root,ou=test,o=dream,c=KR";
					String locator = issuer;
					AuthorityInformationAccess AIA = new AuthorityInformationAccess(
							new AccessDescription(
									new ASN1ObjectIdentifier("1.2.3.4.5"),
									new GeneralName(new X500Name(locator))));
					util.addServiceLocatorExt(issuer, AIA, false);

					Extensions singleExts = util.build();

					// add request exts
					util.reset();

					util.addAcceptableRespTypeExt(new String[] {
							OCSPObjectIdentifiers.id_pkix_ocsp_basic.getId() },
							false);

					util.addNonceExt(BigInteger.valueOf(1L), false);

					PreferredSigAlgo psa = new PreferredSigAlgo("1.2.3.4.5",
							SMIMECapability.aES128_CBC.getId(), null);
					util.addPreferredSigAlgoExt(
							new ArrayList<PreferredSigAlgo>(Arrays.asList(psa)),
							false);

					Extensions reqExts = util.build();

					// set req exts
					req.setRequestExtension(reqExts);

					req.addRequestCert(rootCert.getEncoded(), serialNum,
							singleExts);
				} else {
					req.addRequestCert(rootCert.getEncoded(), serialNum);
				}
			} catch (CertificateEncodingException e) {
				fail("Error in adding requested certificate info: "
						+ e.getMessage());
			}
		}

		req.setRequestorName(ocspReqName);

		OCSPReq ocspReq = null;

		if (signed) {
			List<X509CertificateHolder> hl = new ArrayList<>();
			hl.add(CryptoUtil.X509ToHolder(requestorCert));
			ocspReq = req.build(requestorPri,
					Constants.SigningAlgo.SHA256WITHECDSA.getAlgo(),
					hl.stream().toArray(X509CertificateHolder[]::new));
		} else {
			ocspReq = req.build();
		}

		return ocspReq;
	}
}
