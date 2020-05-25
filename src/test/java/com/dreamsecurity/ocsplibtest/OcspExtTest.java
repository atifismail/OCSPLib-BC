package com.dreamsecurity.ocsplibtest;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.Test;

import com.dreamsecurity.ocsplib.extension.ExtensionsUtil;
import com.dreamsecurity.ocsplib.extension.PreferredSigAlgo;

public class OcspExtTest {
	Logger logger = LogManager.getLogger(OcspExtTest.class);
	
	@Test
	public void testAcceptableRespTypeExt() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Testing AcceptableRespTypeExt extension");

		ExtensionsUtil util = new ExtensionsUtil();
		util.addAcceptableRespTypeExt(
				new String[] {
						OCSPObjectIdentifiers.id_pkix_ocsp_basic.getId() },
				false);

		// check
		Extension ext = util.getExtension(
				OCSPObjectIdentifiers.id_pkix_ocsp_response.getId());

		ASN1Sequence seq = DERSequence.getInstance(ext.getParsedValue());
		logger.info("Actual extension value: " + seq.getObjectAt(0).toString());
		assertTrue("Object Identifier didnt matched",
				OCSPObjectIdentifiers.id_pkix_ocsp_basic.getId()
						.equalsIgnoreCase(seq.getObjectAt(0).toString()));
	}

	@Test
	public void testArchiveCutoffExt() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Testing ArchiveCutoffExt extension");

		ExtensionsUtil util = new ExtensionsUtil();
		Date date = new Calendar.Builder().setDate(2020, 03, 12).build()
				.getTime();
		util.addAchiveCutoffExt(date, false);
		// check
		Extension ext = util.getExtension(
				OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId());

		ASN1GeneralizedTime asn1 = DERGeneralizedTime
				.getInstance(ext.getParsedValue());
		try {
			// logger.info("Expected value: " + cutoffDate.getTime() +
			// "\nActual extension value: " + asn1.getDate().getTime());
			assertTrue("Archive Cutoff date didnt match",
					date.getTime() == asn1.getDate().getTime());
		} catch (ParseException e) {
			fail("Failed to get cutoff date");
			e.printStackTrace();
		}
	}

	@Test
	public void testCrlEntryCertIssuersExt() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Testing CrlEntryCertIssuers extension");

		List<String> issuersList = Arrays
				.asList(new String[] { "cn=root1,ou=test,o=dream,c=KR",
						"cn=root2,ou=test,o=dream,c=KR" });

		ExtensionsUtil util = new ExtensionsUtil();
		util.addCrlEntryCertIssuersExt((String[]) issuersList.toArray(), false);
		// check
		Extension ext = util
				.getExtension(new ASN1ObjectIdentifier("2.5.29.29").getId());

		ASN1Sequence seq = DERSequence.getInstance(ext.getParsedValue());
		// logger.debug(GeneralName.getInstance(seq.getObjectAt(0)).getName().toString());
		// logger.debug(GeneralName.getInstance(seq.getObjectAt(1)).getName().toString());
		assertTrue("Issuer does not match",
				issuersList.get(0).equalsIgnoreCase(GeneralName
						.getInstance(seq.getObjectAt(0)).getName().toString()));
		assertTrue("Issuer does not match",
				issuersList.get(1).equalsIgnoreCase(GeneralName
						.getInstance(seq.getObjectAt(1)).getName().toString()));
	}

	@Test
	public void testCrlEntryInvalidityDateExt() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Testing CrlEntryInvalidityDateExt");

		ExtensionsUtil util = new ExtensionsUtil();
		Date date = new Calendar.Builder().setDate(2020, 03, 12).build()
				.getTime();
		util.addCrlEntryInvalidityDateExt(date, false);
		// check
		Extension ext = util
				.getExtension(new ASN1ObjectIdentifier("2.5.29.24").getId());

		ASN1GeneralizedTime asn1 = DERGeneralizedTime
				.getInstance(ext.getParsedValue());
		try {
			// logger.info("Expected value: " + cutoffDate.getTime() +
			// "\nActual extension value: " + asn1.getDate().getTime());
			assertTrue("Crl invalidity date not match",
					date.getTime() == asn1.getDate().getTime());
		} catch (ParseException e) {
			fail("Failed to get CrlEntryInvalidity date");
			e.printStackTrace();
		}
	}

	@Test
	public void testCrlEntryReasonCodeExt() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Testing CrlEntryReasonCodeExt");

		ExtensionsUtil util = new ExtensionsUtil();

		CRLReason crlReason = CRLReason.lookup(CRLReason.certificateHold);

		util.addCrlEntryReasonCodeExt(crlReason.getValue().intValue(), false);
		// check
		Extension ext = util
				.getExtension(new ASN1ObjectIdentifier("2.5.29.21").getId());

		CRLReason actualCrlReason = CRLReason
				.getInstance(ext.getExtnValue().getOctets());

		assertTrue(crlReason.getValue().intValue() == actualCrlReason.getValue()
				.intValue());
	}

	@Test
	public void testCrlReferenceExt() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Testing CrlReferenceExt");

		ExtensionsUtil util = new ExtensionsUtil();

		Date date = new Calendar.Builder().setDate(2020, 03, 12).build()
				.getTime();

		util.addCrlRefExt("check.crl.com", 1, date, false);
		// check
		Extension ext = util
				.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_crl.getId());

		ASN1Sequence asn1 = DERSequence.getInstance(ext.getParsedValue());
		ASN1TaggedObject o = DERTaggedObject.getInstance(asn1.getObjectAt(0));
		String s = DERIA5String.getInstance(o.getObject()).getString();

		assertTrue("Crl url not match", "check.crl.com".equalsIgnoreCase(s));
		assertTrue("Crl number not match", 1 == ASN1Integer
				.getInstance(asn1.getObjectAt(1)).longValueExact());
		try {
			assertTrue("Crl time does not match",
					date.getTime() == ASN1GeneralizedTime
							.getInstance(asn1.getObjectAt(2)).getDate()
							.getTime());
		} catch (ParseException e) {
			fail("Failed to get crl time: " + e.getMessage());
		}

		// CrlID crlId = CrlID.getInstance(new
		// DERSequence(ext.getExtnValue().toASN1Primitive()));
	}

	@Test
	public void testExtendedRevokedDefExt() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Testing ExtendedRevokedDefExt");

		ExtensionsUtil util = new ExtensionsUtil();

		util.addExtendedRevokedExt(false);
		// check
		Extension ext = util.getExtension(
				OCSPObjectIdentifiers.id_pkix_ocsp_extended_revoke.getId());

		assertTrue("ExtendedRevokedDefExt value error", DERNull.INSTANCE
				.equals(ext.getParsedValue().toASN1Primitive()));
	}

	@Test
	public void testNonceExt() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Testing NonceExt");

		ExtensionsUtil util = new ExtensionsUtil();

		util.addNonceExt(BigInteger.valueOf(1L), false);
		// check
		Extension ext = util
				.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());

		assertTrue("Nonce value does not match",
				1L == new BigInteger(ext.getExtnValue().getOctets())
						.longValue());
	}

	@Test
	public void testPreferredSigAlgoExt() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Testing PreferredSigAlgoExt");

		ExtensionsUtil util = new ExtensionsUtil();

		PreferredSigAlgo psa = new PreferredSigAlgo("1.2.3.4.5",
				SMIMECapability.aES128_CBC.getId(), null);

		util.addPreferredSigAlgoExt(
				new ArrayList<PreferredSigAlgo>(Arrays.asList(psa)), false);
		// check
		Extension ext = util.getExtension(
				OCSPObjectIdentifiers.id_pkix_ocsp_pref_sig_algs.getId());

		ASN1Sequence asn1 = DERSequence.getInstance(ext.getParsedValue());

		PreferredSigAlgo apsa = PreferredSigAlgo
				.getInstance(asn1.getObjectAt(0).toASN1Primitive());

		assertTrue("SignIdentifier does not match",
				psa.getSigIdentifier().getAlgorithm().toString().equals(
						apsa.getSigIdentifier().getAlgorithm().toString()));
		assertTrue("PublicKeyIdentifier does not match",
				psa.getPubKeyAlgIdentifier().getCapabilityID().equals(
						apsa.getPubKeyAlgIdentifier().getCapabilityID()));

	}

	@Test
	public void testServiceLocatorExt() {
		logger.info(StringUtils.repeat("=", 80));
		logger.info("Testing ServiceLocatorExt");

		ExtensionsUtil util = new ExtensionsUtil();

		String issuer = "cn=root,ou=test,o=dream,c=KR";
		String locator = issuer;

		AuthorityInformationAccess AIA = new AuthorityInformationAccess(
				new AccessDescription(new ASN1ObjectIdentifier("1.2.3.4.5"),
						new GeneralName(new X500Name(locator))));

		util.addServiceLocatorExt(issuer, AIA, false);
		// check
		Extension ext = util.getExtension(
				OCSPObjectIdentifiers.id_pkix_ocsp_service_locator.getId());

		ASN1Sequence asn1 = DERSequence.getInstance(ext.getParsedValue());

		assertTrue("Isser value does not match", issuer.equalsIgnoreCase(
				X500Name.getInstance(asn1.getObjectAt(0)).toString()));

		assertTrue("AIA does not match", AIA.equals(
				AuthorityInformationAccess.getInstance(asn1.getObjectAt(1))));
	}
}
