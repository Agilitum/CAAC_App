/* Copyright Rene Mayrhofer, 2006-03-19
 * @ author Ludwig 
 * This file has be copied under the terms of the GNU GPL version 2.
 */ 

package com.ludwig.caac_app;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBMPString;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROutputStream;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.cms.Time;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.RDN;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.X500NameBuilder;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.BasicConstraints;
import org.spongycastle.asn1.x509.DigestInfo;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.asn1.x509.ExtensionsGenerator;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.GeneralNames;
import org.spongycastle.asn1.x509.KeyUsage;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.TBSCertificate;
import org.spongycastle.asn1.x509.V3TBSCertificateGenerator;
import org.spongycastle.asn1.x509.X509CertificateStructure;
import org.spongycastle.asn1.x509.X509ObjectIdentifiers;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509ExtensionUtils;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateHolder;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.spongycastle.crypto.CryptoException;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.encodings.PKCS1Encoding;
import org.spongycastle.crypto.engines.RSAEngine;
import org.spongycastle.crypto.generators.RSAKeyPairGenerator;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.RSAKeyGenerationParameters;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.spongycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.spongycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.provider.X509CertificateObject;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.DigestCalculator;
import org.spongycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.bc.BcRSAContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.spongycastle.x509.extension.SubjectKeyIdentifierStructure;



public class X509CertificateGenerator {

	/** This holds the certificate of the CA used to sign the new certificate. The object is created in the constructor. */
	private X509Certificate caCert;

	/** This holds the private key of the CA used to sign the new certificate. The object is created in the constructor. */
	private RSAPrivateCrtKeyParameters caPrivateKey;


	public X509CertificateGenerator(String caFile, String caPassword, String caAlias) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException,
			UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException 
			{
		// load CA private key and certificate

		KeyStore caKs = KeyStore.getInstance("PKCS12");
		caKs.load(new FileInputStream(new File(caFile)), caPassword.toCharArray());

		// load the key entry from the keystore
		Key key = caKs.getKey(caAlias, caPassword.toCharArray());
		if (key == null){
			throw new RuntimeException("Error: Null key from keystore!");
		}

		RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) key;
		caPrivateKey = new RSAPrivateCrtKeyParameters(privKey.getModulus(),
				privKey.getPublicExponent(), privKey.getPrivateExponent(),
				privKey.getPrimeP(), privKey.getPrimeQ(), privKey.getPrimeExponentP(),
				privKey.getPrimeExponentQ(), privKey.getCrtCoefficient());

		// get the certificate
		caCert = (X509Certificate) caKs.getCertificate(caAlias);
		if(caCert == null){
			throw new RuntimeException("Error: Null cert from keystore!");
		}

		caCert.verify(caCert.getPublicKey());
			}

	/**
	 * create the certificate
	 * @param dn
	 * @param validityDays
	 * @param exportFile
	 * @param exportPassword
	 * @return
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws SecurityException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException
	 * @throws DataLengthException
	 * @throws CryptoException
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 * @throws CertificateException
	 * @throws InvalidKeySpecException
	 */
/*	public boolean createCertificate(String dn, int validityDays, String exportFile, String exportPassword) 
			throws 	IOException, InvalidKeyException, SecurityException, SignatureException, NoSuchAlgorithmException, DataLengthException, 
			CryptoException, KeyStoreException, NoSuchProviderException, CertificateException, InvalidKeySpecException 
			{
		SecureRandom sr = new SecureRandom();

		PublicKey pubKey;
		PrivateKey privKey;

		Date startDate = new Date();
		Date expiryDate = new Date(System.currentTimeMillis() + TimeUnit.MILLISECONDS.convert(365, TimeUnit.DAYS));

		// generate public / private key pair
		RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
		rsaGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(3), sr, 1024, 80));

		AsymmetricCipherKeyPair keypair = rsaGen.generateKeyPair();
		RSAKeyParameters publicKey = (RSAKeyParameters) keypair.getPublic();
		RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keypair.getPrivate();

		// get correct encoding for the certificate
		//RSAPublicKeyStructure pkStruct = new RSAPublicKeyStructure(publicKey.getModulus(), publicKey.getExponent());

		// JCE format is needed for the certificates because getEncoded() is needed
		pubKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(publicKey.getModulus(), 
				publicKey.getExponent()));

		privKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(publicKey.getModulus(), 
				publicKey.getExponent(), privateKey.getExponent(), privateKey.getP(), privateKey.getQ(), 
				privateKey.getDP(), privateKey.getDQ(), privateKey.getQInv()));

		// expiry date
		Calendar expiry = Calendar.getInstance();
		expiry.add(Calendar.DAY_OF_YEAR, validityDays);

		// instantiate CertificateGenerator
		V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
		X500Name x500Name = new JcaX509CertificateHolder(caCert).getSubject();
		RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
		// X509Name x509Name = new X509Name ("CN = " + dn);

		// set certifcate parameters
		certGen.setSerialNumber(new ASN1Integer(BigInteger.valueOf(System.currentTimeMillis())));
		//certGen.setIssuer(PrincipalUtil.getSubjectX509Principal(caCert));
		certGen.setStartDate(new Date(System.currentTimeMillis()));
		certGen.setEndDate(new Time(expiry.getTime()));
		certGen.setSubject(cn);
		DERObjectIdentifier sigOID = X509Util.getAlgorithmID("SHA1WithRSAEncryption");
		AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(sigOID, new DERNull());
		certGen.setSignature(sigAlgId);
		certGen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(
				new ByteArrayInputStream(pubKey.getEncoded())).readObject()));

		TBSCertificate tbsCert = certGen.generateTBSCertificate();

		// signing the certificate
		// hard coding of SHA1 + RSA !!!
		SHA1Digest digester = new SHA1Digest();
		PKCS1Encoding rsa = new PKCS1Encoding(new RSAEngine());
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		DEROutputStream dOut = new DEROutputStream(bOut);
		dOut.writeObject(tbsCert);
		byte[] signature;
		byte[] certBlock = bOut.toByteArray();

		// create digest
		digester.update(certBlock, 0, certBlock.length);
		byte[]	hash = new byte[digester.getDigestSize()];
		digester.doFinal(hash, 0);

		// sign it
		rsa.init(true, caPrivateKey);
		DigestInfo dInfo = new DigestInfo(new AlgorithmIdentifier(
				X509ObjectIdentifiers.id_SHA1, null), hash);
		byte[] digest = dInfo.getEncoded(ASN1Encodable.DER);
		signature = rsa.processBlock(digest, 0, digest.length);

		// and finally construct the certificate structure
		ASN1EncodableVector  v = new ASN1EncodableVector();

		v.add(tbsCert);
		v.add(sigAlgId);
		v.add(new DERBitString(signature));

		// write certificate as PKCS12 file

		X509CertificateObject clientCert = new X509CertificateObject(
				new X509CertificateStructure(new DERSequence(v)));
		clientCert.verify(caCert.getPublicKey());

		// export as PKCS12 formatted file along with the private key and the CA certificate
		PKCS12BagAttributeCarrier bagCert = clientCert;
		bagCert.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
				new DERBMPString("Certificate for IPSec CAAC access"));
		bagCert.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
				new SubjectKeyIdentifierStructure(pubKey));

		KeyStore store = KeyStore.getInstance("PKCS12");
		store.load(null, null);

		X509Certificate[]	chain = new X509Certificate[2];

		// first the client, then the Ca certificate
		chain[0] = clientCert;
		chain[1] = caCert;

		store.setKeyEntry("Certificate for IPSec CAAC access", privKey,
				exportPassword.toCharArray(), chain);

		FileOutputStream fOut = new FileOutputStream(exportFile);
		store.store(fOut, exportPassword.toCharArray());

		return true;
			}
*/
	/**
	 * Build a V3 certificate to use as an CAAC end entity certificate
	 */

	private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week
	private static SignatureAlgorithmIdentifierFinder algFinder = new DefaultSignatureAlgorithmIdentifierFinder();

	public static X509CertificateHolder buildEndEntityCert(AsymmetricKeyParameter entityKey, AsymmetricKeyParameter caKey, X509CertificateHolder caCert)
			throws Exception
			{
		SubjectPublicKeyInfo entityKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(entityKey);

		X509v3CertificateBuilder   certBldr = new X509v3CertificateBuilder(
				caCert.getSubject(),
				BigInteger.valueOf(1),
				new Date(System.currentTimeMillis()),
				new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
				new X500Name("CN=CAAC End Entity Certificate"),
				entityKeyInfo);

		X509ExtensionUtils extUtils = new X509ExtensionUtils((DigestCalculator) new SHA1Digest());

		certBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
		.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(entityKeyInfo))
		.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
		.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

		AlgorithmIdentifier sigAlg = algFinder.find("SHA1withRSA");
		AlgorithmIdentifier digAlg = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlg);

		ContentSigner signer = new BcRSAContentSignerBuilder(sigAlg, digAlg).build(caKey);

		return certBldr.build(signer);
			}
	
    /**
     * Create a random 2048 bit RSA key pair
     */
    public static AsymmetricCipherKeyPair generateRSAKeyPair()
        throws Exception
    {
        AsymmetricCipherKeyPairGenerator kpGen = new RSAKeyPairGenerator();

        kpGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x11), new SecureRandom(), 2048, 12));

        return kpGen.generateKeyPair();
    }

	/**
	 * generation and verification of a PKCS#10 (Certification Request Standart) request
	 * @throws Exception 
	 */
	public static Boolean correctCertificate(KeyPair kp, X500Name subject, String sigName) throws Exception{
		Security.addProvider(new BouncyCastleProvider());

		//String sigName = "SHA1withRSA";


		//KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

		//kpg.initialize(1024);

		//KeyPair kp = kpg.genKeyPair();

		/*X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

		x500NameBuilder.addRDN(BCStyle.C, "AU");
		x500NameBuilder.addRDN(BCStyle.ST, "OXFORD");
		x500NameBuilder.addRDN(BCStyle.L, "Manchester");
		x500NameBuilder.addRDN(BCStyle.O, "CAAC");

		X500Name subject = x500NameBuilder.build();
		 */
		PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(
				subject, kp.getPublic());

		ExtensionsGenerator extGen = new ExtensionsGenerator();

		extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(
				GeneralName.rfc822Name, "feedback@CCCA.co.uk")));

		requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
		
		PKCS10CertificationRequest req1 = requestBuilder.build(new JcaContentSignerBuilder(sigName).setProvider("BC").build(kp.getPrivate()));
		
		if(req1.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(kp.getPublic()))){
			return true;
		}
		else
			return false;
	}
}
