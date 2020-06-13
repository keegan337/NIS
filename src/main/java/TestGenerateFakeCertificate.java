import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Generates and saves a "fake_alice" certificate which has been signed by a fake certificate authority.
 * This certificate can be used with the messenger app to test certificate verification
 * An attacker can use this certificate to attempt to impersonate alice
 * The client that the attacker connects to should reject the attacker's certificate
 */
public class TestGenerateFakeCertificate {

	private static X509CertificateHolder fakeCaCert;
	private static PrivateKey fakeCaPrivateKey;

	public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException, KeyStoreException {
		// generate fake ca certificate
		X500Name name = CertificateUtils.getX500Name("ZA", "University of Cape Town", "Department of Computer Science", "dept@cs.uct.ac.za");
		KeyPair kp = CertificateUtils.generateKeyPair();
		fakeCaPrivateKey = kp.getPrivate();
		fakeCaCert = CertificateUtils.getX509CertificateHolder(kp.getPrivate(), kp.getPublic(), name, name);

		// generate fake alice certificate
		X500NameBuilder nameBuilder = new X500NameBuilder();
		nameBuilder.addRDN(BCStyle.NAME, "alice");
		KeyPair fakeAliceKP = CertificateUtils.generateKeyPair();
		X509CertificateHolder certHolder = CertificateUtils.getX509CertificateHolder(fakeCaPrivateKey, fakeAliceKP.getPublic(), fakeCaCert.getSubject(), nameBuilder.build());

		// save cert and keys to file
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		X509Certificate caCert = converter.getCertificate(fakeCaCert);
		X509Certificate clientCert = converter.getCertificate(certHolder);
		Certificate[] certChain = new Certificate[]{clientCert, caCert};
		CertificateUtils.saveToPKCS12(fakeAliceKP, certHolder, certChain, "fake_alice", "123", "fake_alice.p12", "123");
	}
}
