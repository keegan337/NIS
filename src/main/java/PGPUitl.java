import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.*;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.cms.*;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.Streams;

public class PGPUitl {

    public static byte[] signData(byte[] data, final X509Certificate signingCertificate, PrivateKey signingKey) throws CertificateEncodingException, OperatorCreationException, CMSException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] signedMessage = null;

        //Creating a list of X509Certificate objects
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>();

        //Creating a CMSTypedData object using the data byte array that was sent to the method
        CMSTypedData cmsData = new CMSProcessableByteArray(data);

        certificateList.add(signingCertificate);

        //Creating a new store from the certificate list
        Store certificateStore = new JcaCertStore(certificateList);

        //Creating an object that will be used to generate a CMSSignedData object
        CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);

        cmsSignedDataGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner, signingCertificate));

        cmsSignedDataGenerator.addCertificates(certificateStore);

        //Create the CMSSignedData object from the cmsData
        CMSSignedData cms = cmsSignedDataGenerator.generate(cmsData, true);

        signedMessage = cms.getEncoded();

        return signedMessage;
    }

    public static String verifSignData(final byte[] signedData) throws CMSException, IOException, OperatorCreationException, CertificateException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(signedData);

        ASN1InputStream asn1InputStream = new ASN1InputStream(byteArrayInputStream);

        CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asn1InputStream.readObject()));

        asn1InputStream.close();

        byteArrayInputStream.close();

        //Return any X.509 certificate objects in this SignedData structure as a Store of X509CertificateHolder objects
        Store certificates = cmsSignedData.getCertificates();

        //Return the collection of signers that are associated with the signatures for the message
        SignerInformationStore signers = cmsSignedData.getSignerInfos();

        Collection<SignerInformation> signerInformationCollection = signers.getSigners();

        SignerInformation signer = signerInformationCollection.iterator().next();

        Collection<X509CertificateHolder> certificateHolders = certificates.getMatches(signer.getSID());

        Iterator<X509CertificateHolder> certificateHolderIterator = certificateHolders.iterator();

        X509CertificateHolder certificateHolder = certificateHolderIterator.next();

        boolean verifiedResult = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificateHolder));

        CMSTypedData cmsProcessable = cmsSignedData.getSignedContent();

        if (!verifiedResult) {
            return "Message Insecure";
        }

        String message = new String((byte[])cmsProcessable.getContent());
        return message;
    }

    public static void encryptFile(OutputStream out, byte[] inputByteArray, PGPPublicKey encKey) throws IOException, NoSuchProviderException, PGPException {
        //Adds a new Security Provider
        Security.addProvider(new BouncyCastleProvider());

        ByteArrayInputStream in = new ByteArrayInputStream(inputByteArray);
        //This implements an output stream in which the data is written into a byte array
        ByteArrayOutputStream byteStreamOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

        //Construct a new compressed data generator with the ZIP algorithm
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

        OutputStream outputStream = literalDataGenerator.open(compressedDataGenerator.open(byteStreamOut), PGPLiteralData.BINARY, "filename", in.available(), new Date());
        Streams.pipeAll(in, outputStream);
        //Read a file and write its contents as a literal data packet to the compressed data generator stream
        //PGPUtil.writeFileToLiteralData(compressedDataGenerator.open(byteStreamOut), PGPLiteralData.BINARY, new File(fileName));

        compressedDataGenerator.close();

        //Constructs a PGPEncryptedDataGenerator Object to encrypt raw data
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES).setSecureRandom(new SecureRandom()));

        //Adds the encryption method, which is the public key sent to this method in this instance
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

        byte[] bytes = byteStreamOut.toByteArray();

        //Create an OutputStream based on the output stream sent to this method and the length of variable bytes,
        // and write a single encrypted object of known length to the output stream

        //Create a new output stream which is created based on the configured method of public key encryption, to create a new encrypted object, based on the length of the byte stream
        OutputStream encryptedCompressedOutputstream = encryptedDataGenerator.open(out, bytes.length);

        encryptedCompressedOutputstream.write(bytes);

        encryptedCompressedOutputstream.close();

        out.close();

    }

    public static byte[] decryptFile(InputStream in, PGPPrivateKey pgpPrivateKey) throws IOException, PGPException, InvalidCipherTextException {
        Security.addProvider(new BouncyCastleProvider());

        //Obtains a stream that can be used to read PGP data from the provided stream
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory jcaPGPFactory;

        //Create an object factory suitable for reading PGP objects
        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());

        //Return the next object in the stream, or null if the end of stream is reached
        Object pgpObject = pgpObjectFactory.nextObject();

        PGPEncryptedDataList pgpEncryptedDataList;

        // The first object might be a PGP marker packet
        if (pgpObject instanceof PGPEncryptedDataList) {

            pgpEncryptedDataList = (PGPEncryptedDataList) pgpObject;

        } else {

            pgpEncryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();

        }

        Iterator<PGPPublicKeyEncryptedData> iterator = pgpEncryptedDataList.getEncryptedDataObjects();
        PGPPublicKeyEncryptedData publicKeyEncryptedDataObject = null;
        while (iterator.hasNext()) {
            publicKeyEncryptedDataObject = iterator.next();
        }

        InputStream decryptedDataInputStream = publicKeyEncryptedDataObject.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivateKey));

        jcaPGPFactory = new JcaPGPObjectFactory(decryptedDataInputStream);

        PGPCompressedData pgpCompressedData = (PGPCompressedData) jcaPGPFactory.nextObject();

        //Construct a JcaPGPObjectFactory object with an input stream that decompresses and returns data in the compressed packet
        jcaPGPFactory = new JcaPGPObjectFactory(pgpCompressedData.getDataStream());

        PGPLiteralData literalData = (PGPLiteralData) jcaPGPFactory.nextObject();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        //Return the input stream representing the data stream
        InputStream dataStream = literalData.getDataStream();

        int dataByte;
        while ((dataByte = dataStream.read()) >= 0) {
            byteArrayOutputStream.write(dataByte);
        }

        //System.out.println("THE ENCRYPTED MESSAGE FROM THE ALIENS IS: " + byteArrayOutputStream.toString());

        //byteArrayOutputStream.writeTo(new FileOutputStream(literalData.getFileName()));
        return byteArrayOutputStream.toByteArray();

    }
}
