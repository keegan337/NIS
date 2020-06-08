import org.bouncycastle.operator.OperatorCreationException;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Scanner;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;


public class Main {
    private static int SERVER_PORT = 9000;
    private static String MACHINE_NAME = "localhost";
    private static final BlockingDeque<String> sendQueue = new LinkedBlockingDeque<>();
    private static Socket clientSocket = null;
    private static DataInputStream input;
    private static DataOutputStream output;
    private static String ID;

    private static X509Certificate caCertificate; //CA cert
    private static X509Certificate clientCertificate; // MY cert
    private static X509Certificate connectedClientCertificate; // THEIR cert

    private static PrivateKey clientPrivateKey; //MY private key

    private static final Scanner in = new Scanner(System.in);

    /**
     * @param args leave blank to run as server, otherwise provide ip and port to connect directly (1.2.3.4 1234)
     */
    public static void main(String[] args) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException, OperatorCreationException {

        String username = "alice";
        String password = "123";

        ensureCertificateExists(username, password);
        KeyStore store = CertificateUtils.loadKeyStoreFromPKCS12(username + ".p12", password);
        Certificate[] certChain = store.getCertificateChain(username);
        clientCertificate = (X509Certificate) certChain[0];
        caCertificate = (X509Certificate) certChain[1];
        clientPrivateKey = (PrivateKey) store.getKey(username, password.toCharArray());


//		Initial connection setup
        if (args.length == 0) {
            ID = "ServerClient";
            startServer();
            System.out.println("Connection setup on " + MACHINE_NAME + ":" + SERVER_PORT);
            System.out.println("UserID = " + ID);
        } else {
            ID = "ConnectingClient";
            MACHINE_NAME = args[0];
            SERVER_PORT = Integer.parseInt(args[1]);
            setupConnection();
            System.out.println("Connected to " + MACHINE_NAME + ":" + SERVER_PORT);
        }
        System.out.println("Setting up IO streams");
        setupIOStreams();

//		Perform certificate verification
        System.out.println("Sending certificate");
        sendCertificate(clientCertificate);
        System.out.println("Receiving certificate");
        connectedClientCertificate = receiveCertificate(input.readInt());
        validateCertificate(connectedClientCertificate);
        System.out.println("Certificate authenticated");
//		Create threads to allow free flow of messages in both directions
        createThreads();
        System.out.println("Threads created");


        String inputLine = in.nextLine();

        while (!inputLine.equals("EXIT")) {
            sendQueue.add(inputLine);
            inputLine = in.nextLine();
        }
    }

    /**
     * Check for certificate file and generate one if it does not exist.
     * Assign to clientCertificate
     */
    private static void ensureCertificateExists(String username, String password) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, OperatorCreationException, IOException {
        File f = new File(username + ".p12");
        if(!f.exists()) {
            GenerateClientCert.generateClientCert(username, password);
        }
    }

    /**
     * Hash the certificate using (algorithm) and compare with the CA signed certificate hash. Use local CA PubKey Copy
     *
     * @param cert received from connected client
     */
    private static void validateCertificate(X509Certificate cert) {

        try {
            cert.verify(caCertificate.getPublicKey());
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Invalid Key");
            sendQueue.add("Invalid Key"); //TODO Luc
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    /**
     * Receive the connected client's certificate over the network.
     * @param numBytes the length of the certificate to be received
     * @return the connected client's certificate
     */
    private static X509Certificate receiveCertificate(int numBytes) throws IOException, CertificateException {
        byte[] certAsBytes = new byte[numBytes];
        int bytesRead = input.read(certAsBytes, 0, numBytes);
        //System.out.println("Number of bytes read: " + bytesRead);
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certAsBytes));
        return cert;
    }

    /**
     * Send clients certificate over the network to the connected client
     *
     * @param cert to be sent.
     */
    private static void sendCertificate(X509Certificate cert) throws CertificateEncodingException, IOException {
        byte[] frame = cert.getEncoded();
        output.writeInt(frame.length);
        //System.out.println("Length of certificate: " + frame.length);
        output.write(frame);
    }

    /**
     * Connects the current user to the server.
     */
    private static void setupConnection() {
        try {
            clientSocket = new Socket(MACHINE_NAME, SERVER_PORT);
        } catch (IOException e) {
            System.err.println("Error creating client socket.");
            e.printStackTrace();
        }
    }

    /**
     * Sets up the data input and output streams over the clientSocket
     */
    private static void setupIOStreams() {
        try {
            input = new DataInputStream(clientSocket.getInputStream());
            output = new DataOutputStream(clientSocket.getOutputStream());
        } catch (IOException e) {
            System.err.println("Error creating data stream connection");
            e.printStackTrace();
        } catch (NullPointerException e) {
            System.err.println("Please ensure a client has been started as a server before attempting to connect.");
            e.printStackTrace();
        }
    }

    /**
     * Start the server as listening for a connection and connect to the clientSocket
     */
    private static void startServer() {
        ServerSocket listenSocket;

        try {
            System.out.println("Waiting for client to connect...");
            listenSocket = new ServerSocket(SERVER_PORT);
            clientSocket = listenSocket.accept();

//			ClientConnectThread clientConnectThread = new ClientConnectThread(clientSocket);
//			clientConnectThread.start();
        } catch (IOException e) {
            System.err.println("Error whilst opening listening socket/connecting client.");
            e.printStackTrace();
        }

    }

    /**
     * Creates two threads, one to deal with messages being sent to the server, by the client,
     * and one to deal with messages being sent to the client, by the server. Must be called after a successful
     * login has occurred.
     */
    private static void createThreads() {
        Thread readMsgThread = new Thread(() ->
        {
            while (true) {
                try {
//					TODO Jared: Change this to whatever format needs to be sent
                    String received = input.readUTF();
                    System.out.println("Received:");
                    System.out.println(received);

                } catch (EOFException eofEx) {
                    System.err.println("Hit end of file exception");
                    eofEx.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                    System.err.println("Client terminated connection");
                    System.exit(1);
                }
            }
        });
        Thread sendMsgThread = new Thread(() ->
        {
            while (true) {
                try {
//					TODO Jared: Change this to whatever format needs to be received

                    String message = sendQueue.take(); // take a message out of the queue if there is one available
                    output.writeUTF(message);


                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        readMsgThread.start();
        sendMsgThread.start();
    }
}
