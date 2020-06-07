
import Common.Deliverable;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;

public class Main {
	private static int SERVER_PORT = 9000;
	private static  String MACHINE_NAME = "localhost";
	private final BlockingDeque<Deliverable> sendQueue = new LinkedBlockingDeque();
	private static Socket clientSocket = null;
	private static DataInputStream input;
	private static DataOutputStream output;
	public static String username;
	/**
	 * @param args leave blank to run as server, otherwise provide ip and port to connect directly
	 */
	public static void main(String[] args) {
		if (args.length == 0) {
			startServer();
			System.out.println("Connection setup on "+ MACHINE_NAME + ":" + SERVER_PORT);
		}
		else {
			MACHINE_NAME = args[0];
			SERVER_PORT = Integer.parseInt(args[1]);
			setupConnection();
			System.out.println("Connected to "+ MACHINE_NAME + ":" + SERVER_PORT);
			
		}
		
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
		
		try {
			input = new DataInputStream(clientSocket.getInputStream());
			output = new DataOutputStream(clientSocket.getOutputStream());
		} catch (IOException e) {
			System.err.println("Error creating data stream connection");
			e.printStackTrace();
		}
	}
	
	/**
	 * Start the server as listening for a connection and connect to the clientSocket
	 */
	private static void startServer() {
		ServerSocket listenSocket = null;
		
		try {
			listenSocket = new ServerSocket(SERVER_PORT);
			Socket clientSocket = listenSocket.accept();
			
//			ClientConnectThread clientConnectThread = new ClientConnectThread(clientSocket);
//			clientConnectThread.start();
		}
		catch (IOException e) {
			System.err.println("Error whilst opening listening socket/connecting client.");
			e.printStackTrace();
		}
		
	}
}
