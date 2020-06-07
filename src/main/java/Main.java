
import Common.Deliverable;
import Common.Header;
import Common.ProtocolUtils;

import javax.swing.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;

import static Common.ProtocolUtils.parseHeader;

public class Main {
	private static int SERVER_PORT = 9000;
	private static String MACHINE_NAME = "localhost";
	private static final BlockingDeque<String> sendQueue = new LinkedBlockingDeque();
	private static Socket clientSocket = null;
	private static DataInputStream input;
	private static DataOutputStream output;
	public static String username;
	private static final int ID = (int) (Math.random() * 10);
	
	private static Scanner in = new Scanner(System.in);
	
	/**
	 * @param args leave blank to run as server, otherwise provide ip and port to connect directly
	 */
	public static void main(String[] args) {
		System.out.println("UserID = " + ID);
		if (args.length == 0) {
			startServer();
			System.out.println("Connection setup on " + MACHINE_NAME + ":" + SERVER_PORT);
		} else {
			MACHINE_NAME = args[0];
			SERVER_PORT = Integer.parseInt(args[1]);
			setupConnection();
			System.out.println("Connected to " + MACHINE_NAME + ":" + SERVER_PORT);
		}
		System.out.println("Setting up IO streams");
		setupIOStreams();
		createThreads();
		
		System.out.println("Threads created, you may type your messages:");
		String inputLine = in.nextLine();
		
		while (!inputLine.equals("EXIT")) {
			sendQueue.add(inputLine);
			inputLine = in.nextLine();
		}
	}
	
	/**
	 * Connects the current user to the server.
	 */
	private static void setupConnection() {
		try {
			clientSocket = new Socket(MACHINE_NAME, SERVER_PORT);
		}
		catch (IOException e) {
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
		}
		catch (IOException e) {
			System.err.println("Error creating data stream connection");
			e.printStackTrace();
		}
		catch (NullPointerException e) {
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
		}
		catch (IOException e) {
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
					String received = input.readUTF();
					System.out.println("Received:");
					System.out.println(received);
					
				}
				catch (EOFException eofEx) {
					System.err.println("Hit end of file exception");
					eofEx.printStackTrace();
				}
				catch (Exception e) {
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
					String message = sendQueue.take(); // take a message out of the queue if there is one available
					output.writeUTF(message);
					
					
				}
				catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
		readMsgThread.start();
		sendMsgThread.start();
	}
}
