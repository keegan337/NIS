import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Main {
	private static int SERVER_PORT = 9000;
	
	/**
	 * @param args leave blank to run as server, otherwise provide ip and port to connect directly
	 */
	public static void main(String[] args) {
		if (args.length == 0) {
			startServer();
		}
//		else {
//
//		}
	}
	
	
	private static void startServer() {
		ServerSocket listenSocket = null;
		
		try {
			listenSocket = new ServerSocket(SERVER_PORT);
		}
		catch (IOException e) {
			System.err.println("Error whilst opening listening socket.");
			e.printStackTrace();
		}
		
		try {
			Socket clientSocket = listenSocket.accept();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}
}
