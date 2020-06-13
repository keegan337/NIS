import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class NetworkManager {
	private Socket socket;
	private DataInputStream input;
	private DataOutputStream output;

	/**
	 * Start the server as listening for a connection and connect to the clientSocket
	 */
	public void listenForConnection(int port) {
		try {
			System.out.println("Waiting for client to connect...");
			ServerSocket listenSocket = new ServerSocket(port);
			socket = listenSocket.accept();
			listenSocket.close();
			setupIOStreams();
		}
		catch (IOException e) {
			System.err.println("Error whilst opening listening socket/connecting client.");
			e.printStackTrace();
		}
	}

	/**
	 * Connects the current user to the server.
	 */
	public void connect(String host, int port) throws IOException {
		socket = new Socket(host, port);
		setupIOStreams();
	}

	/**
	 * Sets up the data input and output streams over the clientSocket
	 */
	private void setupIOStreams() {
		try {
			input = new DataInputStream(socket.getInputStream());
			output = new DataOutputStream(socket.getOutputStream());
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

	public void writeByte(byte b) throws IOException {
		output.write(b);
	}

	public byte readByte() throws IOException {
		return input.readByte();
	}

	public void writeByteArray(byte[] bytes) throws IOException {
		output.writeInt(bytes.length);
		output.write(bytes);
	}

	public byte[] readByteArray() throws IOException {
		int length = input.readInt();
		byte[] bytes = new byte[length];
		input.read(bytes);
		return bytes;
	}

	/**
	 * Creates a thread to continuously receive messages.
	 */
	public void startAsyncReceiveThread(BytesReceivedCallback callback) {
		Thread readMsgThread = new Thread(() -> {
			try {
				while (true) {
					callback.onBytesReceived(readByteArray());
				}
			} catch (IOException e) {
				System.out.println("stopped async receive thread");
				System.exit(0);
			}
		});
		readMsgThread.start();
	}

	public void close() throws IOException {
		socket.close();
	}

	public interface BytesReceivedCallback {
		/**
		 * Callback for when a message is received in a background thread in the NetworkManager
		 * @param bytes the received message data
		 */
		void onBytesReceived(byte[] bytes);
	}
}
