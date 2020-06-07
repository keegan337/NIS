//import test.Header;
//import test.ProtocolUtils;
//
//import java.io.DataInputStream;
//import java.io.DataOutputStream;
//import java.io.IOException;
//import java.net.Socket;
//
///**
// * Thread for handling the login process for a client.
// * Spawns sending and receiving threads for the user upon successful login.
// */
//class ClientConnectThread extends Thread {
//	private final Socket socket;
//
//	private DataInputStream dataInputStream;
//	private DataOutputStream dataOutputStream;
//
//	public ClientConnectThread(Socket socket) throws IOException {
//		this.socket = socket;
//
//		this.dataInputStream = new DataInputStream(socket.getInputStream());
//		this.dataOutputStream = new DataOutputStream(socket.getOutputStream());
//	}
//
//	@Override
//	public void run() {
//		try {
//
//			User user;
//
//			while (true) {  // let the client make many attempts to get in
//				Header header = ProtocolUtils.parseHeader(dataInputStream.readUTF());
//
//				if (!header.command.equals(Header.COMMAND_AUTHENTICATE)) {
//					dataOutputStream.writeUTF("🖕");
//				}
//
//				String receivedUsername = dataInputStream.readUTF();
//				String receivedPassword = dataInputStream.readUTF();
//
//				user = Server.users.get(receivedUsername);
//
//				dataOutputStream.writeUTF(ProtocolUtils.buildHeaderString(Header.COMMAND_AUTHENTICATE_RESPONSE));
//
//				if (user != null && user.getPassword().equals(receivedPassword)) {
//					dataOutputStream.writeUTF(ProtocolUtils.KEYWORD_SUCCESS);
//					break;
//				} else {
//					dataOutputStream.writeUTF(ProtocolUtils.KEYWORD_FAILURE);
//				}
//			}
//
//			//client successfully logged in
//			user.connect(socket);
//
//		} catch (Exception ex) {
//			ex.printStackTrace();
//		}
//	}
//}
