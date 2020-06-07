package Common;

/**
 * Header representation enabling easy parsing and creating of headers.
 * <p>
 * Contains various Tag and Command strings.
 */
public class Header {
	
	public final static String TAG_COMMAND = "COMMAND";
	public final static String TAG_DESTINATION = "DESTINATION";
	public final static String TAG_SOURCE = "SOURCE";
	public final static String TAG_LENGTH = "LENGTH";
	
	public final static String COMMAND_AUTHENTICATE = "AUTHENTICATE";
	public final static String COMMAND_AUTHENTICATE_RESPONSE = "AUTH_RESP";
	public final static String COMMAND_MESSAGE = "MESSAGE";
	public final static String COMMAND_DISCONNECT = "DISCONNECT";
	public final static String COMMAND_CONNECT_CHAT = "CONNECT_CHAT";
	public final static String COMMAND_CONNECT_CHAT_RESPONSE = "CONNECT_RSP";
	public final static String COMMAND_FILE = "FILE";
	public final static String COMMAND_FILE_REQUEST = "FILE_REQUEST";
	public final static String COMMAND_FILE_RESPONSE = "FILE_RSP";
	
	public Header() {
	}
	
	public Header(String command, String destination, String source, int length) {
		this.command = command;
		this.destination = destination;
		this.source = source;
		this.length = length;
	}
	
	public String command;
	public String destination;
	public String source;
	public int length = -1;
	
	@Override
	public String toString() {
		return "Header{" +
				"COMMAND='" + command + '\'' +
				", DESTINATION='" + destination + '\'' +
				", SOURCE='" + source + '\'' +
				", LENGTH='" + length + '\'' +
				'}';
	}
}