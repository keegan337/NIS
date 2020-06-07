package Common;

/**
 * Wrapper class containing the data to be sent in each message
 * <p>
 * Strings contains the header string and any subsequent strings in the "body"
 * file should be null if not needed
 */
public class Deliverable {
	
	public final String[] strings;
	public final byte[] file;
	
	public Deliverable(String[] strings, byte[] file) {
		this.strings = strings;
		this.file = file;
	}
	
	public Deliverable(String[] strings) {
		this(strings, new byte[0]);
	}
}
