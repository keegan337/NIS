package Common;

public class ProtocolUtils {
	
	public final static String KEYWORD_SUCCESS = "SUCCESS";
	public final static String KEYWORD_FAILURE = "FAIL";
	
	public final static String KEYWORD_ACCEPTED = "ACCEPT";
	public final static String KEYWORD_REJECTED = "REJECT";
	
	/**
	 * Parses formatted header strings back into Header objects
	 *
	 * @param string formatted header string
	 * @return Header object representing the input string
	 * @throws Exception in the case of malformed header tags
	 */
	public static Header parseHeader(String string) throws Exception {
		String[] lines = string.trim().split("\\s*\n\\s*");
		
		Header header = new Header();
		
		for (String line : lines) {
			String[] parts = line.split("\\s*:\\s*");
			
			if (parts.length != 2 || parts[0].length() == 0 || parts[1].length() == 0)
				throw new Exception("Invalid header line: " + line);
			
			switch (parts[0]) {
				case Header.TAG_COMMAND:
					header.command = parts[1];
					break;
				case Header.TAG_DESTINATION:
					header.destination = parts[1];
					break;
				case Header.TAG_SOURCE:
					header.source = parts[1];
					break;
				case Header.TAG_LENGTH:
					header.length = Integer.parseInt(parts[1]);
					break;
				default:
					throw new Exception("Invalid header tag: " + parts[0]);
			}
		}
		
		return header;
	}
	
	/**
	 * Creates a new header string
	 *
	 * @param command
	 * @param length  byte length of data in body
	 * @return the header string.
	 */
	@Deprecated
	public static String buildHeaderString(String command, int length) {
		return Header.TAG_COMMAND + ": " + command + "\n" + "length: " + length;
		
	}
	
	@Deprecated
	public static String buildHeaderString(String command) {
		return Header.TAG_COMMAND + ": " + command;
		
	}
	
	/**
	 * Builders a new header string based on the populated header fields in a given header object
	 *
	 * @param header the header for which to build a string
	 * @return Formatted header string
	 */
	public static String buildHeaderString(Header header) {
		String headerString = "";
		if (header.command != null) {
			headerString += Header.TAG_COMMAND + ": " + header.command + "\n";
		}
		if (header.destination != null) {
			headerString += Header.TAG_DESTINATION + ": " + header.destination + "\n";
		}
		if (header.source != null) {
			headerString += Header.TAG_SOURCE + ": " + header.source + "\n";
		}
		if (header.length > -1) {
			headerString += Header.TAG_LENGTH + ": " + header.length;
		}
		
		return headerString;
	}
	
}
