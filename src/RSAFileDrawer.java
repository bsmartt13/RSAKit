import java.io.*;
import java.util.*;

public class RSAFileDrawer {

	private File inputDirectory;
	private File[] contents;
	private Scanner scanner;

	/**
	 * Instantiate a new file drawer
	 * @param path is the input directory for the filedrawer.  You can pass null
	 * if you'd like to be prompted.  This is also a fallback if the supplied path string
	 * is not a valid (absolute) directory. 
	 * On linux, use in the form : /root/filedrawer/
	 */
	public RSAFileDrawer(String path) {
		System.out.println("[*]  Creating new file drawer....");
		this.scanner = new Scanner(System.in);
		if (path != null)
			this.inputDirectory = new File(path);
		else {
			System.out.println("No path supplied for FileDrawer.  " 
					+ "Please enter a valid absolute path (example: /root/img/): ");
			this.inputDirectory = new File(this.scanner.nextLine());
		}
		while (!this.inputDirectory.isDirectory()) {
			System.out.println("Unable to open input directory.");
			System.out.println("Java could not identify the string as a valid directory.");
			System.out.println("Please enter a new directory: ");
			this.inputDirectory = new File(this.scanner.nextLine());
		}
		System.out.println("[+]  Successfully opened input directory.  reading contents...");
		this.contents = this.inputDirectory.listFiles();
		System.out.println("+------------------------------------------------+");
		System.out.println("Files in " + this.inputDirectory + ":");
		for (int i = 0; i < this.contents.length; i++) {
			System.out.println("|----> " + this.contents[i].getName());
		}
		System.out.println("+------------------------------------------------+");
	}


	/**
	 * Wrapper for org.apache.commons.io.FileUtils.readFileToByteArray(File)
	 * @param inputFile to convert to byte array
	 * @return raw byte array of file
	 */
	public byte[] file2byteArray(File inputFile) {
		try {
			byte[] outputBytes = org.apache.commons.io.FileUtils.readFileToByteArray(inputFile);
			return outputBytes;
		} catch (IOException io_e) {
			System.out.println("IOException: could not read file before encryption.");
			System.out.println("Exiting...");
			System.exit(-1);
		}
		return null;
	}

	public void testByteArray(File inputFile) {
		try {
			byte[] outputBytes = org.apache.commons.io.FileUtils.readFileToByteArray(inputFile);
			this.byteArray2File(outputBytes, "TESTOUTPUT.jpg");
		} catch (IOException io_e) {
			System.out.println("IOException opening file: " + inputFile);
			System.err.println(io_e.getMessage());
			System.exit(-1);
		}
	}

	/**
	 * Write a file with FileOutputStream.
	 * @param inputBytes a file read into a byte array.
	 *
	 */
	public File byteArray2File(byte[] inputBytes, String fileName) {
		long fileSize = inputBytes.length;
		File outputFile = new File(fileName);
		FileOutputStream oStream;
		try {
			boolean fileCreated = outputFile.createNewFile();
			if (!fileCreated) {
				while (!fileCreated) {
					System.out.println("Error creating file " + fileName + ": File already exists.");
					System.out.println("Enter a new filename (type exit to quit): ");
					fileName = this.scanner.nextLine();
					outputFile = new File(fileName);
					if (fileName.equals("exit")) 
						System.exit(0);
					fileCreated = outputFile.createNewFile();
				}
				System.out.println("File " + fileName + " created.");
			}
		} catch (IOException io_e) {
			System.out.println("IOException while creating file.");
			System.out.println(io_e.getMessage());
			System.exit(-1);
		}
		try {
			oStream = new FileOutputStream(outputFile);
			if (inputBytes.length >= Integer.MAX_VALUE){
				System.out.println("Error byte array longer than supported filesize (" + fileSize + ")");
				return null;
			}
			oStream.write(inputBytes);
			oStream.flush();
			oStream.close();
		} catch (FileNotFoundException fnf_e) {
			System.out.println("FileNotFoundException: " + fnf_e.getMessage());
			System.out.println("byteArray2File failed for \"" + outputFile.getName() + 
			"\".  \nExiting...");
			System.exit(-1);
		} catch (IOException io_e) {
			System.out.println("IOException: could not read file before encryption.");
			System.out.println("Exiting...");
			System.exit(-1);
		}
		return outputFile;
	}

	public void test(){
		RSAFileDrawer fd = new RSAFileDrawer("/root/img/");
		System.out.println("Reading in file....");
		byte[] bytes = fd.file2byteArray(fd.contents[0]);
		System.out.println("Writing file....");
		fd.byteArray2File(bytes, "/root/img/out1.png");
		System.out.println("Done!");
		System.out.println("\nTesting byte array");
		fd.testByteArray(new File("/root/img/huge.jpg"));	
	}

	public static void main(String[] args) {

	}
}
