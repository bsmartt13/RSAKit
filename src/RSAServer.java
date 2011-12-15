import java.io.*;
import java.net.*;
import java.security.Key;
import java.util.Scanner;


public class RSAServer {

	public String userName;
	public String userPass;

	public int port = 31336;
	public Socket s;
	private ServerSocket ss;
	private OutputStream outStream;
	private InputStream inStream;
	private DataOutputStream dOutStream;
	private DataInputStream dInStream;
	
	Scanner localscan;
	
	RSAKit serverKit;


	public RSAServer(){
		
		localscan = new Scanner(System.in);
		this.serverKit = new RSAKit();

		try {
			// networking
			ss = new ServerSocket(port);
			s = ss.accept();
			
			this.inStream = s.getInputStream();
			this.outStream = s.getOutputStream();
			this.dOutStream = new DataOutputStream(this.outStream);
			this.dInStream = new DataInputStream(this.inStream);
			
			this.dOutStream.flush();
			
			System.out.println("connection established.");

			
		} catch (IOException e) {
			System.out.println("Error accepting connection on socket");
			System.exit(-1);
		}
		
		int a = 0;
		a++;
	}

	
	public byte[] recv(Key k, boolean keyIsPublic){

		int sent_sz, recvd_sz;
		byte[] cipherBytes, decodedBytes;
		
		try {
			sent_sz = this.dInStream.readInt();
			cipherBytes = new byte[sent_sz];
			recvd_sz = this.dInStream.read(cipherBytes);
			if (recvd_sz != sent_sz) {
				System.out.println("something happened.");
				System.out.println("recvd = " + recvd_sz + "sent: " + sent_sz);
			}
			if (keyIsPublic)
				decodedBytes = this.serverKit.rsaDecrypt(cipherBytes, k, true);
			else
				decodedBytes = this.serverKit.rsaDecrypt(cipherBytes, k, false);
			return decodedBytes;
		} catch (IOException ioe) {
			System.out.println("I/O error: " + ioe.getMessage());
			System.exit(-1); 
		} catch (Exception e) {
			System.out.println("rsa decryption error: " + e.getMessage());
			System.exit(-1);
		}
		return null;
	}
	
	
	public static void main(String[] args){
		
		/*RSAServer serv = new RSAServer();
		 String decodedUsername = new String(
				serv.recv((Key) serv.serverKit., true));
		System.out.println("user: " + decodedUsername);
		String decodedPassword = new String(
				serv.recv((Key) serv.serverKit.cPubKey, true));
		System.out.println("password: " + decodedPassword);
		*/
		
	}
}