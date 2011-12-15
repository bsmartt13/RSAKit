import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class RSAUser {
	
	private Scanner scanner;
	private String publicKeyFName;
	private String privateKeyFName;
	private RSAPublicKeySpec rsaPublicKeySpec;
	private RSAPrivateKeySpec rsaPrivateKeySpec;
	public PublicKey publicKey;
	public PrivateKey privateKey;
	public KeyFactory keyFactory;  //global factory pass into constructor.  
								   //Or pass null for static getFactory().
	RSAUser(KeyFactory _keyfactory) {
		Security.addProvider( new org.bouncycastle.jce.provider.BouncyCastleProvider());
		this.scanner = new Scanner(System.in);
		this.getKeyFileNames();
		this.keyFactory = _keyfactory;
		if (this.keyFactory == null)
			this.keyFactory = RSAUser.getFactory("RSA", "BC");
		this.readPublicKey();
		this.readPrivateKey();
	}
	
	public static KeyFactory getFactory(String _algorithm, String _provider) {
		try {
			return KeyFactory.getInstance(_algorithm, _provider);
		} catch (NoSuchProviderException nsp_e) {
			System.out.println("NoSuchProviderException: " + nsp_e.getMessage());
			System.out.println("Couldn't find " + _provider + "provider");
			System.out.println("try Security.addProvider()?");
			System.exit(-1);
		} catch (NoSuchAlgorithmException nsa_e) {
			System.out.println("NoSuchAlgorithmException: " + nsa_e.getMessage());
			System.out.println("Couldn't load" + _algorithm + "algorithm.");
			System.out.println("has the java security package been imported?");
			System.exit(-1);
		} return null;
	}
	
	public void getKeyFileNames() {
		this.getPublicKeyFileName();
		this.getPrivateKeyFileName();
	}
	
	private void getPublicKeyFileName() {
		System.out.println("Name of your public key: ");
		this.publicKeyFName = this.scanner.nextLine();
	}
	
	private void getPrivateKeyFileName() {
		System.out.println("Name of your private key: ");
		this.privateKeyFName = this.scanner.nextLine();
	}

	public void readPublicKey() {
		System.out.println("[*]  readPublicKey()");
		System.out.print("[*]  attempting to open ObjectInputStream on " + this.publicKeyFName + "...");
		InputStream is = RSAGen.class.getResourceAsStream(this.publicKeyFName);
		try {
			ObjectInputStream objis = new ObjectInputStream(new BufferedInputStream(is));
			System.out.println("[+]  Done.");
			BigInteger m = (BigInteger) objis.readObject();
			BigInteger e = (BigInteger) objis.readObject();
			System.out.println("[+]  Got public key modulus and exponent.");
			System.out.print("[*]  Creating RSA specification from public mod/exp.");
			this.rsaPublicKeySpec = new RSAPublicKeySpec(m, e);
			this.publicKey = this.keyFactory.generatePublic(this.rsaPublicKeySpec);
			System.out.println("[+]  Done.");
			objis.close();
		} catch (IOException io_e) {
			System.out.println("[-]  IOException: error creating ObjectInputStream. " + 
					io_e.getMessage());
			System.out.println("[-]  readPublicKey() failed, exiting...");
			System.exit(-1);
		} catch (ClassNotFoundException cnf_e) {
			System.out.println("[-]  ClassNotFoundException: couldn't locate Object for InputStream. " 
					+ cnf_e.getMessage());
			System.out.println("[-]  readPublicKey() failed, exiting...");
			System.exit(-1);
		} catch (InvalidKeySpecException iks_e) {
			System.out.println("[-]  InvalidKeySpecException: couldn't parse rsaPublicKeySpec key format"
					+ iks_e.getMessage());
			System.out.println("[-]  readPublicKey() failed, exiting...");
			System.exit(-1);
		}
		System.out.println("[+]  readPublicKey() successful!");
	}

	public void readPrivateKey() {
		System.out.println("[*]  readPrivateKey()");
		System.out.print("[*]  attempting to open ObjectInputStream on " + this.privateKeyFName + "...");
		InputStream is = RSAGen.class.getResourceAsStream(this.privateKeyFName);
		try {
			ObjectInputStream objis = new ObjectInputStream(new BufferedInputStream(is));
			System.out.println("[+]  Done.");
			BigInteger m = (BigInteger) objis.readObject();
			BigInteger e = (BigInteger) objis.readObject();
			System.out.println("[+]  Got private key modulus and exponent.");
			System.out.print("[*]  Creating RSA specification from private mod/exp...");
			this.rsaPrivateKeySpec = new RSAPrivateKeySpec(m, e);
			this.privateKey = this.keyFactory.generatePrivate(this.rsaPrivateKeySpec);
			System.out.println("[+]  Done.");
			objis.close();
		} catch (IOException io_e) {
			System.out.println("[-]  IOException: error creating ObjectInputStream. " + 
					io_e.getMessage());
			System.out.println("[-]  readPrivateKey() failed, exiting...");
			System.exit(-1);
		} catch (ClassNotFoundException cnf_e) {
			System.out.println("[-]  ClassNotFoundException: couldn't locate obj for input stream. " 
					+ cnf_e.getMessage());
			System.out.println("[-]  readPrivateKey() failed, exiting...");
			System.exit(-1);
		} catch (InvalidKeySpecException iks_e) {
			System.out.println("[-]  InvalidKeySpecException: couldn't parse rsaPublicKeySpec key format"
					+ iks_e.getMessage());
			System.out.println("[-]  readPrivateKey() failed, exiting...");
			System.exit(-1);
		}
		System.out.println("[+]  readPrivateKey() successful!");
	}
	
	public static void main(String[] args) {
		RSAUser rsauser = new RSAUser(null);
		rsauser.privateKey.getAlgorithm();
		
	}
}