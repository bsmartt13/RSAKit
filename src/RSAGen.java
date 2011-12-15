import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Scanner;
import javax.crypto.*;

public class RSAGen {
	//variables
	private String algorithm;
	private String translation;
	private String provider;
	private int keySize;
	//filenames
	public String publicKeyFName;
	public String privateKeyFName;
	//key objects
	private KeyPair keyPair;
	private Key publicKey;
	private Key privateKey;
	//utils
	private Scanner scanner;
	//key generation/specification
	private Cipher cipher;
	private SecureRandom random;
	private KeyPairGenerator generator;
	private KeyFactory keyFactory;
	private RSAPublicKeySpec rsaPublicSpec;
	private RSAPrivateKeySpec rsaPrivateSpec;

	public RSAGen() {

		System.out.println("[*]  Setting up control variables...");
		this.provider = "BC";
		this.translation = "RSA/None/NoPadding";
		this.algorithm = "RSA";
		System.out.println("[*]  algorithm: rsa");
		System.out.println("[+]  provider: bouncycastle (BC)");
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		this.scanner = new Scanner(System.in);
		this.getFileNames();
		this.getKeySize();
		this.random = new SecureRandom();
		System.out.println("[+]  Done.");
		System.out.println("[*]  Setting up RSA...");
		try {
			this.cipher = Cipher.getInstance(this.translation, this.provider);
			this.generator = KeyPairGenerator.getInstance(this.algorithm, this.provider);
			this.keyFactory = KeyFactory.getInstance(this.algorithm, this.provider);
		} catch (NoSuchPaddingException nsp_e) {
			System.out.println("[-]  Key generation failed.\n");
			System.out.println("[-]  Problem creating the cipher: NoSuchPaddingException " +
					"(" + this.translation + ")");
			System.err.println("[-]  NoSuchPaddingException: " + nsp_e.getMessage());
			System.exit(-1);
		} catch (NoSuchProviderException nspr_e) {
			System.out.println("[-]  Problem creating the cipher: NoSuchProviderException " +
					"(" + this.translation + ")");
			System.err.println("[-]  NoSuchProviderException: " + nspr_e.getMessage());
			System.exit(-1);
		} catch (NoSuchAlgorithmException nsa_e) {
			System.out.println("[-]  Problem creating the cipher: NoSuchAlgorithmException " +
					"(" + this.translation + ")");
			System.err.println("[-]  NoSuchAlgorithmException: " + nsa_e.getMessage());
			System.exit(-1);
		}
		System.out.println("[+]  RSA ready!");
		this.generator.initialize(this.keySize, this.random);
		this.keyPair = this.generator.generateKeyPair();
		System.out.println("[+]  Key generation successful!");
		System.out.println("[*]  Building public and private key specifications...");
		this.publicKey = this.keyPair.getPublic();
		this.privateKey = this.keyPair.getPrivate();
		try {
			this.rsaPublicSpec = this.keyFactory.getKeySpec(this.keyPair.getPublic(), RSAPublicKeySpec.class);
			this.rsaPrivateSpec = this.keyFactory.getKeySpec(this.keyPair.getPrivate(), RSAPrivateKeySpec.class);
		} catch (InvalidKeySpecException iks_e) {
			System.out.println("Error getting spec from key (InvalidKeySpecException");
			System.err.println("InvalidKeySpecException: " + iks_e.getMessage());
		}
		System.out.println("[+]  Got key specifications!");
		System.out.println("[*]  Writing keys to disk...");
		writeKey(this.rsaPublicSpec.getModulus(), this.rsaPublicSpec.getPublicExponent(), this.publicKeyFName);
		writeKey(this.rsaPrivateSpec.getModulus(), this.rsaPrivateSpec.getPrivateExponent(), this.privateKeyFName);
		System.out.println("[+]  Key files saved to disk [" + 
				this.publicKeyFName + "," + this.privateKeyFName + "]!");
		this.testKeys();
	}

	/**
	 *  Asks the user for public/private key file names.
	 */
	private void getFileNames() {
		System.out.println("Enter the name to use for public key:");
		this.publicKeyFName = this.scanner.nextLine();
		System.out.println("Enter the name to use for private key:");
		this.privateKeyFName = this.scanner.nextLine();
	}

	/**
	 *  Asks the user for a keysize (RSA key length).
	 */
	private void getKeySize() {
		System.out.println("Enter the keysize [16,32,...,1024,2048,4096]: ");
		this.keySize = this.scanner.nextInt();
	}

	/**
	 *  Given a public and private keypair, we encrypt with the public key
	 *  and decrypt with the private key, confirming their validity.
	 * @return a boolean indicating whether or not the keys properly encrypted /
	 * decrypted the test data.
	 * @exception InvalidKeyException if cipher.init() cannot read key.
	 * @exception BadPaddingException if the padding type 
	 */
	private boolean testKeys() {

		byte[] ciphertext_ba;
		byte[] cipheroutput_ba;
		System.out.println("[*]  testing keys...");
		System.out.println("[*]  starting encryption...");
		String plaintext_s = "0123456789!RSA SAFETY FOR THE WIN!0123456789";
		byte[] plaintext_ba = plaintext_s.getBytes();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, this.publicKey, random);
		} catch(InvalidKeyException ik_e) {
			System.out.println("[-]  encryption failed; InvalidKeyException raised.");
			System.err.println("[-]  InvalidKeyException: " + ik_e.getMessage());
			return false;
		}
		try {
			ciphertext_ba = cipher.doFinal(plaintext_ba);
		} catch (BadPaddingException bp_e) {
			System.out.println("[-]  encryption failed; BadPaddingException raised.");
			System.err.println("[-]  BadPaddingException: " + bp_e.getMessage());
			return false;
		} catch (IllegalBlockSizeException ibs_e) {
			System.out.println("[-]  encryption failed; IllegalBlockSizeException raised.");
			System.err.println("[-]  IllegalBlockSizeException: " + ibs_e.getMessage());
			return false;			
		}
		
		System.out.println("[+]  encryption successful!");
		System.out.println("[*]  starting decryption...");
		
		try {
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey, random);
		} catch(InvalidKeyException ik_e) {
			System.out.println("[-]  decryption failed; InvalidKeyException raised.");
			System.err.println("[-]  InvalidKeyException: " + ik_e.getMessage());
			return false;
		}
		try {
			cipheroutput_ba = cipher.doFinal(ciphertext_ba);
		} catch (BadPaddingException bp_e) {
			System.out.println("[-]  decryption failed; BadPaddingException raised.");
			System.err.println("[-]  BadPaddingException: " + bp_e.getMessage());
			return false;
		} catch (IllegalBlockSizeException ibs_e) {
			System.out.println("[-]  decryption failed; IllegalBlockSizeException raised.");
			System.err.println("[-]  IllegalBlockSizeException: " + ibs_e.getMessage());
			return false;			
		}
		System.out.println("[+]  decryption successful! let's compare the data.");
		String cipheroutput_s = new String(cipheroutput_ba);
		System.out.println("[*]  we started with: ");
		System.out.println("\t" + plaintext_s);
		System.out.println("[*]  we ended with: ");
		System.out.println("\t" + cipheroutput_s);
		boolean result = plaintext_s.equals(cipheroutput_s);
		System.out.println("Comparing the strings with .equals returns: " + result);
		return result;
	}

	static public void writeKey(BigInteger mod, BigInteger exp, String fname) {
		try {
			ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fname)));
			oout.writeObject(mod);
			oout.writeObject(exp);
			oout.close();
		} catch (IOException io_e) {
			System.out.println("Error writing object stream (key) to file.");
			System.err.println("IOException" + io_e.getMessage());
		}
	}
}