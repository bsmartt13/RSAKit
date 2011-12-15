/*
 * RSAKit.java - rsa encryption for your java apps.
 *
 * Copyright (C) 2011  Bill Smartt <bsmartt13@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
import java.security.*;
import javax.crypto.*;

/**
 * This class implements various methods which can be used in RSA cryptography.
 * It can be added to existing server/client systems, or you can build a fresh
 * one on top of it.
 * 
 * @author Bill Smartt
 *
 */

public class RSAKit {

	private String provider;
	private String algorithm;
	private String transformation;

	private RSAUser client;
	private RSAUser server;
	
	// client and server shared
	private KeyFactory keyFactory;
	private Cipher cipher;


	public RSAKit() {
		this.provider = "BC";
		this.algorithm = "RSA";
		this.transformation = "RSA/None/NoPadding";
		Security.addProvider( new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try {
		this.cipher = Cipher.getInstance(this.transformation, this.provider);
		} catch (NoSuchPaddingException nsp_e) {
			System.out.println("NoSuchPaddingException: " + nsp_e.getMessage());
			System.out.println("Unable to do crypto without a cipher...");
			System.exit(-1);
		} catch (NoSuchProviderException nsp_e_cipher) {
			System.out.println("NoSuchProviderException: cipher: " + nsp_e_cipher.getMessage());
			System.out.println("Unable to do crypto without a cipher...");
			System.exit(-1);
		} catch (NoSuchAlgorithmException nsa_e_cipher) {
			System.out.println("NoSuchAlgorithmException: cipher: " + nsa_e_cipher.getMessage());
			System.out.println("Unable to do crypto without a cipher...");
			System.exit(-1);
		}
		try {
			this.keyFactory = KeyFactory.getInstance(this.algorithm, this.provider);
		} catch (NoSuchProviderException nsp_e) {
			System.out.println("NoSuchProviderException: " + nsp_e.getMessage());
			System.out.println("KeyFactory.getInstance() failed.  (rsa, bc)");
			System.out.println("try Security.addProvider()?");
			System.exit(-1);
		} catch (NoSuchAlgorithmException nsa_e) {
			System.out.println("NoSuchAlgorithmException: " + nsa_e.getMessage());
			System.out.println("Couldn't load RSA algorithms.");
			System.out.println("has the java security package been imported?");
			System.exit(-1);
		}
		this.server = new RSAUser(this.keyFactory);
		this.client = new RSAUser(this.keyFactory);
		this.client.keyFactory.getAlgorithm();
		this.server.keyFactory.getAlgorithm();
	}

	public byte[] rsaEncrypt(byte[] data, Key _key, boolean keyIsPublic) {
		try {
		if (keyIsPublic) 
			this.cipher.init(Cipher.ENCRYPT_MODE, (PublicKey) _key);
		else //key is private
			this.cipher.init(Cipher.ENCRYPT_MODE, (PrivateKey) _key);
		byte[] cipherData = cipher.doFinal(data);
		return cipherData;
		} catch (InvalidKeyException ik_e) {
			System.out.println("InvalidKeyException: rsaEncrypt(): " + ik_e.getMessage());
			System.out.println("Exiting due to encryption error...");
			System.exit(-1);
		} catch (BadPaddingException bp_e) {
			System.out.println("BadPaddingException: rsaEncrypt(): " + bp_e.getMessage());
			System.out.println("Exiting due to encryption error...");
			System.exit(-1);
		} catch (IllegalBlockSizeException ibs_e) {
			System.out.println("IllegalBlockSizeException: rsaEncrypt(): " + ibs_e.getMessage());
			System.out.println("Exiting due to encryption error...");
			System.exit(-1);
		}
		return null;
	}

	public byte[] rsaDecrypt(byte[] data, Key _key, boolean keyIsPublic) {
		try {
		if (keyIsPublic) 
			this.cipher.init(Cipher.DECRYPT_MODE, (PublicKey) _key);
		else //key is private
			this.cipher.init(Cipher.DECRYPT_MODE, (PrivateKey) _key);
		byte[] textData = cipher.doFinal(data);
		return textData;
		} catch (InvalidKeyException ik_e) {
			System.out.println("InvalidKeyException: rsaEncrypt(): " + ik_e.getMessage());
			System.out.println("Exiting due to encryption error...");
			System.exit(-1);
		} catch (BadPaddingException bp_e) {
			System.out.println("BadPaddingException: rsaEncrypt(): " + bp_e.getMessage());
			System.out.println("Exiting due to encryption error...");
			System.exit(-1);
		} catch (IllegalBlockSizeException ibs_e) {
			System.out.println("IllegalBlockSizeException: rsaEncrypt(): " + ibs_e.getMessage());
			System.out.println("Exiting due to encryption error...");
			System.exit(-1);
		}
		return null;
	}

	public int[] byte2int(byte[] input, int size){ 
		int[] output = new int[size];
		for (int i = 0; i < size; i++)
			output[i] = (int) input[i];
		return output;
	}

	public byte[] int2byte(int[] input, int size) {
		byte[] output = new byte[size];
		for (int i = 0; i < size; i++) 
			output[i] = (byte) input[i];
		return output;
	}
}