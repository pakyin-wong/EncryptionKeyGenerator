package encryptionutils;

import java.io.File;

import javax.crypto.SecretKey;

public class EncryptionUtilsCLI {
	 
	public static void main(String args[]) throws Exception{
		EncryptionUtils ekg = new EncryptionUtils();
		//Testing Base64
		String out = ekg.encodeToBase64String("Test".getBytes());
		System.out.println(out);
		out = new String(ekg.decodeBase64String(out));
		System.out.println(out);
		//Testing Base64End
		
		String originalFile = "./plain.jpg";
		String encryptedFile = "./ciphertext.enc"; 
		String deryptedFile = "./decrypted.jpg";
		
		SecretKey key = ekg.genSecretKey();
		String strKey = ekg.encodeToBase64String(key.getEncoded());
		System.out.println("key: " + strKey);
		
		byte[] iv = ekg.genIV();
		String strIv = ekg.encodeToBase64String(iv);
		System.out.println("IV: " + strIv);		
		
		
		//ekg.createTestFile(originalFile); //: Create Testing Data
		ekg.encrypt(key, iv, new File(originalFile), new File(encryptedFile));
		ekg.decrypt(key, iv, new File(encryptedFile), new File(deryptedFile));
		
		//byte[] ret = ekg.DecryptPartial(secretKey, iv, new File(encryptedFile), 100, 10);   
		//System.out.println(new String(ret));
	}
	
	
}
