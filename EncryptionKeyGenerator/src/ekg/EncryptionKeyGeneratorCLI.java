package ekg;

public class EncryptionKeyGeneratorCLI {
	public static void main(String args[]){
		EncryptionKeyGenerator ekg = new EncryptionKeyGenerator();
		String out = ekg.encodeToBase64String("eeeee".getBytes());
		System.out.println(out);
		out = new String(ekg.decodeBase64String(out));
		System.out.println(out);
		
	}
	
	
}
