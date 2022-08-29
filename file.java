import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class file {
	
	//encryption
	 public String encrypt(String password, String key) throws 
     NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidKeyException, IllegalBlockSizeException, 
       BadPaddingException, UnsupportedEncodingException {
		 byte[] KeyData = key.getBytes();
		 SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
		 Cipher cipher = Cipher.getInstance("Blowfish");
		 cipher.init(Cipher.ENCRYPT_MODE, KS);
		 String encryptedtext = Base64.getEncoder().
				 encodeToString(cipher.doFinal(password.getBytes("UTF-8")));
		 return encryptedtext;

}
	 //decryption
	 public String decrypt(String encryptedtext, String key) 
			 throws NoSuchAlgorithmException, NoSuchPaddingException,
	InvalidKeyException, IllegalBlockSizeException, 
           BadPaddingException {
		 byte[] KeyData = key.getBytes();
		 SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
		 byte[] ecryptedtexttobytes = Base64.getDecoder().
            decode(encryptedtext);
		 Cipher cipher = Cipher.getInstance("Blowfish");
		 cipher.init(Cipher.DECRYPT_MODE, KS);
		 byte[] decrypted = cipher.doFinal(ecryptedtexttobytes);
		 String decryptedString = 
      new String(decrypted, Charset.forName("UTF-8"));
		 return decryptedString;

}

	 public static void main(String[] args) throws Exception
	    {
	 try {
	        File file = new File(
	            "C:\\Users\\ronwa\\Documents\\file.txt");
	 
	        // interpret words
	   
	        // Creating an object of BufferedReader class
	        BufferedReader br
	            = new BufferedReader(new FileReader(file));
	 
	        // Declaring a string variable
	        String str;
	        // Condition holds true till
	        // there is character in a string
	        while ((str = br.readLine()) != null)
	        
	        	
	            // Print the string
	            System.out.println(str);
	 } catch (FileNotFoundException e) {
	      System.out.println("An error occurred.");
	      e.printStackTrace();
	 }
	 "Str".replaceAll("[^a-zA-Z]", "");
	 final String password = "1234!";
  final String key = "mod3";
  System.out.println("Password: " + password);
  file obj = new file();
  String enc_output = obj.encrypt(password, key);
  System.out.println("Encrypted text: " + enc_output);
  String dec_output = obj.decrypt(enc_output, key);
  System.out.println("Decrypted text: " + dec_output);
  long preTime=System.currentTimeMillis();
  long postTime=System.currentTimeMillis();
  System.out.println("Time taken to compute in milliseconds->"+(postTime-preTime));
 }   
}
