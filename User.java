import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileWriter;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
public class User {
    private static String salt = "ssshhhhhhhhhhh!!!!";
    public static String encrypt(String strToEncrypt, String secret)
    {
        try
        {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    public static void main(String args[]){
        String Session_Key = "Saurav1997Chak";
        Scanner sc = new Scanner(System.in);
        String name = sc.nextLine();
        String password = sc.nextLine();
        sc.close();
        password = User.encrypt(password,Session_Key);
        try{
            FileWriter fin = new FileWriter("UserCredentials//"+name+".txt");
            fin.write(name);
            fin.write("\n");
            fin.write(password);
            fin.close();
        }
        catch (Exception e){
            System.out.println(e);
        }
    }
}
