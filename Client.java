import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
class Client{
    private static String salt = "ssshhhhhhhhhhh!!!!";
    static void network_interface(String s){

    }
    static void user_input_interface(String s){

    }
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
    public static String decrypt(String strToDecrypt, String secret) {
        try
        {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
    public static void main(String args[])throws Exception{
        Scanner sc = new Scanner(System.in);
          String Session_Key = "Saurav1997Chak";
          String username,password;
          username = args[0];
          username = username+" ";
          password = args[1];
          password = password+" ";
          /*int num = (int)Math.random()%4;
          if(num == 0){
              username = "Saurav ";
              password = "324567 ";
          }
          else if(num == 1){
              username = "Ankit ";
              password = "987453 ";
          }
          else if(num == 2){
              username = "Vikash ";
              password = "342189 ";
          }
          else{
              username = "Pinaki ";
              password = "452398 ";
          }*/
          String auth = username+password+Session_Key;
          //System.out.println(auth);
          String start = "Hello Server";
          Socket s = new Socket("127.0.0.1",3333);
          DataInputStream din = new DataInputStream(s.getInputStream());
          DataOutputStream dout = new DataOutputStream(s.getOutputStream());
          ObjectInputStream dobj = new ObjectInputStream(s.getInputStream());
          dout.writeUTF(start);
          dout.flush();
          PublicKey pubkey = (PublicKey)dobj.readObject();
          System.out.println("Received public Key from Server");
          Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
          cipher.init(Cipher.ENCRYPT_MODE,pubkey);
          byte[] str = auth.getBytes();
          cipher.update(str);
          byte[] ciphertext = cipher.doFinal();
          dout.writeInt(ciphertext.length);
          dout.write(ciphertext);
          start = din.readUTF();
          System.out.println(start);
          while(!start.equals("Logout")){
              start = sc.nextLine();
              String enc = Client.encrypt(start,Session_Key);
              dout.writeUTF(enc);
              dout.flush();
              if(start.equals("listfiles")){
                String resposne = din.readUTF();
                resposne = Client.decrypt(resposne,Session_Key);
                File dir = new File(resposne);
                File listfile[] = dir.listFiles();
                for(int i=0;i<listfile.length;i++){
                System.out.println(listfile[i]);
                }
              }
              else{
              String resposne = din.readUTF();
              resposne = Client.decrypt(resposne,Session_Key);
              System.out.println(resposne);
              }
          }
          dobj.close();
          din.close();
          dout.close();
          s.close();
          sc.close();
    }
}