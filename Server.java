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

public class Server{
    private static String salt = "ssshhhhhhhhhhh!!!!";
    static String cd = System.getProperty("user.dir");
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
    static void command_processor(String msg)throws InterruptedException, IOException {
         String cmd = "";
         if(msg.equals("listfiles")){
               cmd ="LS";
               network_interface(cmd);
         }
         else if(msg.equals("cwd")){
               cmd = "PWD";
               network_interface(cmd);
         }
         else{
             for(int i=0;i<msg.length();i++){
                 if(msg.charAt(i)==' '){
                     cmd = msg.substring(0,i);
                     break;
                 }
             }
             if(cmd.equals("chgdir")){
                 cmd = "CD";
                 String path ="";
                 for(int i=0;i<msg.length();i++){
                     if(msg.charAt(i)==' '){
                        path = msg.substring(i+1,msg.length());
                        break;
                     }
                 }
                 network_interface(cmd,path);
             }
             if(cmd.equals("cp")){
                 cmd ="CP";
                 int count =0;
                 int f1,f2,f3;
                 f1 = f2 =f3=0;
                 String str1,str2,str3;
                 str1 = str2 =str3=" ";
                 for(int i=0;i<msg.length();i++){
                     if(msg.charAt(i)==' '){
                         count++;
                     }
                     if(msg.charAt(i)==' '&& count==1){
                         f1=i;
                     }
                     if(count==2 && msg.charAt(i)==' '){
                         f2 =i;
                     }
                     if(count == 3 && msg.charAt(i)==' '){
                         f3 =i;
                     }
                 }
                 str1 = msg.substring(f1+1,f2);
                 str2 = msg.substring(f2+1,f3);
                 str3 = msg.substring(f3+1,msg.length());
                 System.out.println(str1);
                 System.out.println(str2);
                 System.out.println(str3);
                 network_interface(cmd,str1,str2,str3);
             }
             if(cmd.equals("mv")){
                 cmd = "MV";
                 int count =0;
                 int f1,f2,f3;
                 f1 = f2 =f3=0;
                 String str1,str2,str3;
                 str1 = str2 =str3=" ";
                 for(int i=0;i<msg.length();i++){
                     if(msg.charAt(i)==' '){
                         count++;
                     }
                     if(msg.charAt(i)==' '&& count==1){
                         f1=i;
                     }
                     if(count==2 && msg.charAt(i)==' '){
                         f2 =i;
                     }
                     if(count == 3 && msg.charAt(i)==' '){
                         f3 = i;
                     }
                 }
                 str1 = msg.substring(f1+1,f2);
                 str2 = msg.substring(f2+1,f3);
                 str3 = msg.substring(f3+1,msg.length());
                 System.out.println(str1);
                 System.out.println(str2);
                 System.out.println(str3);
                 network_interface(cmd,str1,str2,str3);
             }
         }
    }
    static void network_interface(String msg){
        if(msg.equals("LS")){
            File dir = new File(cd);
            File listfile[] = dir.listFiles();
            for(int i=0;i<listfile.length;i++){
                System.out.println(listfile[i]);
            }
        }
        else if(msg.equals("PWD")){

            System.out.println(cd);
        }
        else{

        }
    }
    static void network_interface(String msg,String path){
        if(msg.equals("CD")){
            cd = path;
            System.out.println(cd);
        }
    }
    static void network_interface(String msg,String file, String src,String desc)throws IOException{
        if(msg.equals("CP")){
            String s = "";
            File f1 = new File(src+"//"+file);
            Scanner filereader = new Scanner(f1);
            while (filereader.hasNextLine()){
                s += filereader.nextLine();
                s +="\n";
            }
            System.out.println(s);
            FileWriter fw1 = new FileWriter(desc+"//"+file);
            fw1.write(s);
            fw1.close();
            filereader.close();
        }
        if(msg.equals("MV")){
            String s = "";
            File f1 = new File(src+"//"+file);
            Scanner filereader = new Scanner(f1);
            while (filereader.hasNextLine()){
                s += filereader.nextLine();
                s +="\n";
            }
            System.out.println(s);
            FileWriter fw1 = new FileWriter(desc+"//"+file);
            fw1.write(s);
            fw1.close();
            f1.delete();
            filereader.close();
        }
    }

    public static void main(String args[])throws Exception{
        KeyPairGenerator keypairGen = KeyPairGenerator.getInstance("RSA");
        keypairGen.initialize(2048);
        KeyPair pair = keypairGen.generateKeyPair();
        PrivateKey privkey = pair.getPrivate();
        PublicKey pubkey = pair.getPublic();
        try{
            FileWriter fw = new FileWriter("ServerKeys//serverpriv.txt");
            fw.write(privkey.toString());
            fw.close();
        }
        catch(Exception e){
            System.out.println(e);
        }
        try{
            FileWriter fw1 = new FileWriter("ServerKeys//serverpub.txt");
            fw1.write(pubkey.toString());
            fw1.close();
        }
        catch(Exception e) {
            System.out.println(e);
        }
        ServerSocket ss = new ServerSocket(3333);
        Socket s = ss.accept();
        DataInputStream din = new DataInputStream(s.getInputStream());
        DataOutputStream dout = new DataOutputStream(s.getOutputStream());
        ObjectOutputStream dobj = new ObjectOutputStream(s.getOutputStream());
        InputStream in = s.getInputStream();
        Scanner sc = new Scanner(System.in);
        String msg = din.readUTF();
        System.out.println(msg);
        dobj.writeObject(pubkey);
        dobj.flush();
        int len = din.readInt();
        byte m[] = new byte[len];
        if(len>0){
        din.readFully(m,0,m.length);}
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,pair.getPrivate());
        cipher.update(m);
        byte msgauth[] = cipher.doFinal();
        msg = new String(msgauth);
        String user,pass,key;
        user = pass = key ="";
        int count=0;
        int k=0;
        for(int i=0;i<msg.length();i++)
        {
            if(msg.charAt(i)==' '&& count==0){
                user = msg.substring(k,i);
                count++;
                k =i+1;
            }
            else if(msg.charAt(i)==' '&& count==1){
                pass = msg.substring(k,i);
                count++;
                k = i+1;
            }
            if(count==2){
                key = msg.substring(k,msg.length());
                break;
            }
        }
        File dir = new File("UserCredentials");
        File list[] = dir.listFiles();
        String z = "UserCredentials/"+user+".txt";
        for(int i=0;i<list.length;i++)
        {
            if(z.equals(list[i].toString())){
                try{
                    File f1 = new File("UserCredentials//"+user+".txt");
                    Scanner filereader = new Scanner(f1);
                    String data = "";
                    while(filereader.hasNextLine())
                    {
                        data = filereader.nextLine();
                    }
                    //System.out.println(data);
                    data = Server.decrypt(data,key);
                    if(data.equals(pass))
                    {
                        System.out.println("Client Authenticated");
                    }
                    filereader.close();
                }
                catch (Exception e)
                {
                    System.out.println(e);
                }
            }
        }
        dout.writeUTF("Authenticated");
        while(!msg.equals("Logout")){
            msg = din.readUTF();
            msg = Server.decrypt(msg,key);
            command_processor(msg);
            System.out.println("------------------------------------------------");
            String reply = "Action "+msg+" done";
            if(msg.equals("cwd")){
                 reply = cd;
                 reply = Server.encrypt(reply,key);
                 dout.writeUTF(reply);
                 dout.flush();

            }
            else if(msg.equals("listfiles"))
            {
                reply = cd;
                 reply = Server.encrypt(reply,key);
                 dout.writeUTF(reply);
                 dout.flush();
            }
            else{
            reply = Server.encrypt(reply,key);
            dout.writeUTF(reply);
            dout.flush();
            System.out.println("------------------------------------------------");
            }
        }
        sc.close();
        dout.flush();
        dobj.close();
        dout.close();
        din.close();
        in.close();
        s.close();
        ss.close();
    }
}