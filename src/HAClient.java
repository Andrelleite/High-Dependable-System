import javax.crypto.*;
import javax.print.attribute.standard.RequestingUserName;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.IdentityHashMap;
import java.util.Iterator;

import static java.nio.charset.StandardCharsets.UTF_8;


public class HAClient extends Thread{

    private String entity;
    private ServerInterface h;
    private IdentityHashMap<Integer,Integer> identity;
    private SecretKey symKey;

    public void setSymKey(SecretKey symKey) {
        this.symKey = symKey;
    }

    public SecretKey getSymKey() {
        return symKey;
    }

    public HAClient(){
        super();
    }

    public void handshake(int op,String user,String x, String y, String epoch){
        try {
            try {
                this.h = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");

                SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
                String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
                System.out.println("lado do ha client: " + encodedKey);
                this.setSymKey(secretKey);

                FileInputStream fis01 = new FileInputStream("src/keys/serverPub.key");
                byte[] encoded2 = new byte[fis01.available()];
                fis01.read(encoded2);
                fis01.close();
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded2);
                KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
                PublicKey pub = keyFacPub.generatePublic(publicKeySpec);

                Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipherRSA.init(Cipher.ENCRYPT_MODE, pub);
                byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
                byte[] cipherBytes = cipherRSA.doFinal(keyBytes);
                String encryptedKey = Base64.getEncoder().encodeToString(cipherBytes);

                h.HASubscribe(encryptedKey);
                communicate(this.h, op,user,x,y,epoch);
            }catch (RemoteException | MalformedURLException | NotBoundException e){
                retry(op,user,x,y,epoch);
            }
        } catch (Exception e) {
            System.out.println("Exception in main: " + e);
            e.printStackTrace();
        }
    }

    private void communicate(ServerInterface h, int op,String user,String x, String y, String epoch) throws IOException, ClassNotFoundException {

        ArrayList<Report> reports;
        System.setProperty("java.rmi.transport.tcp.responseTimeout", "2000");
        try {
            if(op == 1){
                /* All users location report at specific location and epoch *test* */
                System.out.println("$$$ USERS AT: "+x+","+y+" IN EPOCH "+epoch+" $$$");

                Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipherReport.init(Cipher.ENCRYPT_MODE, this.getSymKey());

                byte[] cipherBytes3 = cipherReport.doFinal(epoch.getBytes());
                String epochEnc = Base64.getEncoder().encodeToString(cipherBytes3);

                String location = x + "," + y;

                byte[] cipherBytes4 = cipherReport.doFinal(location.getBytes());
                String locationEnc = Base64.getEncoder().encodeToString(cipherBytes4);

                ServerReturn s = h.obtainUsersAtLocation("ha", locationEnc,epochEnc);

                reports = s.getReports();

                System.out.println("SERVER RETURN: " + s.getServerProof());
                if(reports != null){
                    for(int i = 0; i < reports.size(); i++){
                        System.out.println("\tENTRY "+(i+1)+": "+reports.get(i).getUsername());
                    }
                }else{
                    System.out.println("No entries for that combination.");
                }
            }else if(op == 2){
                /* Specific user report at specific epochs *test* */
                System.out.println("$$$ LOCATIONS OF USER: "+user+" at epoch "+epoch+" $$$");

                Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipherReport.init(Cipher.ENCRYPT_MODE, this.getSymKey());

                byte[] cipherBytes3 = cipherReport.doFinal(user.getBytes());
                String userEnc = Base64.getEncoder().encodeToString(cipherBytes3);

                byte[] cipherBytes4 = cipherReport.doFinal(epoch.getBytes());
                String epochEnc = Base64.getEncoder().encodeToString(cipherBytes4);

                ServerReturn s = h.obtainLocationReport(userEnc,epochEnc);

                reports = s.getReports();

                System.out.println("SERVER RETURN: " + s.getServerProof());

                Cipher rsaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                rsaCipher.init(Cipher.DECRYPT_MODE, this.getSymKey());

                Iterator i = reports.iterator();
                while (i.hasNext()) {

                    Report re = (Report) i.next();

                /*System.out.println("===============================================================================================");
                System.out.println("RECEIVED THE SERVER PROOF0 OF LOCATION FROM - "+ re.getUsername());
                System.out.println("USER SIGNATURE: " + re.getUserSignature());
                System.out.println("TIMESTAMP: " + re.getTimeStamp());
                System.out.println("POS: (" + re.getPosX() + "," + re.getPosY() + ") AT EPOCH " + re.getEpoch());
                System.out.println("WITNESS: " + re.getWitness());
                System.out.println("WITNESS SIGNATURE: " + re.getWitnessSignature());
                System.out.println("WITNESS TIMESTAMP: " + re.getWitnessTimeStamp());
                System.out.println("===============================================================================================");*/

                    byte[] hashBytes1 = java.util.Base64.getDecoder().decode(re.getEncryptedInfo());
                    byte[] chunk = rsaCipher.doFinal(hashBytes1);
                    String info = Base64.getEncoder().encodeToString(chunk);
                    info = info.split("=")[0];

                    re.setPosX(Integer.parseInt(info.split("w")[0].split("q")[1]));
                    re.setPosY(Integer.parseInt(info.split("w")[1].split("q")[1]));
                    re.setEpoch(Integer.parseInt(info.split("w")[2].split("q")[1]));

                    byte[] hashBytes3 = java.util.Base64.getDecoder().decode(re.getWitness());
                    byte[] chunk2 = rsaCipher.doFinal(hashBytes3);
                    String witness =  new String(chunk2, UTF_8);

                    re.setWitness(witness);

                    System.out.println("==================ZECA=============================================");
                    System.out.println("RECEIVED THE SERVER PROOF OF LOCATION FROM - "+ re.getUsername());
                    System.out.println("USER SIGNATURE: " + re.getUserSignature());
                    System.out.println("TIMESTAMP: " + re.getTimeStamp());
                    System.out.println("POS: (" + re.getPosX() + "," + re.getPosY() + ") AT EPOCH " + re.getEpoch());
                    System.out.println("WITNESS: " + re.getWitness());
                    System.out.println("WITNESS SIGNATURE: " + re.getWitnessSignature());
                    System.out.println("WITNESS TIMESTAMP: " + re.getWitnessTimeStamp());
                    System.out.println("===============================================================================================");

                }

                /*if(reports != null){
                    for(int i = 0; i < reports.size(); i++){
                        System.out.println("\tENTRY "+(i+1)+": "+
                                reports.get(i).getUsername()+" -> ("+
                                reports.get(i).getPosX()+","+reports.get(i).getPosY()+")");
                    }
                }else{
                    System.out.println("No entries for that combination.");
                }*/
            }else{
                System.out.println("OP Code unavailable");
            }
        }catch (ConnectException | UnmarshalException | InterruptedException e){
            try {
                this.h = null;
                retry(op,user,x,y,epoch);
            } catch (InterruptedException interruptedException) {
                System.out.println("SERVICE IS DOWN. COME BACK LATER.");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

    }

    //=======================THREAD CONNECTION==========================================================================

    private void retry(int op,String user,String x, String y, String epoch) throws InterruptedException, IOException, ClassNotFoundException {
        Thread thread = new Thread(this);
        thread.start();
        thread.join();
        if(this.h == null){
            System.out.println("SERVICE IS DOWN. COME BACK LATER.");
            return;
        }else{
            communicate(this.h,op,user,x,y,epoch);
        }
    }

    @Override
    public void run(){
        int tries = 0;
        while(this.h == null && tries < 5){
            System.out.println("New try.");
            try {
                Thread.sleep(2000);
                this.h = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
            } catch (InterruptedException e) {
                /*exit*/
            } catch (RemoteException | MalformedURLException | NotBoundException e){
                /*Try new connection in 2 seconds*/
            }
            tries++;
        }
    }

    //====================================MAIN==========================================================================

    public static void main(String[] args) {
        HAClient ha = new HAClient();
        ha.handshake(1,"","30","37","0");
    }
}
