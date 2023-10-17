import javax.crypto.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.rmi.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static java.nio.charset.StandardCharsets.UTF_8;


public class HAClient extends Thread{

    private String entity;
    private ServerInterface h;
    private int F;
    private IdentityHashMap<Integer,Integer> identity;
    private SecretKey symKey;
    private OutputManager fileMan;
    private int servers;

    private HashMap<ServerInterface,SecretKey> networkTosymKey;
    private HashMap<ServerInterface,String> ackList;
    private HashMap<ServerInterface,ServerReturn> readList;
    private AtomicInteger requestId;
    private AtomicInteger timeStamp;
    private AtomicInteger writerTimeStamp;
    private String val;
    private String signature;
    private String userid;

    public void setSymKey(SecretKey symKey) {
        this.symKey = symKey;
    }

    public SecretKey getSymKey() {
        return symKey;
    }

    public HAClient(int servers, int f, int id) throws IOException, NotBoundException, ClassNotFoundException, NotBoundException, IOException, ClassNotFoundException{
        super();
        this.fileMan = new OutputManager("HA"+id,"Health Authority");
        this.networkTosymKey = new HashMap<>();
        this.fileMan.initFile();
        this.F = f;
        this.servers = servers;
        this.userid = "hauser"+id;
        bonrrInit();

    }

    private PublicKey loadPublicKey (String keyName) {
        try {
            FileInputStream fin = new FileInputStream("src/keys/" + keyName + ".cer");
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
            PublicKey pk = certificate.getPublicKey();
            //System.out.println("PUB KEY" + pk);
            return pk;
        }catch (Exception e){
            System.out.println(e);
        }
        return null;
    }

    private PrivateKey loadPrivKey (String keyName) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream readStream = new FileInputStream("src/keys/" + keyName +".keystore");
            keyStore.load(readStream, (keyName + "key").toCharArray());
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyName, new KeyStore.PasswordProtection((keyName + "key").toCharArray()));
            PrivateKey pk = entry.getPrivateKey();
            //System.out.println("PRIV KEY " + pk);
            return pk;
        } catch(Exception e){
            System.out.println(e);
        }

        return null;
    }

    public void handshake(){
        try {
            try {
                ServerInterface h;
                for(int i = 0; i < this.servers; i++){
                    h = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER"+(i+1));

                    SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
                    String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
                    //this.setSymKey(secretKey);

                    PublicKey pub = loadPublicKey("server"+(i+1));
                    Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipherRSA.init(Cipher.ENCRYPT_MODE, pub);
                    byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
                    byte[] cipherBytes = cipherRSA.doFinal(keyBytes);
                    String encryptedKey = Base64.getEncoder().encodeToString(cipherBytes);

                    h.HASubscribe(encryptedKey, this.userid);
                    this.networkTosymKey.put(h,secretKey);
                }
            }catch (RemoteException | MalformedURLException | NotBoundException e){
                /*Handled with care*/
            }
        } catch (Exception e) {
            System.out.println("Exception in main: " + e);
            e.printStackTrace();
        }
    }

    public void communicate(ServerInterface h, int op,String user,String x, String y, String epoch) throws IOException, ClassNotFoundException {

        ArrayList<Report> reports = new ArrayList<>();
        System.setProperty("java.rmi.transport.tcp.responseTimeout", "2000");
        this.requestId.addAndGet(1);
        ServerInterface sr = null;

        try {
            if(op == 1){

                /* All users location report at specific location and epoch *test* */
                this.fileMan.appendInformation("\n");
                this.fileMan.appendInformation("[REQUEST TO SERVER] USERS AT: "+x+","+y+" IN EPOCH "+epoch+" $$$");

                // !! BEGIN !!
                for (ServerInterface s: this.networkTosymKey.keySet()) {
                    Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipherReport.init(Cipher.ENCRYPT_MODE, this.networkTosymKey.get(s));

                    byte[] cipherBytes3 = cipherReport.doFinal(epoch.getBytes());
                    String epochEnc = Base64.getEncoder().encodeToString(cipherBytes3);

                    String location = x + "," + y;

                    byte[] cipherBytes4 = cipherReport.doFinal(location.getBytes());
                    String locationEnc = Base64.getEncoder().encodeToString(cipherBytes4);

                    String s1 = "";
                    String hashPOW = "";
                    int hashInt = 0;

                    do{
                        hashInt++;
                        s1 = this.requestId.get() + hashInt +"";
                        //Hash message
                        byte[] messageByte0 = s1.getBytes();
                        MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                        digest0.update(messageByte0);
                        byte[] digestByte0 = digest0.digest();
                        hashPOW = Base64.getEncoder().encodeToString(digestByte0);
                    }
                    while(!hashPOW.startsWith("0"));

                    PrivateKey priv = loadPrivKey(this.userid);

                    //sign the hash with the ha private key
                    Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                    byte[] hashBytes = Base64.getDecoder().decode(hashPOW);
                    byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                    String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);


                    ServerReturn r = s.obtainUsersAtLocation(locationEnc,epochEnc,this.requestId.get(), signedHash, hashInt, this.userid);
                    reports = r.getReports();
                    if(this.requestId.get() == r.getRid()){
                        if(verifiySignature(r.getReports(),s)==1) {
                            this.readList.put(s, r);
                        }
                    }
                }

                // verify cardinality
                System.out.println("============================== "+this.readList.size());
                if(this.readList.size() > (this.servers + this.F) / 2){
                    //verify highest value
                    ServerInterface maxKey = null;
                    String timestamp = "";
                    String temp = "";
                    for(ServerInterface key: this.readList.keySet()){
                        temp = highestVal(this.readList.get(key).getReports());
                        if(timestamp.equals("")){
                            timestamp = temp;
                            maxKey = key;
                        }else{
                            LocalTime max = LocalTime.parse(timestamp);
                            LocalTime act = LocalTime.parse(temp);
                            if(act.isAfter(max)){
                                timestamp = temp;
                                maxKey = key;
                            }
                        }
                    }
                    sr = maxKey;
                    reports = this.readList.get(maxKey).getReports();
                }
                // !! END !!
                System.out.println("============================== "+sr);

                if(reports != null && sr != null){
                    this.fileMan.appendInformation("\t\tSERVER RETURN: " + this.readList.get(sr).getServerProof());

                    Cipher rsaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    rsaCipher.init(Cipher.DECRYPT_MODE, this.networkTosymKey.get(sr));

                    Iterator i = reports.iterator();
                    while (i.hasNext()) {

                        Report re = (Report) i.next();

                        byte[] hashBytes1 = java.util.Base64.getDecoder().decode(re.getEncryptedInfo());
                        byte[] chunk = rsaCipher.doFinal(hashBytes1);
                        String info = Base64.getEncoder().encodeToString(chunk);
                        info = info.split("=")[0];

                        re.setPosX(Integer.parseInt(info.split("w")[0].split("q")[1]));
                        re.setPosY(Integer.parseInt(info.split("w")[1].split("q")[1]));
                        re.setEpoch(Integer.parseInt(info.split("w")[2].split("q")[1]));

                        /*System.out.println("======================================= "+re.getWitness());
                        byte[] hashBytes3 = java.util.Base64.getDecoder().decode(re.getWitness());
                        byte[] chunk2 = rsaCipher.doFinal(hashBytes3);
                        String witness =  new String(chunk2, UTF_8);

                        re.setWitness(witness);

                        byte[] hashBytes4 = java.util.Base64.getDecoder().decode(re.getUsername());
                        byte[] chunk3 = rsaCipher.doFinal(hashBytes4);
                        String username =  new String(chunk3, UTF_8);

                        re.setUsername(username);
                        */

                        this.fileMan.appendInformation("\t\t\tENTRY "+": "+re.getUsername());

                    }

                }else{
                    this.fileMan.appendInformation("\t\t\tNo entries for that combination.");
                }
                this.readList.clear();

            }else if(op == 2){

                /* Specific user report at specific epochs *test* */
                this.fileMan.appendInformation("\n");
                this.fileMan.appendInformation("[REQUEST TO SERVER]  LOCATIONS OF USER: "+user+" at epoch "+epoch+" $$$");

                // !! BEGIN !!

                for (ServerInterface s: this.networkTosymKey.keySet()) {

                    Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipherReport.init(Cipher.ENCRYPT_MODE, this.networkTosymKey.get(s));

                    byte[] cipherBytes3 = cipherReport.doFinal(user.getBytes());
                    String userEnc = Base64.getEncoder().encodeToString(cipherBytes3);

                    byte[] cipherBytes4 = cipherReport.doFinal(epoch.getBytes());
                    String epochEnc = Base64.getEncoder().encodeToString(cipherBytes4);

                    String s1 = "";
                    String hashPOW = "";
                    int hashInt = 0;

                    do{
                        hashInt++;
                        s1 = this.requestId.get() + hashInt +"";
                        //Hash message
                        byte[] messageByte0 = s1.getBytes();
                        MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                        digest0.update(messageByte0);
                        byte[] digestByte0 = digest0.digest();
                        hashPOW = Base64.getEncoder().encodeToString(digestByte0);
                    }
                    while(!hashPOW.startsWith("0"));

                    PrivateKey priv = loadPrivKey(this.userid);

                    //sign the hash with the ha private key
                    Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                    byte[] hashBytes = Base64.getDecoder().decode(hashPOW);
                    byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                    String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

                    ServerReturn r = s.obtainLocationReport(userEnc,epochEnc,this.requestId.get(), signedHash, hashInt, this.userid);
                    reports = r.getReports();

                    if(this.requestId.get() == r.getRid()){
                        if(verifiySignature(r.getReports(),s)==1) {
                            this.readList.put(s, r);
                        }
                    }
                }

                // verify cardinality
                if(this.readList.size() > (this.servers + this.F) / 2){
                    //verify highest value
                    ServerInterface maxKey = null;
                    String timestamp = "";
                    String temp = "";
                    for(ServerInterface key: this.readList.keySet()){
                        temp = highestVal(this.readList.get(key).getReports());
                        if(timestamp.equals("")){
                            timestamp = temp;
                            maxKey = key;
                        }else{
                            LocalTime max = LocalTime.parse(timestamp);
                            LocalTime act = LocalTime.parse(temp);
                            if(act.isAfter(max)){
                                timestamp = temp;
                                maxKey = key;
                            }
                        }
                    }
                    sr = maxKey;
                    reports = this.readList.get(maxKey).getReports();
                }
                // !! END !!
                this.fileMan.appendInformation("\t\tSERVER RETURN: " + this.readList.get(sr).getServerProof());
                this.readList.clear();

                int j = 0;
                Iterator i = reports.iterator();
                while (i.hasNext()) {

                    Cipher rsaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    rsaCipher.init(Cipher.DECRYPT_MODE, this.networkTosymKey.get(sr));

                    Report re = (Report) i.next();

                    byte[] hashBytes1 = java.util.Base64.getDecoder().decode(re.getEncryptedInfo());
                    byte[] chunk = rsaCipher.doFinal(hashBytes1);
                    String info = Base64.getEncoder().encodeToString(chunk);
                    info = info.split("=")[0];

                    re.setPosX(Integer.parseInt(info.split("w")[0].split("q")[1]));
                    re.setPosY(Integer.parseInt(info.split("w")[1].split("q")[1]));
                    re.setEpoch(Integer.parseInt(info.split("w")[2].split("q")[1]));

                    /*byte[] hashBytes3 = java.util.Base64.getDecoder().decode(re.getWitness());
                    byte[] chunk2 = rsaCipher.doFinal(hashBytes3);
                    String witness =  new String(chunk2, UTF_8);

                    re.setWitness(witness);

                    byte[] hashBytes4 = java.util.Base64.getDecoder().decode(re.getUsername());
                    byte[] chunk3 = rsaCipher.doFinal(hashBytes4);
                    String username =  new String(chunk3, UTF_8);

                    re.setUsername(username);*/


                    j++;
                    this.fileMan.appendInformation("\t\t ====== REPORT #"+j);
                    this.fileMan.appendInformation("\t\t\tRECEIVED THE SERVER PROOF OF LOCATION FROM - "+ re.getUsername());
                    this.fileMan.appendInformation("\t\t\tUSER SIGNATURE: " + re.getUserSignature() + "NONCE: " + re.getNonce());
                    this.fileMan.appendInformation("\t\t\tPOS: (" + re.getPosX() + "," + re.getPosY() + ") AT EPOCH " + re.getEpoch());
                    this.fileMan.appendInformation("\t\t\tWITNESS: " + re.getWitness());
                    this.fileMan.appendInformation("\t\t\tWITNESS SIGNATURE: " + re.getWitnessSignature());
                    this.fileMan.appendInformation("\t\t\tWITNESS NONCE: " + re.getWitnessNonce());

                }

            }else{
                this.fileMan.appendInformation("OP Code unavailable");
            }
        }catch (ConnectException | UnmarshalException | InterruptedException e){
            try {
                this.h = null;
                retry(op,user,x,y,epoch);
            } catch (InterruptedException interruptedException) {
                this.fileMan.appendInformation("SERVICE IS DOWN. COME BACK LATER.");
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

    //=======================1,N Byzantine =============================================================================

    private void bonrrInit(){
        this.ackList = new HashMap<>();
        this.readList = new HashMap<>();
        this.writerTimeStamp = new AtomicInteger(0);
        this.requestId = new AtomicInteger(0);
        this.timeStamp = new AtomicInteger(0);
        this.signature = null;
        this.val = null;
    }

    public int verifiySignature(ArrayList<Report> reportList, ServerInterface sr){
        for(int j = 0; j < reportList.size(); j++){

            try {

                Cipher rsaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                rsaCipher.init(Cipher.DECRYPT_MODE, this.networkTosymKey.get(sr));

                Report re = (Report) reportList.get(j);

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

                byte[] hashBytes4 = java.util.Base64.getDecoder().decode(re.getUsername());
                byte[] chunk3 = rsaCipher.doFinal(hashBytes4);
                String username =  new String(chunk3, UTF_8);

                re.setUsername(username);

                // split

                PublicKey pub = loadPublicKey(reportList.get(j).getUsername());
                rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsaCipher.init(Cipher.DECRYPT_MODE, pub);

                String s1 = reportList.get(j).getUsername() + reportList.get(j).getNonce() + reportList.get(j).getTimeStamp() + reportList.get(j).getEpoch() + reportList.get(j).getPosX() + reportList.get(j).getPosY() + reportList.get(j).getIntPOW();

                hashBytes1 = java.util.Base64.getDecoder().decode(reportList.get(j).getUserSignature());
                chunk = rsaCipher.doFinal(hashBytes1);
                String serverSignature = Base64.getEncoder().encodeToString(chunk);

                byte[] messageByte2 = s1.getBytes();
                MessageDigest digest2 = MessageDigest.getInstance("SHA-256");
                digest2.update(messageByte2);
                byte[] digestByte2 = digest2.digest();
                String checkHash = Base64.getEncoder().encodeToString(digestByte2);

                if(!serverSignature.equals(checkHash)){
                    return -1;
                }

            } catch ( NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException | InvalidKeyException e) {
                System.out.println("Wrong signature");
                e.printStackTrace();
                return -1;
            }
        }
        return 1;
    }

    private String highestVal(ArrayList<Report> v){

        String timestamp = "";

        for (int i = 0; i < v.size(); i++) {
            if(timestamp.equals("")){
                timestamp = v.get(i).getTimeStamp();
            }else{
                String vact = timestamp = v.get(i).getTimeStamp();;
                LocalTime max = LocalTime.parse(timestamp);
                LocalTime act = LocalTime.parse(vact);
                if(act.isAfter(max)){
                    timestamp = vact;
                }
            }
        }

        return timestamp;
    }

    //=======================THREAD CONNECTION==========================================================================

    private void retry(int op,String user,String x, String y, String epoch) throws InterruptedException, IOException, ClassNotFoundException {
        Thread thread = new Thread(this);
        thread.start();
        thread.join();
        if(this.h == null){
            this.fileMan.appendInformation("\nSERVICE IS DOWN. COME BACK LATER.");
            return;
        }else{
            communicate(this.h,op,user,x,y,epoch);
        }
    }

    @Override
    public void run(){
        int tries = 0;
        while(this.h == null && tries < 5){
            this.fileMan.appendInformation("New try.");
            try {
                Thread.sleep(2000);
                this.h = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER"+this.servers);
            } catch (InterruptedException e) {
                /*exit*/
            } catch (RemoteException | MalformedURLException | NotBoundException e){
                /*Try new connection in 2 seconds*/
            }
            tries++;
        }
    }

    public ServerInterface getServerInterface(){
        return this.h;
    }

    //====================================MAIN==========================================================================

    public static void main(String[] args) throws NotBoundException, IOException, ClassNotFoundException {
        HAClient ha = new HAClient(6,2, 1);
        //ha.handshake(1,"","30","37","0");
        //ha.handshake(1,"","30","37","0");
    }
}
