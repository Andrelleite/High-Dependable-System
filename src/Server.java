import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.MalformedURLException;
import java.rmi.*;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Server extends UnicastRemoteObject implements ServerInterface, Serializable{

    private static final long serialVersionUID = 1L;
    public static int GRIDDIMENISION = 40;
    public  ConcurrentHashMap<String,SecretKey> symKey;
    private ConcurrentHashMap<String,Double> allSystemUsers; // User and the certainty of byzantine behaviour
    public  ConcurrentHashMap<String,Integer> sendNonce = new ConcurrentHashMap<String, Integer>();
    public  ConcurrentHashMap<String,Integer> receiveNonce= new ConcurrentHashMap<String, Integer>();
    private ArrayList<Report> reps; // Structure of all reports in the system
    private ArrayList<ServerInterface> replicas;
    private ServerInterface server;
    private OutputManager fileMan;
    private List<String> clients;
    private boolean imPrimary;
    private String IPV4;
    private int portRMI;
    private int[] f;
    private long id;
    private String password;
    private int network;

    public void setPassword(String password){
        this.password = password;
    }

    public String getPassword(){
        return password;
    }

    //=======================CONNECTION=================================================================================

    public Server(int f, int fline, long id, int net) throws IOException, NotBoundException, ClassNotFoundException {

        this.f = new int[2];
        this.f[0] = f;
        this.f[1] = fline;
        this.id = id;
        this.network = net;
        this.IPV4 = "127.0.0.1";
        this.portRMI = 7000;
        this.symKey = new ConcurrentHashMap<>();
        this.replicas = new ArrayList<>();
        this.fileMan = new OutputManager("Server"+this.id,"Server"+this.id);
        this.fileMan.initFile();
        synchronize(); // Updates the reports in list to the latest in file
        this.server = retryConnection(7000);

        if (!imPrimary) {
            checkPrimaryServer(this.server);
        }
    }

    public void setClients(List<String> clients) {
        this.clients = clients;
    }

    public void loadSymmetricKeys() {
        if(clients != null){
            loadSymmKeys(clients);
        }
    }

    private void checkPrimaryServer(ServerInterface serverPrimary) {
        boolean state = false;
        Server server = this;
        while (!state){
            imPrimary = false;
            state = false;
            try {
                LocateRegistry.createRegistry(this.portRMI);
                Naming.rebind("rmi://"+this.IPV4+":" + this.portRMI + "/SERVER"+this.id, server);
                imPrimary = true;
                state = true;
            } catch (MalformedURLException | RemoteException ex) {
                /*wait silently*/
            }
        }
        System.out.println("I'm in.");
    }

    private ServerInterface retryConnection(int port) throws IOException {

        ServerInterface serverInt = null;
        Server server = this;
        System.out.println("SERVER "+this.id+" IS ONLINE AT "+this.IPV4);

        try {
            LocateRegistry.createRegistry(port);
            Naming.rebind("rmi://"+this.IPV4+":" + port + "/SERVER"+this.id, server);
            imPrimary = true;
            System.out.println("I'm the primary");
        } catch (ExportException ex) {
            imPrimary = false;
            System.out.println("I'm the backup");
            try {
                serverInt = (ServerInterface) Naming.lookup("rmi://"+this.IPV4+":" + port + "/SERVER"+this.id);
                System.out.println("Connetion to primary succeded...");
            } catch (NotBoundException e) {
                try {
                    LocateRegistry.createRegistry(port);
                }catch (ExportException s){
                    LocateRegistry.getRegistry(port);
                }
                Naming.rebind("rmi://"+this.IPV4+":" + port + "/SERVER"+this.id, server);
                imPrimary = true;
                System.out.println("I'm the primary");
            }
        }
        System.out.println("Server ready...");
        return serverInt;
    }

    public int shutdown() throws MalformedURLException, NotBoundException, RemoteException {
        Naming.unbind("rmi://"+this.IPV4+":" + portRMI + "/SERVER"+this.id);
        return 1;
    }

    //=======================SERVER-SYS=================================================================================

    public void HASubscribe(String key) throws RemoteException{

        try {

            PrivateKey priv = loadPrivKey("server" + id);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, priv);
            byte[] hashBytes = java.util.Base64.getDecoder().decode(key);
            byte[] chunk = rsaCipher.doFinal(hashBytes);
            String decryptedKey = Base64.getEncoder().encodeToString(chunk);
            byte[] decodedKey = Base64.getDecoder().decode(decryptedKey);
            SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            String encodedKey = Base64.getEncoder().encodeToString(originalKey.getEncoded());
            this.symKey.put("ha",originalKey);
            StoreKeysToKeyStore(originalKey, "ha","KeyStore","src/keys/aes-ha.keystore");


        }  catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }  catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void subscribe(ClientInterface c, String user, String key) throws RemoteException{

        this.allSystemUsers.put(user,0.0);
        try {
            updateUsers();

            PrivateKey priv = loadPrivKey("server" + id);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, priv);
            byte[] hashBytes = java.util.Base64.getDecoder().decode(key);
            byte[] chunk = rsaCipher.doFinal(hashBytes);
            String decryptedKey = Base64.getEncoder().encodeToString(chunk);
            byte[] decodedKey = Base64.getDecoder().decode(decryptedKey);
            SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            String encodedKey = Base64.getEncoder().encodeToString(originalKey.getEncoded());

            this.symKey.put(user,originalKey);

            StoreKeysToKeyStore(originalKey, user,"KeyStore","src/keys/aes-" + user +".keystore");



            //this.setSymKey(originalKey);
        } catch (IOException e) {
            e.printStackTrace();
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
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public String echo(String message) throws RemoteException {
        System.out.println("received " + message);
        return message;
    }

    //=======================USER-METHODS===============================================================================

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
            System.out.println("keyName " + keyName);
            System.out.println("pass " + getPassword());
            KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream readStream = new FileInputStream("src/keys/" + keyName +".keystore");
            keyStore.load(readStream, (getPassword() + "key").toCharArray());
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyName, new KeyStore.PasswordProtection((getPassword() + "key").toCharArray()));
            PrivateKey pk = entry.getPrivateKey();
            //System.out.println("PRIV KEY " + pk);
            return pk;
        } catch(Exception e){
            System.out.println(e);
        }

        return null;
    }

    public void loadSymmKeys(List<String> clients ) {
        for (String client : clients){
            SecretKey key = LoadFromKeyStore("src/keys/aes-" + client +".keystore", client, "KeyStore");
            this.symKey.put(client, key);
        }
    }

    public static void StoreKeysToKeyStore(SecretKey keyToStore, String userName, String password,String filepath) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore javaKeyStore = KeyStore.getInstance("PKCS12");
        javaKeyStore.load(null, password.toCharArray());

        System.out.println("GUARDEI O USER " + userName);
        javaKeyStore.setKeyEntry(userName, keyToStore, password.toCharArray(), null);
        OutputStream writeStream = new FileOutputStream(filepath);
        javaKeyStore.store(writeStream, password.toCharArray());
    }

    public static SecretKey LoadFromKeyStore(String filepath, String userName, String password){
        try {
            InputStream keystoreStream = new FileInputStream(filepath);
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(keystoreStream, password.toCharArray());
            if (!keystore.containsAlias(userName)) {
                throw new RuntimeException("Alias for key not found");
            }
            SecretKey key = (SecretKey) keystore.getKey(userName, password.toCharArray());

            return key;
        } catch(Exception e){
            e.printStackTrace();
        }

        return null;
    }

    public synchronized String submitLocationReport(ClientInterface c,String user, Report locationReport) throws RemoteException, InterruptedException {

        String[] serverReturn = new String[1];
        ArrayList<Report> reps = this.reps;
        ConcurrentHashMap<String,SecretKey> symKey = this.symKey;
        OutputManager filer = this.fileMan;

        Thread worker = new Thread("Worker") {
            @Override
            public void run() {
                try{
                    filer.appendInformation("\n");
                    filer.appendInformation("[PROOF REQUEST] "+user);

                    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, symKey.get(user));


                    byte[] hashBytes1 = java.util.Base64.getDecoder().decode(locationReport.getEncryptedInfo());
                    byte[] chunk = cipher.doFinal(hashBytes1);
                    String info = new String(chunk, UTF_8);

                    locationReport.setPosX(Integer.parseInt(info.split("w")[0].split("q")[1]));
                    locationReport.setPosY(Integer.parseInt(info.split("w")[1].split("q")[1]));
                    locationReport.setEpoch(Integer.parseInt(info.split("w")[2].split("q")[1]));

                    byte[] hashBytes3 = java.util.Base64.getDecoder().decode(locationReport.getWitness());
                    byte[] chunk2 = cipher.doFinal(hashBytes3);
                    String witness =  new String(chunk2, UTF_8);

                    locationReport.setWitness(witness);

                    if(witness.equals(user)){
                        serverReturn[0] = "null";
                        filer.appendInformation("\t\t !REQUEST FOR LOCATION PROOF DROPPED! WITNESS EQUALS USER");
                    }


                    if(serverReturn[0] != "null"){
                        Cipher cipherWit = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        cipherWit.init(Cipher.DECRYPT_MODE, symKey.get(witness));

                        byte[] hashBytes2 = java.util.Base64.getDecoder().decode(locationReport.getWitnessPos());
                        byte[] chunkWit = cipherWit.doFinal(hashBytes2);
                        String info2 = new String(chunkWit, UTF_8);

                        locationReport.setPosXWitness(Integer.parseInt(info2.split("w")[0].split("q")[1]));
                        locationReport.setPosYWitness(Integer.parseInt(info2.split("w")[1].split("q")[1]));
                    }

                }
                catch (NoSuchAlgorithmException e) {
                    filer.appendInformation("\t\t !REQUEST FOR LOCATION PROOF DROPPED! CODE#SSLR1");
                    serverReturn[0] = "null";
                } catch (NoSuchPaddingException e) {
                    filer.appendInformation("\t\t !REQUEST FOR LOCATION PROOF DROPPED! CODE#SSLR2");
                    serverReturn[0] = "null";
                } catch (InvalidKeyException e) {
                    filer.appendInformation("\t\t !REQUEST FOR LOCATION PROOF DROPPED! CODE#SSLR3");
                    serverReturn[0] = "null";
                } catch (IllegalBlockSizeException e) {
                    filer.appendInformation("\t\t !REQUEST FOR LOCATION PROOF DROPPED! CODE#SSLR4");
                    serverReturn[0] = "null";
                } catch (BadPaddingException e) {
                    filer.appendInformation("\t\t !REQUEST FOR LOCATION PROOF DROPPED! CODE#SSLR5");
                    serverReturn[0] = "null";
                }

                if(serverReturn[0] != "null"){
                    filer.appendInformation("[PROOF REQUEST] "+user+" SUBMITING NEW LOCATION PROOF AT EPOCH "+locationReport.getEpoch()+" ===== ");

                    String verifyRet = verifyLocationReport(c, user, locationReport);
                    if(verifyRet.equals("Correct") /* && !checkClone(locationReport) */){
                        filer.appendInformation("\t\t\tRECEIVED A NEW PROOF OF LOCATION FROM - "+ locationReport.getUsername());
                        filer.appendInformation("\t\t\tUSER SIGNATURE: " + locationReport.getUserSignature());
                        filer.appendInformation("\t\t\tNONCE: " + locationReport.getNonce());
                        filer.appendInformation("\t\t\tPOS: (" + locationReport.getPosX() + "," + locationReport.getPosY() + ") AT EPOCH " + locationReport.getEpoch());
                        filer.appendInformation("\t\t\tWITNESS: " + locationReport.getWitness());
                        filer.appendInformation("\t\t\tWITNESS SIGNATURE: " + locationReport.getWitnessSignature());
                        filer.appendInformation("\t\t\tWITNESS NONCE: " + locationReport.getWitnessNonce());
                        filer.appendInformation("\t\t\tWITNESS POS: (" + locationReport.getPosXWitness() + "," + locationReport.getPosYWitness() + ") ");

                        reps.add(locationReport);
                        try {

                            updateReports();

                            int nonceSend = 1;
                            if(!sendNonce.containsKey(user)){
                                sendNonce.put(user, nonceSend);
                            }else {
                                nonceSend = sendNonce.get(user);
                                nonceSend += 1;
                                sendNonce.replace(user, nonceSend);
                            }

                            String s1 = user + nonceSend + locationReport.getEpoch();


                            PrivateKey priv = loadPrivKey("server" + id);

                            //Hash message
                            byte[] messageByte0 = s1.getBytes();
                            MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                            digest0.update(messageByte0);
                            byte[] digestByte0 = digest0.digest();
                            String digest64 = Base64.getEncoder().encodeToString(digestByte0);

                            //sign the hash with the server's private key
                            Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                            byte[] hashBytes = Base64.getDecoder().decode(digest64);
                            byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                            String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

                            serverReturn[0] = "nonce: " + nonceSend + " | signature: " + signedHash;
                            String time = java.time.LocalTime.now().toString();
                            filer.appendInformation("\t\t REQUEST FOR LOCATION PROOF COMPLETE AT: " + time);
                            filer.appendInformation("\t\t SIGNATURE: " + signedHash);


                        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
                            filer.appendInformation("\t\t !REQUEST FOR LOCATION PROOF DROPPED! CODE#SSLR6");
                        } catch (BadPaddingException e) {
                            filer.appendInformation("\t\t !REQUEST FOR LOCATION PROOF DROPPED! CODE#SSLR7");
                        } catch (IllegalBlockSizeException e) {
                            filer.appendInformation("\t\t !REQUEST FOR LOCATION PROOF DROPPED! CODE#SSLR8");
                        }
                    }else{
                        filer.appendInformation("\t\t\tREQUEST FOR LOCATION PROOF DENIED.");
                    }
                }

                if(serverReturn[0] == null)
                    serverReturn[0] = "null";
            }
        };
        worker.start();
        worker.join();
        this.symKey = symKey;
        this.reps = reps;
        return serverReturn[0];
    }

    public synchronized ServerReturn obtainLocationReport(ClientInterface c, String epoch, String username) throws IOException, ClassNotFoundException, InterruptedException {

        int[] ep = {-1};
        ServerReturn[] serverReturn = new ServerReturn[1];
        ArrayList<Report> reps = this.reps;
        ConcurrentHashMap<String,SecretKey> symKey = this.symKey;
        OutputManager filer = this.fileMan;

        Thread worker = new Thread("Worker") {
            @Override
            public void run() {
                int flag = 0;
                filer.appendInformation("\n");
                filer.appendInformation("[REPORT REQUEST] NEW REPORT DELIVERY REQUEST =====");
                try{

                    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, symKey.get(username));

                    byte[] hashBytes3 = java.util.Base64.getDecoder().decode(epoch);
                    byte[] chunk2 = cipher.doFinal(hashBytes3);
                    String parse =  new String(chunk2, UTF_8);

                    ep[0] = Integer.parseInt(parse);

                }
                catch (NoSuchAlgorithmException e) {
                    filer.appendInformation("\t\t !REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR1");
                    System.out.println("!REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR1");
                    flag = 1;
                }catch (NoSuchPaddingException e) {
                    filer.appendInformation("\t\t !REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR2");
                    System.out.println("!REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR2");
                    flag = 1;
                } catch (InvalidKeyException e) {
                    filer.appendInformation("\t\t !REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR3");
                    System.out.println("!REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR3");
                    flag = 1;
                } catch (IllegalBlockSizeException e) {
                    filer.appendInformation("\t\t !REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR4");
                    System.out.println("!REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR4");
                    flag = 1;
                } catch (BadPaddingException e) {
                    filer.appendInformation("\t\t !REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR5");
                    System.out.println("!REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR5");
                    flag = 1;
                }


                ArrayList<Report> reports = null;

                if(flag==0){
                    if(ep[0] !=-1){
                        reports = fetchReports(c, ep[0]);
                    }

                    int nonceSend = 1;
                    if(!sendNonce.containsKey(username)){
                        sendNonce.put(username, nonceSend);
                    }else {
                        nonceSend = sendNonce.get(username);
                        nonceSend += 1;
                        sendNonce.replace(username, nonceSend);
                    }

                    String s1 = username + nonceSend + ep[0];

                    String finalS = "";

                    ArrayList<Report> returnReport = new ArrayList<>();

                    try {
                        Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        cipherReport.init(Cipher.ENCRYPT_MODE, symKey.get(username));
                        filer.appendInformation("===== NEW REPORT DELIVERY REQUEST FROM "+username+" =====");

                        if(reports != null){
                            Iterator i = reports.iterator();
                            while (i.hasNext()) {
                                Report r = (Report) i.next();

                                String info = "posXq" + r.getPosX() + "wposYq" + r.getPosY() + "wepochq" + r.getEpoch();

                                //r.setEpoch(-1);
                                //r.setPosX(-1);
                                //r.setPosY(-1);

                                byte[] infoBytes = Base64.getDecoder().decode(info);
                                byte[] cipherBytes1 = cipherReport.doFinal(infoBytes);
                                String loc = Base64.getEncoder().encodeToString(cipherBytes1);

                                //r.setEncryptedInfo(loc);

                                //byte[] witnessBytes = Base64.getDecoder().decode(message.getWitness());
                                byte[] cipherBytes3 = cipherReport.doFinal(r.getWitness().getBytes());
                                String loc3 = Base64.getEncoder().encodeToString(cipherBytes3);

                                Report n = new Report(null,-1,-1,-1,username,r.getUserSignature(),r.getNonce(),loc3,r.getWitnessSignature(),r.getWitnessNonce(),r.getWitnessPos());
                                n.setEncryptedInfo(loc);

                                returnReport.add(n);

                                //r.setWitness(loc3);
                            }
                        }else{
                            filer.appendInformation("\t\t NO FETCH FOR "+username);
                        }


                        //get server private key
                    /*
                    FileInputStream fis0 = new FileInputStream("src/keys/serverPriv.key");
                    byte[] encoded1 = new byte[fis0.available()];
                    fis0.read(encoded1);
                    fis0.close();
                    PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded1);
                    KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
                    PrivateKey priv = keyFacPriv.generatePrivate(privSpec);
                     */

                        PrivateKey priv = loadPrivKey("server" + id);

                        //Hash message
                        byte[] messageByte0 = s1.getBytes();
                        MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                        digest0.update(messageByte0);
                        byte[] digestByte0 = digest0.digest();
                        String digest64 = Base64.getEncoder().encodeToString(digestByte0);

                        //sign the hash with the client's private key
                        Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                        byte[] hashBytes = Base64.getDecoder().decode(digest64);
                        byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                        String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

                        finalS = "nonce: " + nonceSend + " | signature: " + signedHash;
                        String time = java.time.LocalTime.now().toString();
                        filer.appendInformation("\t\t REQUEST FOR LOCATION PROOF COMPLETE AT: " + time);
                        filer.appendInformation("\t\t SIGNATURE: " + signedHash);
                    }
                    catch (NoSuchAlgorithmException e) {
                        filer.appendInformation("\t\t !REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR6");
                    } catch (InvalidKeyException e) {
                        filer.appendInformation("\t\t !REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR7");
                    } catch (NoSuchPaddingException e) {
                        filer.appendInformation("\t\t !REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR8");
                    } catch (BadPaddingException e) {
                        filer.appendInformation("\t\t !REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR9");
                    } catch (IllegalBlockSizeException e) {
                        filer.appendInformation("\t\t !REQUEST FOR REPORT DELIVERY DROPPED! CODE#SOLR10");
                    }

                    serverReturn[0] = new ServerReturn(finalS,returnReport);
                    filer.appendInformation("\t\t\t REQUEST COMPLETE FOR "+username);
                }

                else{
                    serverReturn[0] = new ServerReturn(null,null);
                }



            }
        };
        worker.start();
        worker.join();
        return serverReturn[0];

    }

    //=======================AUTHORITY-METHODS==========================================================================

    public synchronized  ServerReturn obtainLocationReport(String user, String epoch) throws InterruptedException {

        int[] ep = {-1};
        ServerReturn[] serverReturn = new ServerReturn[1];
        ArrayList<Report> reps = (ArrayList<Report>) this.reps.clone();
        ConcurrentHashMap<String,SecretKey> symKey = this.symKey;
        OutputManager filer = this.fileMan;

        Thread worker = new Thread("Worker"){
            @Override
            public void run(){

                String userFinal="";
                int epochFinal = -1;

                try {
                    Cipher cipher = null;
                    cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, symKey.get("ha"));

                    byte[] hashBytes3 = java.util.Base64.getDecoder().decode(epoch);
                    byte[] chunk2 = cipher.doFinal(hashBytes3);
                    String parse =  new String(chunk2, UTF_8);

                    byte[] hashBytes4 = java.util.Base64.getDecoder().decode(user);
                    byte[] chunk3 = cipher.doFinal(hashBytes4);
                    userFinal =  new String(chunk3, UTF_8);

                    ep[0] = Integer.parseInt(parse);
                    epochFinal = ep[0];

                } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
                    e.printStackTrace();
                }

                filer.appendInformation("\n");
                filer.appendInformation("[HA USER REQUEST] HA REQUESTING "+userFinal+" LOCATION REPORTS AT EPOCH "+epochFinal+" ===== ");

                ArrayList<Report> clientReports = (ArrayList<Report>) reps.clone();
                for(int i = 0; i < clientReports.size();i++){
                    if(!clientReports.get(i).getUsername().equals(userFinal)){
                        clientReports.remove(i);
                        i--;
                    }else if(clientReports.get(i).getEpoch() != ep[0]){
                        clientReports.remove(i);
                        i--;
                    }
                }
                cleanRepetition(clientReports,1);
                filer.appendInformation("\t\t\tREQUEST SIZE :"+clientReports.size());
                filer.appendInformation("\t\t\tREQUEST COMPLETE");

                int nonceSend = 1;
                if(!sendNonce.containsKey(userFinal)){
                    sendNonce.put(userFinal, nonceSend);
                }else {
                    nonceSend = sendNonce.get(userFinal);
                    nonceSend += 1;
                    sendNonce.replace(userFinal, nonceSend);
                }

                String s1 = "ha" + userFinal + nonceSend + epochFinal;

                String finalS = "";

                ArrayList<Report> returnReport = new ArrayList<>();

                try {

                    Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipherReport.init(Cipher.ENCRYPT_MODE, symKey.get("ha"));

                    Iterator i = clientReports.iterator();
                    while (i.hasNext()) {
                        Report r = (Report) i.next();

                        String info = "posXq" + r.getPosX() + "wposYq" + r.getPosY() + "wepochq" + r.getEpoch();
                        //r.setEpoch(-1);
                        //r.setPosX(-1);
                        //r.setPosY(-1);

                        byte[] infoBytes = Base64.getDecoder().decode(info);
                        byte[] cipherBytes1 = cipherReport.doFinal(infoBytes);
                        String loc = Base64.getEncoder().encodeToString(cipherBytes1);

                        //r.setEncryptedInfo(loc);

                        //byte[] witnessBytes = Base64.getDecoder().decode(message.getWitness());
                        byte[] cipherBytes3 = cipherReport.doFinal(r.getWitness().getBytes());
                        String loc3 = Base64.getEncoder().encodeToString(cipherBytes3);

                        //r.setWitness(loc3);

                        byte[] cipherBytes4 = cipherReport.doFinal(r.getUsername().getBytes());
                        String loc4 = Base64.getEncoder().encodeToString(cipherBytes4);

                        Report n = new Report(null,-1,-1,-1,loc4,r.getUserSignature(),r.getNonce(),loc3,r.getWitnessSignature(),r.getWitnessNonce(),r.getWitnessPos());
                        n.setEncryptedInfo(loc);

                        returnReport.add(n);

                        //r.setUsername(loc4);
                    }


                    //get client private key
                    /*FileInputStream fis0 = new FileInputStream("src/keys/serverPriv.key");
                    byte[] encoded1 = new byte[fis0.available()];
                    fis0.read(encoded1);
                    fis0.close();
                    PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded1);
                    KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
                    PrivateKey priv = keyFacPriv.generatePrivate(privSpec);*/
                    PrivateKey priv = loadPrivKey("server" + id);

                    //Hash message
                    byte[] messageByte0 = s1.getBytes();
                    MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                    digest0.update(messageByte0);
                    byte[] digestByte0 = digest0.digest();
                    String digest64 = Base64.getEncoder().encodeToString(digestByte0);

                    //sign the hash with the client's private key
                    Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                    byte[] hashBytes = Base64.getDecoder().decode(digest64);
                    byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                    String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

                    finalS = "nonce: " + nonceSend + " | signature: " + signedHash;
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                }

                serverReturn[0] = new ServerReturn(finalS,returnReport);


                //clientReports.clear();
            }
        };
        worker.start();
        worker.join();
        return serverReturn[0];
    }

    public synchronized  ServerReturn obtainUsersAtLocation(String pos, String epoch) throws InterruptedException{

        int[] ep = {-1};
        int[] posi = {-1, -1};
        ServerReturn[] serverReturn = new ServerReturn[1];
        ArrayList<Report> reps = (ArrayList<Report>) this.reps.clone();
        ConcurrentHashMap<String,SecretKey> symKey = this.symKey;
        String[] positionDec = new String[2];
        OutputManager filer = this.fileMan;

        Thread worker = new Thread("Worker"){
            @Override
            public void run() {

                try {
                    Cipher cipher = null;
                    cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

                    cipher.init(Cipher.DECRYPT_MODE, symKey.get("ha"));

                    byte[] hashBytes3 = java.util.Base64.getDecoder().decode(epoch);
                    byte[] chunk2 = cipher.doFinal(hashBytes3);
                    String parse =  new String(chunk2, UTF_8);

                    ep[0] = Integer.parseInt(parse);

                    byte[] hashBytes4 = java.util.Base64.getDecoder().decode(pos);
                    byte[] chunk3 = cipher.doFinal(hashBytes4);
                    String position =  new String(chunk3, UTF_8);

                    positionDec[0] = position.split(",")[0];
                    positionDec[1] = position.split(",")[1];

                    posi[0] = Integer.parseInt(positionDec[0]);
                    posi[1] = Integer.parseInt(positionDec[1]);

                } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
                    e.printStackTrace();
                }

                filer.appendInformation("\n");
                filer.appendInformation("[HA LOCATION REQUEST] HA REQUESTING LOCATION REPORTS FOR POSITION ("+ positionDec[0] +","+ positionDec[1] +") AT EPOCH "+ep[0]+" =====");

                ArrayList<Report> clientReports = (ArrayList<Report>) reps.clone();
                for(int i = 0; i < clientReports.size();i++){
                    if(clientReports.get(i).getPosY() != posi[1]){
                        clientReports.remove(i);
                        i--;
                    }else if(clientReports.get(i).getPosX() != posi[0]) {
                        clientReports.remove(i);
                        i--;
                    }else if(clientReports.get(i).getEpoch() != ep[0]){
                        clientReports.remove(i);
                        i--;
                    }
                }
                cleanRepetition(clientReports,0);
                filer.appendInformation("\t\t\tREQUEST SIZE :"+clientReports.size());
                filer.appendInformation("\t\t\tREQUEST COMPLETE");


                int nonceSend = 1;
                if(!sendNonce.containsKey("ha")){
                    sendNonce.put("ha", nonceSend);
                }else {
                    nonceSend = sendNonce.get("ha");
                    nonceSend += 1;
                    sendNonce.replace("ha", nonceSend);
                }

                String s1 = "ha" + posi[0] + posi[1] + nonceSend + ep[0];

                String finalS = "";

                ArrayList<Report> returnReport = new ArrayList<>();

                try {

                    Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipherReport.init(Cipher.ENCRYPT_MODE, symKey.get("ha"));

                    Iterator i = clientReports.iterator();
                    while (i.hasNext()) {
                        Report r = (Report) i.next();

                        String info = "posXq" + r.getPosX() + "wposYq" + r.getPosY() + "wepochq" + r.getEpoch();
                        //r.setEpoch(-1);
                        //r.setPosX(-1);
                        //r.setPosY(-1);

                        byte[] infoBytes = Base64.getDecoder().decode(info);
                        byte[] cipherBytes1 = cipherReport.doFinal(infoBytes);
                        String loc = Base64.getEncoder().encodeToString(cipherBytes1);

                        //r.setEncryptedInfo(loc);

                        //byte[] witnessBytes = Base64.getDecoder().decode(message.getWitness());
                        byte[] cipherBytes3 = cipherReport.doFinal(r.getWitness().getBytes());
                        String loc3 = Base64.getEncoder().encodeToString(cipherBytes3);

                        //r.setWitness(loc3);

                        byte[] cipherBytes4 = cipherReport.doFinal(r.getUsername().getBytes());
                        String loc4 = Base64.getEncoder().encodeToString(cipherBytes4);

                        Report n = new Report(null,-1,-1,-1,loc4,r.getUserSignature(),r.getNonce(),loc3,r.getWitnessSignature(),r.getWitnessNonce(),r.getWitnessPos());
                        n.setEncryptedInfo(loc);

                        returnReport.add(n);

                        //r.setUsername(loc4);
                    }

                    //get client private key
                    /*FileInputStream fis0 = new FileInputStream("src/keys/serverPriv.key");
                    byte[] encoded1 = new byte[fis0.available()];
                    fis0.read(encoded1);
                    fis0.close();
                    PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded1);
                    KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
                    PrivateKey priv = keyFacPriv.generatePrivate(privSpec);*/

                    PrivateKey priv = loadPrivKey("server" + id);

                    //Hash message
                    byte[] messageByte0 = s1.getBytes();
                    MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                    digest0.update(messageByte0);
                    byte[] digestByte0 = digest0.digest();
                    String digest64 = Base64.getEncoder().encodeToString(digestByte0);

                    //sign the hash with the client's private key
                    Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                    byte[] hashBytes = Base64.getDecoder().decode(digest64);
                    byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                    String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

                    finalS = "nonce: " + nonceSend + " | signature: " + signedHash;
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                }

                serverReturn[0] = new ServerReturn(finalS,returnReport);
            }
        };
        worker.start();
        worker.join();
        return serverReturn[0];

    }

    //=======================INTRA-SERVER-COMMS=========================================================================

    public String serverHello(long n) throws RemoteException{
        System.out.println(">>>"+this.id+">>> "+"Got an hello message from replica "+n);
        return "Hello from replica "+this.id;
    }

    public void connectToNetwork(){
        ServerInterface s;
        for(int i = 0; i < this.network; i++){
            if((i+1) != this.id){
                try {
                    s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER"+(i+1));
                    System.out.println(">>>"+this.id+">>> "+s.serverHello(this.id));
                    this.replicas.add(s);
                } catch (NotBoundException | MalformedURLException | RemoteException e) {
                    System.out.println("SHIT.");
                }
            }
        }
        System.out.println("NETWORK SIZE: "+this.replicas.size());
    }

    //=======================DATA-FILES-METHODS=========================================================================

    private boolean checkClone(Report report){

        for(Report entry: reps){
            if (entry.getEpoch() == report.getEpoch()){
                if (entry.getPosY() == report.getPosY() && entry.getPosX() == report.getPosX()) {
                    if (entry.getUsername().equals(report.getUsername())) {
                        if (entry.getWitness().equals(report.getWitness())) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;

    }

    private void cleanRepetition(ArrayList<Report> list,int op){

        if(op == 0){ // operation 0 for removal of user repetition
            for (int i = 0; i < list.size(); i++) {
                for(int j = i+1; j < list.size(); j++){
                    if(list.get(i).getUsername().equals(list.get(j).getUsername())){
                        list.remove(j);
                        j--;
                    }
                }
            }
        }else if(op == 1){
            for (int i = 0; i < list.size(); i++) {
                for(int j = i+1; j < list.size(); j++){
                    if(list.get(i).getUsername().equals(list.get(j).getUsername())){
                        if(list.get(i).getWitness().equals(list.get(j).getWitness())){
                            if(list.get(i).getPosX() == list.get(j).getPosX()){
                                if(list.get(i).getPosY() == list.get(j).getPosY()){
                                    list.remove(j);
                                    j--;
                                }
                            }
                        }
                    }
                }
            }
        }

    }

    private void synchronize() throws IOException, ClassNotFoundException {

        ObjectInputStream ois, oist;
        ArrayList<Report> tempRepsU, repsU;
        ConcurrentHashMap<String,Double> tempU, u;
        File tFile = new File("TempClientReports.txt");
        File file = new File("ClientReports.txt");
        File fileu = new File("SystemUsers.txt");
        File tFileu = new File("TempSystemUsers.txt");

        if(!tFile.exists()){
            if (file.length() == 0){
                this.reps = new ArrayList<>();
                System.out.println("Array is empty. Next update will make it usable.");
            }
            else{
                ois = new ObjectInputStream(new FileInputStream(file));
                this.reps = (ArrayList<Report>) ois.readObject();
                System.out.println("LOAD SUCCESSFUL");
                System.out.println("SIZE OF LOAD "+this.reps.size());
                ois.close();
            }
        }else{
            if(file.exists()){
                try{
                    ois = new ObjectInputStream(new FileInputStream(file));
                    oist = new ObjectInputStream(new FileInputStream(tFile));
                    tempRepsU = (ArrayList<Report>) oist.readObject();
                    repsU = (ArrayList<Report>) ois.readObject();
                    if(tempRepsU.size() <= repsU.size()){
                        this.reps = repsU;
                        oist.close();
                        boolean del = tFile.delete();
                        System.out.println("Delete:"+del);
                    }else{
                        this.reps = tempRepsU;
                        ObjectOutputStream oos= new ObjectOutputStream(
                                new FileOutputStream(file));
                        oos.writeObject(this.reps);
                        oist.close();
                        boolean del = tFile.delete();
                        System.out.println("Delete:"+del);
                        oos.close();
                    }
                    ois.close();
                }catch (IOException e){
                    System.out.println("ENTER");
                    oist = new ObjectInputStream(new FileInputStream(tFile));
                    this.reps = (ArrayList<Report>) oist.readObject();
                    System.out.println("+"+this.reps.size());
                    oist.close();
                    ObjectOutputStream oos= new ObjectOutputStream(
                            new FileOutputStream(file));
                    oos.writeObject(this.reps);
                    boolean del = tFile.delete();
                    System.out.println("Delete:"+del);
                    oos.close();
                }
            }else{
                oist = new ObjectInputStream(new FileInputStream(tFile));
                this.reps = (ArrayList<Report>) oist.readObject();
                oist.close();
                ObjectOutputStream oos= new ObjectOutputStream(
                        new FileOutputStream(file));
                oos.writeObject(this.reps);
                tFile.delete();
                oos.close();
            }
        }

        if(!tFileu.exists()){
            if (fileu.length() == 0){
                this.allSystemUsers = new ConcurrentHashMap<>();
                System.out.println("Array is empty. Next update will make it usable.");
            }
            else{
                ois = new ObjectInputStream(new FileInputStream(fileu));
                this.allSystemUsers = (ConcurrentHashMap<String,Double>) ois.readObject();
                System.out.println("LOAD SUCCESSFUL");
                System.out.println("SIZE OF LOAD "+this.allSystemUsers.size());
                ois.close();
            }
        }else{
            if(fileu.exists()){
                try{
                    ois = new ObjectInputStream(new FileInputStream(fileu));
                    oist = new ObjectInputStream(new FileInputStream(tFileu));
                    tempU = (ConcurrentHashMap<String,Double>) oist.readObject();
                    u = (ConcurrentHashMap<String,Double>) ois.readObject();
                    if(tempU.size() <= u.size()){
                        this.allSystemUsers = u;
                        oist.close();
                        boolean del = tFileu.delete();
                        System.out.println("Delete:"+del);
                    }else{
                        this.allSystemUsers = tempU;
                        oist.close();
                        ObjectOutputStream oos= new ObjectOutputStream(
                                new FileOutputStream(fileu));
                        oos.writeObject(this.allSystemUsers);
                        boolean del = tFileu.delete();
                        System.out.println("Delete:"+del);
                        oos.close();
                    }
                    ois.close();
                    oist.close();
                }catch (IOException e){
                    oist = new ObjectInputStream(new FileInputStream(tFileu));
                    this.allSystemUsers = (ConcurrentHashMap<String,Double>) oist.readObject();
                    System.out.println("+"+this.allSystemUsers.size());
                    oist.close();
                    ObjectOutputStream oos= new ObjectOutputStream(
                            new FileOutputStream(fileu));
                    oos.writeObject(this.allSystemUsers);
                    boolean del = tFileu.delete();
                    System.out.println("Delete:"+del);
                    oos.close();
                }
            }else{
                oist = new ObjectInputStream(new FileInputStream(tFileu));
                this.allSystemUsers = (ConcurrentHashMap<String,Double>) oist.readObject();
                oist.close();
                ObjectOutputStream oos= new ObjectOutputStream(
                        new FileOutputStream(fileu));
                oos.writeObject(this.allSystemUsers);
                tFileu.delete();
                oos.close();

            }
        }
    }

    private void updateReports() throws IOException {

        File file=new File("TempClientReports.txt");
        ObjectOutputStream oos= new ObjectOutputStream(
                new FileOutputStream(file));
        oos.writeObject(this.reps);
        System.out.println("FILE R UPDATED. NEW SIZE "+this.reps.size());
        oos.close();
    }

    private void updateUsers() throws IOException{

        File file=new File("TempSystemUsers.txt");
        ObjectOutputStream oos= new ObjectOutputStream(
                new FileOutputStream(file));
        oos.writeObject(this.allSystemUsers);
        System.out.println("FILE SU UPDATED. NEW SIZE "+this.allSystemUsers.size());
        oos.close();
    }

    private ArrayList<Report> fetchReports(ClientInterface c, int epoch){

        //String user = c.getUserId();
        ArrayList<Report> clientReports = (ArrayList<Report>) this.reps.clone();
        System.out.println("fetching size: "+clientReports.size());
        for(int i = 0; i < clientReports.size();i++){
            if(!clientReports.get(i).getC().equals(c)){
                clientReports.remove(i);
                i--;
            }else if(clientReports.get(i).getEpoch() != epoch){
                clientReports.remove(i);
                i--;
            }
        }
        return clientReports;
    }

    //==========================VERIFY DATA=============================================================================

    public void verifyF(int epoch){

        HashMap<String,Integer> userReps = new HashMap<>();

        for(String key : allSystemUsers.keySet()) {
            userReps.put(key,0);
        }

        for(String key : allSystemUsers.keySet()) {
            for(int i = 0; i < this.reps.size(); i++){
                if(epoch == this.reps.get(i).getEpoch()){
                    if(this.reps.get(i).getUsername().equals(key)){
                        userReps.put(key,userReps.get(key)+1);
                    }
                }
            }
        }

        for(String key : allSystemUsers.keySet()) {
            System.out.println("********** "+key+":"+userReps.get(key));
            if(userReps.get(key) > this.f[0]){ // f[0] = f is the highest cardinality for byzantines in system
                this.fileMan.appendInformation("********** AT EPOCH "+epoch+" IT'S ABSOLUTELY GUARANTEED THAT "+key+" POSITION IS CORRECT **********");
            }else if(userReps.get(key) > this.f[1]){ // f[1] = f' is the number of byzantines nearby other users
                this.fileMan.appendInformation("********** AT EPOCH "+epoch+" "+key+" POSITION IS PROBABLY CORRECT **********");
            }else{
                this.fileMan.appendInformation("********** AT EPOCH "+epoch+" THERE'S NO GUARANTEE THAT "+key+" POSITION IS CORRECT **********");
            }
        }

    }

    private String verifyLocationReport(ClientInterface c,String user, Report locationReport) {
        //witness signature
        try {
            /*FileInputStream fis1 = new FileInputStream("src/keys/" + locationReport.getWitness() + "Pub.key");
            byte[] decoded1 = new byte[fis1.available()];
            fis1.read(decoded1);
            fis1.close();
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decoded1);
            KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
            PublicKey pub = keyFacPub.generatePublic(publicKeySpec);

             */
            PublicKey pub = loadPublicKey(locationReport.getWitness());

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pub);
            byte[] hashBytes1 = java.util.Base64.getDecoder().decode(locationReport.getWitnessSignature());
            byte[] chunk = rsaCipher.doFinal(hashBytes1);
            String witSignature = Base64.getEncoder().encodeToString(chunk);

            System.out.println("signed in funtcion " + witSignature);

            String verifyHash = locationReport.getUsername() + locationReport.getWitnessNonce() + locationReport.getWitness() + locationReport.getEpoch();
            System.out.println("VERIFY " + verifyHash);
            byte[] messageByte1 = verifyHash.getBytes();
            MessageDigest digest1 = MessageDigest.getInstance("SHA-256");
            digest1.update(messageByte1);
            byte[] digestByte1 = digest1.digest();
            String digest64si = Base64.getEncoder().encodeToString(digestByte1);

            if(!witSignature.equals(digest64si)){
                return "Error";
            }

            //User Signature
            /*FileInputStream fis2 = new FileInputStream("src/keys/" + locationReport.getUsername() + "Pub.key");
            byte[] decoded2 = new byte[fis2.available()];
            fis2.read(decoded2);
            fis2.close();
            X509EncodedKeySpec publicKeySpecUser = new X509EncodedKeySpec(decoded2);
            KeyFactory keyFacPubUser = KeyFactory.getInstance("RSA");
            PublicKey pubClient = keyFacPubUser.generatePublic(publicKeySpecUser);

             */
            PublicKey pubClient = loadPublicKey(locationReport.getUsername());

            rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pubClient);
            byte[] hashBytes2 = java.util.Base64.getDecoder().decode(locationReport.getUserSignature());
            byte[] chunk2 = rsaCipher.doFinal(hashBytes2);
            String userSignature = Base64.getEncoder().encodeToString(chunk2);

            verifyHash = locationReport.getUsername() + locationReport.getNonce()  + locationReport.getEpoch() + locationReport.getPosX() + locationReport.getPosY();
            byte[] messageByte2 = verifyHash.getBytes();
            MessageDigest digest2 = MessageDigest.getInstance("SHA-256");
            digest2.update(messageByte2);
            byte[] digestByte2 = digest2.digest();
            String digest64user = Base64.getEncoder().encodeToString(digestByte2);

            if(!(locationReport.getPosX() >= 0 && locationReport.getPosX() <= GRIDDIMENISION & locationReport.getPosY() >= 0 && locationReport.getPosY() <= GRIDDIMENISION)){
                System.out.println("Malformed input found! ");

            }

            if(!userSignature.equals(digest64user)){
                return "Error";
            }

            String username =  locationReport.getUsername();
            //String witnessUsername =  locationReport.getWitness();
            try {
                int userNonce = locationReport.getNonce();
                if (!receiveNonce.containsKey(username)) {
                    receiveNonce.put(username, userNonce);
                }else if (receiveNonce.get(username) < userNonce) {
                    receiveNonce.replace(username, userNonce);
                } else {
                    this.fileMan.appendInformation("\t\t\tPossilble replay attack");
                    return "Error";
                }

                /*int witnessNonce = locationReport.getWitnessNonce();
                System.out.println("witness location nonce " + witnessNonce + " na hash " + receiveNonce.get(username));
                if (!receiveNonce.containsKey(witnessUsername)) {
                    receiveNonce.put(witnessUsername, witnessNonce);
                }else if (receiveNonce.get(witnessUsername) < witnessNonce) {
                    receiveNonce.replace(witnessUsername, witnessNonce);
                } else {
                    System.out.println("user -> server  witnessNonce" + witnessUsername + " map -> " + receiveNonce.get(witnessUsername) );
                    System.out.println("heeey 2");
                    this.fileMan.appendInformation("\t\t\tPossilble replay attack");
                    return "Error";
                }*/
            }
            catch (Exception e) {
                System.out.println("Malformed report");
                e.printStackTrace();
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            System.out.println("Wrong signature");
            e.printStackTrace();
            return "Error";
        } catch (InvalidKeyException e) {
            System.out.println("Wrong signature");
            e.printStackTrace();
            return "Error";
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return "Correct";
    }

    //=======================MAIN=======================================================================================

    public static void main(String args[]) {
        try {
            Server server = new Server(4,2,1,5);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NotBoundException e) {
            System.out.println("?RETRYING CONNECTION?");
        }

    }
}
