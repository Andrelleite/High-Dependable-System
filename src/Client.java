import javax.crypto.*;
import java.io.*;
import java.net.MalformedURLException;
import java.rmi.*;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static java.nio.charset.StandardCharsets.UTF_8;

class Pair<A, B> {
    A first = null;
    B second = null;

    Pair(A first, B second) {
        this.first = first;
        this.second = second;
    }

    public A getFirst() {
        return first;
    }

    public void setFirst(A first) {
        this.first = first;
    }

    public B getSecond() {
        return second;
    }

    public void setSecond(B second) {
        this.second = second;
    }

}

public class Client extends UnicastRemoteObject implements ClientInterface, Runnable{

    private static final long serialVersionUID = 1L;
    public static int GRIDDIMENISION = 40;
    private String username;
    private String password;
    private ClientInterface clientInterface;
    private int coordinate1;
    private int coordinate2;
    private List<SecretKey> symKeyList = new ArrayList();
    private List<String> keyList = new ArrayList();
    private int epoch;
    private int hasError = 0;
    private Map<Integer, Pair<Integer,Integer>> moveList = new HashMap<Integer, Pair<Integer,Integer>>();
    public ConcurrentHashMap<String,Integer> sendNonce= new ConcurrentHashMap<String, Integer>();
    public  ConcurrentHashMap<String,Integer> receiveNonce= new ConcurrentHashMap<String, Integer>();
    private List<String> clientsWithError = new ArrayList<String>();
    private OutputManager fileMan;
    private int gridNumber;
    private int servers;
    private int serverCount;

    private int F;
    private HashMap<ServerInterface,SecretKey> networkTosymKey;
    private HashMap<ServerInterface,String> ackList;
    private HashMap<ServerInterface,ServerReturn> readList;
    private HashMap<Integer,ArrayList<ServerReturn>> anwsers;
    private AtomicInteger requestId;
    private AtomicInteger timeStamp;
    private AtomicInteger writerTimeStamp;
    private String val;
    private String signature;
    private Boolean readingState;


    public Client(int grid, int servers, int f) throws RemoteException {
        super();
        this.gridNumber = grid;
        this.servers = servers;
        this.networkTosymKey = new HashMap<>();
        this.serverCount = 1;
        this.F = f;
        bonrrInit();
    }

    public Map<Integer, Pair<Integer, Integer>> getMoveList() {
        return moveList;
    }

    public String getKey(int index) {
        return keyList.get(index);
    }

    public void setKey(String key, int index) {
        this.keyList.add(index, key);
    }

    public ClientInterface getClientInterface() {
        return clientInterface;
    }

    public void setClientInterface(ClientInterface clientInterface) {
        this.clientInterface = clientInterface;
    }

    public SecretKey getSymKeyList(int i) {
        return symKeyList.get(i);
    }

    public OutputManager getFileMan(){ return this.fileMan; }

    public void setSymKeyList(SecretKey symKey, int index) {
        this.symKeyList.add(index, symKey);
    }

    public void setCoordinate1(int coordinate1) {
        this.coordinate1 = coordinate1;
    }

    public void setCoordinate2(int coordinate2) {
        this.coordinate2 = coordinate2;
    }

    public void setClientsWithError(List<String> clientsWithError){
        this.clientsWithError = clientsWithError;
    }

    public void setEpoch(int epoch) throws InterruptedException, IOException, ClassNotFoundException {
        this.epoch = epoch;
        if(moveList.containsKey(epoch)){
            this.setCoordinate1(moveList.get(epoch).getFirst());
            this.setCoordinate2(moveList.get(epoch).getSecond());
            //requestLocationProof();
            //getReports();
        }
    }

    public int getCoordinate1() {
        return coordinate1;
    }

    public int getCoordinate2() {
        return coordinate2;
    }

    public int getEpoch() {
        return epoch;
    }

    public int getHasError(){
        return hasError;
    }

    public void setError(int value) {
        this.hasError = value;
    }

    public String getUsername(){
        return username;
    }

    public void setUsername(String username){
        this.username = username;
        this.fileMan = new OutputManager(this.username,this.username);
        try {
            this.fileMan.initFile();
        } catch (FileNotFoundException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        // REPORT SUBMISSION
        for(int i = 1; i <= this.servers; i++){
            try{

                ServerInterface s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER"+(i));

                SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
                String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
                System.out.println("lado do client: " + encodedKey);
                this.setSymKeyList(secretKey, i-1);

                PublicKey pub = loadPublicKey("server" + (i));

                Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipherRSA.init(Cipher.ENCRYPT_MODE, pub);
                byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
                byte[] cipherBytes = cipherRSA.doFinal(keyBytes);
                String encryptedKey = Base64.getEncoder().encodeToString(cipherBytes);
                this.setKey(encryptedKey, i-1);
                s.subscribe(this.getClientInterface(),this.getUsername(), encryptedKey);
                this.networkTosymKey.put(s,secretKey);

            } catch (ConnectException ev){
                try {
                    retrySub(this.getClientInterface(),this.getUsername(), i);
                } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                    System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                    return;
                }
            } catch (RemoteException | MalformedURLException | NotBoundException e){
                try {
                    retrySub(this.getClientInterface(),this.getUsername(), i);
                } catch (ConnectException ev){
                    try {
                        retrySub(this.getClientInterface(),this.getUsername(), i);
                    } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                        System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                        return;
                    }
                } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                    System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                    return;
                }
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (IOException e) {
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
        }

    }

    public void setUsername(String username,String origin){
        this.username = username;
    }

    public void setPassword(String password){
        this.password = password;
    }

    public String getPassword(){
        return password;
    }

    public int getGridNumber(){
        return this.gridNumber;
    }

    public String echo(String message) throws RemoteException {
        System.out.println("recebeu!");
        return message;
    }

    public void verifyCoords (int x, int y) {
        if(!(x >= 0 && x <= GRIDDIMENISION & y >= 0 && y <= GRIDDIMENISION)){
            System.out.println("Malformed input found! " + this.getUsername());
            this.setError(1);
        }
    }

    public void loadMoves() {
        try {
            //coordenadas falsa
            int grid = getGridNumber();
            File myObj = new File("src/grid/grid"+grid+".txt");
            Scanner reader = new Scanner(myObj);
            while (reader.hasNextLine()) {
                String data = reader.nextLine();
                String username = data.split(",")[0];
                if(username.equals(this.getUsername())) {
                    try {
                        String epochString = data.split(",")[1];
                        int epoch = Integer.parseInt(epochString.split(" ")[1]);
                        String coord1 = data.split(", ")[2];
                        String coord2 = data.split(", ")[3];
                        int x2 = Integer.parseInt(coord1);
                        int y2 = Integer.parseInt(coord2);
                        verifyCoords(x2, y2);
                        if(moveList.containsKey(epoch)){
                            System.out.println("Two or more " + username +" coordinates in the same epoch!");
                            this.setError(1);
                        }
                        moveList.put(epoch, new Pair(x2, y2));
                    } catch (NumberFormatException ex) { // handle your exception
                        System.out.println("Malformed input found!");
                        this.setError(1);
                    }
                }
            }
            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();

        }
        System.out.println(this.moveList);
    }

    public void setRequestLocationProof() throws InterruptedException, IOException, ClassNotFoundException {
        requestLocationProof();
    }

    //=============================================================================================================

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

    public List<Report> generateLocationReportWitness(ClientInterface c, String username, int userEpoch, String signature, int nonce, String timestamp) throws RemoteException{
        try {
            this.fileMan.appendInformation("\n");
            this.fileMan.appendInformation(" [REQUEST TO BE WITNESS]  PROOF OF LOCATION FROM " + username);
            String verifyRet = verifySenderSignature(username, signature,String.valueOf(userEpoch),nonce, timestamp);
            if(verifyRet.equals(("Error"))){
                this.fileMan.appendInformation("\t\t\treport sender signature is wrong");
                return null;
            }

            if(!receiveNonce.containsKey(username)){
                receiveNonce.put(username, nonce);
            }else {
                if(receiveNonce.get(username) < nonce){
                    receiveNonce.replace(username, nonce);
                }else {
                    this.fileMan.appendInformation("\t\t\tPossilble replay attack");
                    return null;
                }
            }

            int grid = getGridNumber();
            File myObj = new File("src/grid/grid"+grid+".txt");
            Scanner reader = new Scanner(myObj);
            while (reader.hasNextLine()) {
                String data = reader.nextLine();
                String usernameFile = data.split(",")[0];
                try {
                    String epochString = data.split(",")[1];
                    int epoch = Integer.parseInt(epochString.split(" ")[1]);
                    if(userEpoch == epoch){

                        String coord1 = data.split(",")[2];
                        String coord2 = data.split(",")[3];

                        //vamos buscar as coordenadas a fontes seguras
                        //System.out.println("user: " +this.getUsername() + " epch: " + userEpoch);
                        double x2 = Double.parseDouble(coord1);
                        double y2 = Double.parseDouble(coord2);
                        int x1 = moveList.get(userEpoch).getFirst();
                        int y1 = moveList.get(userEpoch).getSecond();
                        double distaceCalc = Math.sqrt((Math.pow((x1-x2),2) + Math.pow((y1-y2),2)));
                        int distance = (int) distaceCalc;

                        if(distance <= 15 && usernameFile.equals(username)){

                            int nonceSend = 1;
                            if(!sendNonce.containsKey(username)){
                                sendNonce.put(username, nonceSend);
                            }else {
                                nonceSend = sendNonce.get(username);
                                nonceSend += 1;
                                sendNonce.replace(username, nonceSend);
                            }

                            //Get time
                            String time = java.time.LocalTime.now().toString();

                            String s = username + nonceSend + time + this.getUsername() + userEpoch; //+ this.getCoordinate1() + this.getCoordinate2();
                            PrivateKey priv = loadPrivKey(this.getUsername());

                            //Hash message
                            byte[] messageByte0 = s.getBytes();
                            MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                            digest0.update(messageByte0);
                            byte[] digestByte0 = digest0.digest();
                            String digest64 = Base64.getEncoder().encodeToString(digestByte0);

                            //sign the hash with the witness' private key
                            Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                            byte[] hashBytes = Base64.getDecoder().decode(digest64);
                            byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                            String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

                            List<Report> userReports = new ArrayList();

                            for(ServerInterface k: this.networkTosymKey.keySet()){

                                Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                                cipherReport.init(Cipher.ENCRYPT_MODE, this.networkTosymKey.get(k));
                                System.out.println("=====================CLIENT================= "+this.networkTosymKey.get(k));
                                String info = "posXq" + this.getCoordinate1() + "wposYq" + this.getCoordinate2();

                                //byte[] infoBytes = Base64.getDecoder().decode(info);
                                byte[] cipherBytes1 = cipherReport.doFinal(info.getBytes());
                                String loc = Base64.getEncoder().encodeToString(cipherBytes1);

                                this.fileMan.appendInformation("\t\tSENDER SIGNATURE: NONCE: " + nonceSend + " | SIGNATURE: " + signature);
                                userReports.add(new Report(c,-1,-1,userEpoch,username,"",-1, "",this.getUsername(),signedHash,nonceSend, time,loc,(int) k.getId()));
                            }

                            return userReports;
                        }
                    }
                } catch (NumberFormatException ex) { // handle your exception
                    System.out.println("Malformed input found!");
                    this.setError(1);
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                }
            }
            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        return null;
    }

    public ArrayList<String> findUser() {
        ArrayList<String> usersNearby = new ArrayList<>();
        try {
            int grid = getGridNumber();
            File myObj = new File("src/grid/grid"+grid+".txt");
            Scanner reader = new Scanner(myObj);
            while (reader.hasNextLine()) {
                String data = reader.nextLine();
                String username = data.split(",")[0];
                try {
                    String epochString = data.split(",")[1];
                    int epoch = Integer.parseInt(epochString.split(" ")[1]);
                    if(epoch == this.epoch){
                        String coord1 = data.split(",")[2];
                        String coord2 = data.split(",")[3];
                        double x2 = Double.parseDouble(coord1);
                        double y2 = Double.parseDouble(coord2);
                        int x1 = this.coordinate1;
                        int y1 = this.coordinate2;

                        double distaceCalc = Math.sqrt((Math.pow((x1-x2),2) + Math.pow((y1-y2),2)));
                        int distance = (int) distaceCalc;

                        if(distance <= 15 && !username.equals(this.getUsername()) && !clientsWithError.contains(username)){
                            System.out.println("-> " + this.getUsername() + " adiciona "  + username);
                            usersNearby.add(username);
                        }

                        /*if (usersNearby.size() == 5){
                            return usersNearby;
                        }*/
                    }
                } catch (NumberFormatException ex) { // handle your exception
                    System.out.println("Malformed input found!");
                    this.setError(1);
                }
            }
            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        return usersNearby;
    }

    public String verifyWitnessSignature(Report message, ClientInterface h) {
        try {
            PublicKey pub = loadPublicKey(message.getWitness());

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pub);
            byte[] hashBytes1 = java.util.Base64.getDecoder().decode(message.getWitnessSignature());
            byte[] chunk = rsaCipher.doFinal(hashBytes1);
            String witSiganture = Base64.getEncoder().encodeToString(chunk);

            String verifyHash = message.getUsername() + message.getWitnessNonce() + message.getWitnessTimeStamp() + message.getWitness() + message.getEpoch();

            byte[] messageByte1 = verifyHash.getBytes();
            MessageDigest digest1 = MessageDigest.getInstance("SHA-256");
            digest1.update(messageByte1);
            byte[] digestByte1 = digest1.digest();
            String digest64si = Base64.getEncoder().encodeToString(digestByte1);

            if(witSiganture.equals(digest64si)){
                return "Correct";
            }else{
                return "Error";
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
        return "Error";
    }

    public String verifySenderSignature(String user, String digitalSignature, String epoch, int nonce, String time) {
        try {

            PublicKey pub = loadPublicKey(user);

            //String s01 =  time1 + user + epoch;

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pub);
            byte[] hashBytes1 = java.util.Base64.getDecoder().decode(digitalSignature);
            byte[] chunk = rsaCipher.doFinal(hashBytes1);
            String signature = Base64.getEncoder().encodeToString(chunk);

            String verifyHash =  nonce + time + user + epoch;
            byte[] messageByte1 = verifyHash.getBytes();
            MessageDigest digest1 = MessageDigest.getInstance("SHA-256");
            digest1.update(messageByte1);
            byte[] digestByte1 = digest1.digest();
            String digest64si = Base64.getEncoder().encodeToString(digestByte1);

            if(signature.equals(digest64si)){
                return "Correct";
            }else{
                return "Error";
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
        return "Error";
    }

    public void requestLocationProof() throws InterruptedException, IOException, ClassNotFoundException {

        ArrayList<String> usersToContact = findUser();
        List<Report> reportsList = new ArrayList();
        Report message = null;
        String serverSignature = "";
        this.fileMan.appendInformation("\n");
        this.fileMan.appendInformation(" [REQUEST TO SERVER]  PROOF OF LOCATION");
        if(usersToContact.size() != 0){
            Iterator i = usersToContact.iterator();
            while (i.hasNext()) {

                String userToContact = (String) i.next();
                this.fileMan.appendInformation("\t\t"+this.username + " trying to contact " + userToContact);

                try {

                    ClientInterface h = (ClientInterface) Naming.lookup("rmi://127.0.0.1:7001/" + userToContact);
                    int nonceSend = 1;

                    if(!sendNonce.containsKey(userToContact)){
                        sendNonce.put(userToContact, nonceSend);
                    }else {
                        nonceSend = sendNonce.get(userToContact);
                        nonceSend += 1;
                        sendNonce.replace(userToContact, nonceSend);
                    }

                    String time1 = java.time.LocalTime.now().toString();
                    String s01 =  nonceSend + time1 + this.getUsername() + this.getEpoch(); //+ this.getCoordinate1() + this.getCoordinate2();
                    PrivateKey priv1 = loadPrivKey(this.getUsername());

                    //Hash message
                    byte[] messageByte01 = s01.getBytes();
                    MessageDigest digest01 = MessageDigest.getInstance("SHA-256");
                    digest01.update(messageByte01);
                    byte[] digestByte01 = digest01.digest();
                    String digest641 = Base64.getEncoder().encodeToString(digestByte01);

                    //sign the hash with the witness' private key
                    Cipher cipherHash1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipherHash1.init(Cipher.ENCRYPT_MODE, priv1);
                    byte[] hashBytes1 = Base64.getDecoder().decode(digest641);
                    byte[] finalHashBytes1 = cipherHash1.doFinal(hashBytes1);
                    String digitalSignature = Base64.getEncoder().encodeToString(finalHashBytes1);



                    reportsList = h.generateLocationReportWitness(this.getClientInterface(),this.getUsername(), this.getEpoch(),digitalSignature,nonceSend, time1);
                    if(reportsList == null){
                        this.fileMan.appendInformation("\t\t\treport is null");
                        return;
                    }

                    // 1,N BEGIN
                    this.writerTimeStamp.addAndGet(1); // WTS + 1
                    for(int k = 1; k <= reportsList.size(); k++){ // forall q £ PI Send

                        if(reportsList == null){
                            this.fileMan.appendInformation("\t\t\treport is null");
                            continue;
                        }

                        message = reportsList.get(k-1);


                        if(message.getC() != this.getClientInterface() && !message.getUsername().equals(this.getUsername()) && message.getEpoch() != this.epoch && !message.getWitness().equals(userToContact)){
                            this.fileMan.appendInformation("\t\t\treport don't pass");
                            continue;
                        }

                        String verifyRet = verifyWitnessSignature(message, h);
                        if(verifyRet.equals(("Error"))){
                            this.fileMan.appendInformation("\t\t\treport witness signature is wrong");
                            continue;
                        }

                        int witnessNonce = message.getWitnessNonce();
                        try {

                            if (!receiveNonce.containsKey(userToContact)) {
                                receiveNonce.put(userToContact, witnessNonce);
                                //<= porque recebe relatorios com o mesmo nonce de servers diferentes
                            }else if (receiveNonce.get(userToContact) <= witnessNonce) {
                                receiveNonce.replace(userToContact, witnessNonce);
                            } else {
                                this.fileMan.appendInformation("\t\t\tPossilble replay attack");
                                continue;
                            }
                        }
                        catch (Exception e) {
                            System.out.println("Malformed report");
                            e.printStackTrace();
                        }

                        int sid = (int) message.getServerId();
                        int nonceServer = 1;
                        if(!sendNonce.containsKey("server" + (sid))){
                            sendNonce.put("server" + (sid), nonceServer);
                        }else {
                            nonceServer = sendNonce.get("server" + (sid));
                            nonceServer += 1;
                            sendNonce.replace("server" + (sid), nonceServer);
                        }

                        ServerInterface s = null;
                        for(ServerInterface sr: this.networkTosymKey.keySet()){
                            if(message.getServerId() == sr.getId()){
                                s = sr;
                                break;
                            }
                        }

                        LocalTime clientTime = LocalTime.now();
                        String time = clientTime.toString();

                        String s1 = "";
                        String digest64 = "";
                        int hashInt = 0;

                        do{
                            hashInt++;
                            s1 = this.getUsername() + nonceServer + time + this.getEpoch() + this.getCoordinate1() + this.getCoordinate2() + hashInt;
                            //Hash message
                            byte[] messageByte0 = s1.getBytes();
                            MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                            digest0.update(messageByte0);
                            byte[] digestByte0 = digest0.digest();
                            digest64 = Base64.getEncoder().encodeToString(digestByte0);
                        }
                        while(!digest64.startsWith("0"));
                        //TODO: mudar para minimo 4 zeros
                        //System.out.println("HASH: " + digest64);

                        String s2 = String.valueOf(this.writerTimeStamp.get());
                        PrivateKey priv = loadPrivKey(this.getUsername());

                        //sign the hash with the client's private key
                        Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                        byte[] hashBytes = Base64.getDecoder().decode(digest64);
                        byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                        String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

                        //Hash message wts
                        byte[] messageByte1 = s2.getBytes();
                        MessageDigest digest1 = MessageDigest.getInstance("SHA-256");
                        digest1.update(messageByte1);
                        byte[] digestByte1 = digest1.digest();
                        digest64 = Base64.getEncoder().encodeToString(digestByte1);


                        //sign the hash with the client's private key
                        hashBytes = Base64.getDecoder().decode(digest64);
                        finalHashBytes = cipherHash.doFinal(hashBytes);
                        String signedHash1 = Base64.getEncoder().encodeToString(finalHashBytes);



                        //encrypt the report's sensitive information
                        Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        cipherReport.init(Cipher.ENCRYPT_MODE, this.networkTosymKey.get(s));

                        String info = "posXq" + this.getCoordinate1() + "wposYq" + this.getCoordinate2() + "wepochq" + message.getEpoch();
                        message.setEpoch(-1);

                        //byte[] infoBytes = Base64.getDecoder().decode(info);
                        byte[] cipherBytes1 = cipherReport.doFinal(info.getBytes());
                        String loc = Base64.getEncoder().encodeToString(cipherBytes1);

                        message.setEncryptedInfo(loc);

                        //byte[] witnessBytes = Base64.getDecoder().decode(message.getWitness());
                        byte[] cipherBytes3 = cipherReport.doFinal(message.getWitness().getBytes());
                        String loc3 = Base64.getEncoder().encodeToString(cipherBytes3);

                        message.setWitness(loc3);
                        message.setNonce(nonceServer);
                        message.setTimeStamp(time);
                        message.setUserSignature(signedHash);
                        message.setIntPOW(hashInt);


                        // REPORT SUBMISSION
                        try{
                            serverSignature = s.submitLocationReport(this.getClientInterface(),this.getUsername(),message,this.writerTimeStamp.get(),signedHash1);
                            int ack = Integer.parseInt(serverSignature.split(",")[1]);
                            serverSignature = serverSignature.split(",")[0];
                            if(!serverSignature.equals("null") && ack == this.writerTimeStamp.get()){
                                this.ackList.put(s,serverSignature);
                            }
                        } catch (ConnectException ev){
                            try {
                                serverSignature = retry(this.getClientInterface(),this.getUsername(),message);
                                System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                            } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                                System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                                continue;
                            }
                        } catch (RemoteException e){
                            try {
                                serverSignature = retry(this.getClientInterface(),this.getUsername(),message);
                                System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                            } catch (ConnectException ev){
                                serverSignature = retry(this.getClientInterface(),this.getUsername(),message);
                                System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                            } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                                System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                                continue;
                            }
                        }

                        if(serverSignature.equals("")){
                            this.fileMan.appendInformation("\t\tSOMETHING WRONG HAPPENED, NO RETURN FROM THE SERVER");
                        }else if(serverSignature.equals("null")){
                            this.fileMan.appendInformation("\t\tSOMETHING WRONG HAPPENED, RETURN NOT SIGNED");
                        }else {
                            int nonceServerSign = Integer.parseInt((serverSignature.split(" ")[1]));
                            String signServerHash = serverSignature.split(" ")[4];
                            String timeServerSign = serverSignature.split(" ")[7];
                            String stringTohash = this.username + nonceServerSign + timeServerSign + this.getEpoch();
                            String verifySignRet = verifyServerSign(signServerHash, stringTohash, sid);

                            if(verifySignRet.equals("Correct")){
                                if (!receiveNonce.containsKey("server" + (sid))) {
                                    receiveNonce.put("server" + (sid), nonceServerSign);
                                }else if ((receiveNonce.get("server"+sid))  < nonceServerSign) {
                                    receiveNonce.replace("server" + (sid), nonceServerSign);
                                } else {
                                    this.fileMan.appendInformation("\t\t\tPossilble replay attack");
                                    return;
                                }
                            }else {
                                System.out.println("SERVER SIGN HASH DOESN'T MATCH THE DATA (REQUEST LOCATION PROOF)");
                            }
                        }

                    }

                    //ACK PHASE
                    if(this.ackList.size() > (this.servers + this.F) / 2){
                        for (ServerInterface s:this.ackList.keySet()){
                            this.fileMan.appendInformation("\t\tSERVER"+s.getId()+" HEALTHCHECK: A-OK");
                        }
                        System.out.println("SERVER ACK SIZE:" + this.ackList.size());
                    }
                    this.ackList.clear(); // acklist = [Null]
                    // END (1,N)

                } catch (InvalidKeyException e) {
                    //this.fileMan.appendInformation( "\t\t"+userToContact + " NOT FOUND.");
                    System.out.println("KeyStore Password incorrect!");
                }catch (Exception e) {
                    this.fileMan.appendInformation( "\t\t"+userToContact + " NOT FOUND.");
                    System.out.println("Exception in main: " + e);
                    e.printStackTrace();
                }
            }
        }
        else{
            this.fileMan.appendInformation("\t\t"+this.getUsername() + " DOESN'T HAVE ANY USERS NEARBY. IT'S SAD, BUT YOU ARE ALONE.");
        }
    }

    private String verifyServerSign(String serverHash, String userToHash, int serverId) {

        try {

            PublicKey pub = loadPublicKey("server" + serverId);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pub);
            byte[] hashBytes1 = java.util.Base64.getDecoder().decode(serverHash);
            byte[] chunk = rsaCipher.doFinal(hashBytes1);
            String witSignature = Base64.getEncoder().encodeToString(chunk);

            byte[] messageByte2 = userToHash.getBytes();
            MessageDigest digest2 = MessageDigest.getInstance("SHA-256");
            digest2.update(messageByte2);
            byte[] digestByte2 = digest2.digest();
            String userHash = Base64.getEncoder().encodeToString(digestByte2);

            if(!witSignature.equals(userHash)){
                return "Error";
            }

        } catch ( NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException | InvalidKeyException e) {
            System.out.println("Wrong signature");
            e.printStackTrace();
            return "Error";
        }
        return "Correct";
    }

    public void reportWriteBack(ArrayList<Report> reportsList) throws InterruptedException, IOException, ClassNotFoundException {

        ArrayList<String> usersToContact = findUser();
        Report message = null;
        String serverSignature = "";
        this.fileMan.appendInformation("\n");
        this.fileMan.appendInformation(" [REQUEST TO SERVER]  PROOF OF LOCATION");

        try{
            // 1,N BEGIN
            this.writerTimeStamp.addAndGet(1); // WTS + 1
            System.out.println("================================ REPORTS SIZE : "+reportsList.size());
            for(int k = 1; k <= reportsList.size(); k++){ // forall q £ PI Send

                if(reportsList == null){
                    this.fileMan.appendInformation("\t\t\treport is null");
                    continue;
                }

                message = reportsList.get(k-1);
                String userToContact = message.getWitness();
                System.out.println(" ==================================== USER TO CONTACT =================================== "+userToContact);
                ClientInterface h = (ClientInterface) Naming.lookup("rmi://127.0.0.1:7001/" + userToContact);
                if(message.getC() != this.getClientInterface() && !message.getUsername().equals(this.getUsername()) && message.getEpoch() != this.epoch && !message.getWitness().equals(userToContact)){
                    this.fileMan.appendInformation("\t\t\treport don't pass");
                    continue;
                }

                String verifyRet = verifyWitnessSignature(message, h);
                if(verifyRet.equals(("Error"))){
                    this.fileMan.appendInformation("\t\t\treport witness signature is wrong");
                    continue;
                }

                int witnessNonce = message.getWitnessNonce();
                try {

                    if (!receiveNonce.containsKey(userToContact)) {
                        receiveNonce.put(userToContact, witnessNonce);
                    }else if (receiveNonce.get(userToContact) <= witnessNonce) {
                        receiveNonce.replace(userToContact, witnessNonce);
                    } else {
                        this.fileMan.appendInformation("\t\t\tPossilble replay attack");
                        continue;
                    }
                }
                catch (Exception e) {
                    System.out.println("Malformed report");
                    e.printStackTrace();
                }

                int sid = (int) message.getServerId();
                int nonceServer = 1;
                if(!sendNonce.containsKey("server" + (sid))){
                    sendNonce.put("server" + (sid), nonceServer);
                }else {
                    nonceServer = sendNonce.get("server" + (sid));
                    nonceServer += 1;
                    sendNonce.replace("server" + (sid), nonceServer);
                }

                ServerInterface s = null;
                for(ServerInterface sr: this.networkTosymKey.keySet()){
                    if(message.getServerId() == sr.getId()){
                        s = sr;
                        break;
                    }
                }

                LocalTime clientTime = LocalTime.now();
                String time = clientTime.toString();
                String s1 = "";
                String digest64 = "";
                int hashInt = 0;

                do{
                    hashInt++;
                    s1 = this.getUsername() + nonceServer + time + this.getEpoch() + this.getCoordinate1() + this.getCoordinate2() + hashInt;
                    //Hash message
                    byte[] messageByte0 = s1.getBytes();
                    MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                    digest0.update(messageByte0);
                    byte[] digestByte0 = digest0.digest();
                    digest64 = Base64.getEncoder().encodeToString(digestByte0);
                }
                while(!digest64.startsWith("0"));
                //TODO: mudar para minimo 4 zeros
                String s2 = String.valueOf(this.writerTimeStamp.get());
                PrivateKey priv = loadPrivKey(this.getUsername());


                //sign the hash with the client's private key
                Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                byte[] hashBytes = Base64.getDecoder().decode(digest64);
                byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

                //Hash message wts
                byte[] messageByte1 = s2.getBytes();
                MessageDigest digest1 = MessageDigest.getInstance("SHA-256");
                digest1.update(messageByte1);
                byte[] digestByte1 = digest1.digest();
                digest64 = Base64.getEncoder().encodeToString(digestByte1);


                //sign the hash with the client's private key
                hashBytes = Base64.getDecoder().decode(digest64);
                finalHashBytes = cipherHash.doFinal(hashBytes);
                String signedHash1 = Base64.getEncoder().encodeToString(finalHashBytes);



                //encrypt the report's sensitive information
                Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipherReport.init(Cipher.ENCRYPT_MODE, this.networkTosymKey.get(s));

                String info = "posXq" + this.getCoordinate1() + "wposYq" + this.getCoordinate2() + "wepochq" + message.getEpoch();
                message.setEpoch(-1);

                //byte[] infoBytes = Base64.getDecoder().decode(info);
                byte[] cipherBytes1 = cipherReport.doFinal(info.getBytes());
                String loc = Base64.getEncoder().encodeToString(cipherBytes1);

                message.setEncryptedInfo(loc);

                //byte[] witnessBytes = Base64.getDecoder().decode(message.getWitness());
                byte[] cipherBytes3 = cipherReport.doFinal(message.getWitness().getBytes());
                String loc3 = Base64.getEncoder().encodeToString(cipherBytes3);

                message.setWitness(loc3);
                message.setNonce(nonceServer);
                message.setTimeStamp(time);
                message.setUserSignature(signedHash);
                message.setIntPOW(hashInt);


                // REPORT SUBMISSION
                try{
                    serverSignature = s.submitLocationReport(this.getClientInterface(),this.getUsername(),message,this.writerTimeStamp.get(),signedHash1);
                    int ack = Integer.parseInt(serverSignature.split(",")[1]);
                    serverSignature = serverSignature.split(",")[0];
                    if(!serverSignature.equals("null") && ack == this.writerTimeStamp.get()){
                        this.ackList.put(s,serverSignature);
                    }
                } catch (ConnectException ev){
                    try {
                        serverSignature = retry(this.getClientInterface(),this.getUsername(),message);
                        System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                    } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                        System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                        continue;
                    }
                } catch (RemoteException e){
                    try {
                        serverSignature = retry(this.getClientInterface(),this.getUsername(),message);
                        System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                    } catch (ConnectException ev){
                        serverSignature = retry(this.getClientInterface(),this.getUsername(),message);
                        System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                    } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                        System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                        continue;
                    }
                }

                if(serverSignature.equals("")){
                    this.fileMan.appendInformation("\t\tSOMETHING WRONG HAPPENED, NO RETURN FROM THE SERVER");
                }else if(serverSignature.equals("null")){
                    this.fileMan.appendInformation("\t\tSOMETHING WRONG HAPPENED, RETURN NOT SIGNED");
                }else {
                    int nonceServerSign = Integer.parseInt((serverSignature.split(" ")[1]));
                    String signServerHash = serverSignature.split(" ")[4];
                    String timeServerSign = serverSignature.split(" ")[7];
                    String stringTohash = this.username + nonceServerSign + timeServerSign + this.getEpoch();
                    String verifySignRet = verifyServerSign(signServerHash, stringTohash, sid);

                    if(verifySignRet.equals("Correct")){
                        if (!receiveNonce.containsKey("server" + (sid))) {
                            receiveNonce.put("server" + (sid), nonceServerSign);
                        }else if ((receiveNonce.get("server"+sid))  < nonceServerSign) {
                            receiveNonce.replace("server" + (sid), nonceServerSign);
                        } else {
                            this.fileMan.appendInformation("\t\t\tPossilble replay attack");
                            return;
                        }
                    }else {
                        System.out.println("SERVER SIGN HASH DOESN'T MATCH THE DATA (REQUEST LOCATION PROOF)");
                    }
                }

            }

            //ACK PHASE
            if(this.ackList.size() > (this.servers + this.F) / 2){
                for (ServerInterface s:this.ackList.keySet()){
                    this.fileMan.appendInformation("\t\tSERVER"+s.getId()+" HEALTHCHECK: A-OK");
                }
                System.out.println("SERVER ACK SIZE:" + this.ackList.size());
            }
            this.ackList.clear(); // acklist = [Null]
            // END (1,N)
        }catch (Exception e){
            System.out.println("");
        }

    }

    public void getReports(String ep) throws RemoteException, InterruptedException {

        Integer[] rid = {this.requestId.addAndGet(1)};
        ClientInterface tempC = this.getClientInterface();
        OutputManager tempF = this.fileMan;
        int servers = this.servers;
        int F = this.F;
        int acks = 0;
        this.readingState = true;
        boolean reading = this.readingState;
        HashMap<ServerInterface,SecretKey> netToSym = this.networkTosymKey;


        Thread worker = new Thread("Worker"){
            @Override
            public void run(){
                try {
                    if(tempC.getUsername().equals("user2")){
                        try {
                            Thread.sleep(20000);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                } catch (RemoteException e) {
                    e.printStackTrace();
                }
                HashMap<ServerInterface,ServerReturn> readList = new HashMap<>();
                ServerInterface sr = null;
                ArrayList<Report> reports = new ArrayList<>();
                try {
                    for(ServerInterface s: netToSym.keySet()){

                        Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        cipherReport.init(Cipher.ENCRYPT_MODE, netToSym.get(s));

                        byte[] cipherBytes3 = cipherReport.doFinal(ep.getBytes());
                        String loc3 = Base64.getEncoder().encodeToString(cipherBytes3);

                        int nonceServer = 1;
                        int k = s.getId();
                        if(!sendNonce.containsKey("server"+(k))){
                            sendNonce.put("server", nonceServer+(k));
                        }else {
                            nonceServer = sendNonce.get("server"+(k));
                            nonceServer += 1;
                            sendNonce.replace("server"+(k), nonceServer);
                        }

                        String s1 = "";
                        String digest64 = "";
                        int hashInt = 0;

                        do{
                            hashInt++;
                            s1 = tempC.getUsername() + rid[0] + hashInt;
                            //Hash message
                            byte[] messageByte0 = s1.getBytes();
                            MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                            digest0.update(messageByte0);
                            byte[] digestByte0 = digest0.digest();
                            digest64 = Base64.getEncoder().encodeToString(digestByte0);
                        }
                        while(!digest64.startsWith("0"));
                        //TODO: mudar para min 4 zeros
                        PrivateKey priv = loadPrivKey(tempC.getUsername());

                        //sign the hash with the client's private key
                        Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                        byte[] hashBytes = Base64.getDecoder().decode(digest64);
                        byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                        String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

                        ServerReturn r = s.obtainLocationReport(tempC,loc3,tempC.getUsername(),rid[0], signedHash, hashInt);

                        if(r.getReports() == null || r.getServerProof() == null){
                            tempF.appendInformation("\n");
                            tempF.appendInformation(" [REQUEST TO SERVER]  MY REPORTS");
                            tempF.appendInformation(" [REQUEST TO SERVER]  DENIED");
                            return;
                        }

                        Cipher rsaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        rsaCipher.init(Cipher.DECRYPT_MODE, netToSym.get(s));

                        String serverSignature = r.getServerProof();
                        int nonceServerSign = Integer.parseInt((serverSignature.split(" ")[1]));
                        String signServerHash = serverSignature.split(" ")[4];
                        String timeServerSign = serverSignature.split(" ")[7];
                        String stringTohash = tempC.getUsername() + nonceServerSign + timeServerSign + ep;
                        String verifySignRet = verifyServerSign(signServerHash, stringTohash, k);

                        if(verifySignRet.equals("Correct") && rid[0] == r.getRid()){
                            if(verifiySignatureW(r.getReports(),s,0)==1) {
                                readList.put(s, r);
                            }

                            if (!receiveNonce.containsKey("server" +(k))) {
                                receiveNonce.put("server"+(k), nonceServerSign);
                            }else if (receiveNonce.get("server"+(k)) < nonceServerSign) {
                                receiveNonce.replace("server"+(k), nonceServerSign);
                            } else {
                                tempF.appendInformation("\t\t\tPossilble replay attack");
                                return;
                            }
                        }else {
                            System.out.println("SERVER SIGN HASH DOESN'T MATCH THE DATA (GET REPORTS)");
                        }

                    }
                    String maxTimestamp;
                    // verify cardinality
                    if(readList.size() > (servers + F) / 2){
                        //verify highest value
                        ServerInterface maxKey = null;
                        String timestamp = "";
                        String temp = "";
                        for(ServerInterface key: readList.keySet()){
                            temp = highestVal(readList.get(key).getReports());
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
                        maxTimestamp = timestamp;
                        reports = readList.get(maxKey).getReports();
                    }

                    tempF.appendInformation("\n");
                    tempF.appendInformation(" [REQUEST TO SERVER]  MY REPORTS");
                    readList.clear();
                    Cipher rsaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    System.out.println( netToSym.get(sr));
                    rsaCipher.init(Cipher.DECRYPT_MODE, netToSym.get(sr));
                    Iterator i = reports.iterator();
                    int j = 0;

                    while (i.hasNext()) { // trigger readreturn

                        Report re = (Report) i.next();

                        byte[] hashBytes1 = java.util.Base64.getDecoder().decode(re.getEncryptedInfo());
                        byte[] chunk = rsaCipher.doFinal(hashBytes1);
                        String info =  new String(chunk, UTF_8);
                        info = info.split("=")[0];

                        re.setPosX(Integer.parseInt(info.split("w")[0].split("q")[1]));
                        re.setPosY(Integer.parseInt(info.split("w")[1].split("q")[1]));

                        re.setEpoch(Integer.parseInt(ep));

                        j++;
                        tempF.appendInformation("\t\t ====== REPORT #"+j);
                        tempF.appendInformation("\t\t\tRECEIVED THE SERVER PROOF OF LOCATION FROM - "+ re.getUsername());
                        tempF.appendInformation("\t\t\tUSER SIGNATURE: " + re.getUserSignature() + "NONCE: " + re.getNonce() + "TIMESTAMP: " + re.getTimeStamp());
                        tempF.appendInformation("\t\t\tPOS: (" + re.getPosX() + "," + re.getPosY() + ") AT EPOCH " + re.getEpoch());
                        tempF.appendInformation("\t\t\tWITNESS: " + re.getWitness());
                        tempF.appendInformation("\t\t\tWITNESS SIGNATURE: " + re.getWitnessSignature());
                        tempF.appendInformation("\t\t\tWITNESS NONCE: " + re.getWitnessNonce() + "WITNESS TIMESTAMP: " + re.getWitnessTimeStamp());

                    }

                    // trigger broadcast

                    reportWriteBack(reports);


                } catch (MalformedURLException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        };
        this.readingState = false;
        worker.start();

    } /*THREAD WARNING*/

    public void getMyWitnessProofs(String epi, String epf) throws RemoteException{

        Integer[] rid = {this.requestId.addAndGet(1)};
        ClientInterface tempC = this.getClientInterface();
        OutputManager tempF = this.fileMan;
        int servers = this.servers;
        int F = this.F;
        HashMap<ServerInterface,SecretKey> netToSym = this.networkTosymKey;

        Thread worker = new Thread("Worker"){
            @Override
            public void run(){
                ServerInterface sr = null;
                ArrayList<Report> reports = new ArrayList<>();
                HashMap<ServerInterface,ServerReturn> readList = new HashMap<>();

                try {
                    for(ServerInterface s: netToSym.keySet()){

                        Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        cipherReport.init(Cipher.ENCRYPT_MODE, netToSym.get(s));

                        byte[] cipherBytes3 = cipherReport.doFinal(epi.getBytes());
                        String loc3 = Base64.getEncoder().encodeToString(cipherBytes3);

                        byte[] cipherBytes4 = cipherReport.doFinal(epf.getBytes());
                        String loc4 = Base64.getEncoder().encodeToString(cipherBytes4);

                        int nonceServer = 1;
                        int k = s.getId();
                        if(!sendNonce.containsKey("server"+(k))){
                            sendNonce.put("server", nonceServer+(k));
                        }else {
                            nonceServer = sendNonce.get("server"+(k));
                            nonceServer += 1;
                            sendNonce.replace("server"+(k), nonceServer);
                        }

                        String s1 = "";
                        String digest64 = "";
                        int hashInt = 0;

                        do{
                            hashInt++;
                            s1 = tempC.getUsername() + rid[0] + hashInt;
                            //Hash message
                            byte[] messageByte0 = s1.getBytes();
                            MessageDigest digest0 = MessageDigest.getInstance("SHA-256");
                            digest0.update(messageByte0);
                            byte[] digestByte0 = digest0.digest();
                            digest64 = Base64.getEncoder().encodeToString(digestByte0);
                        }
                        while(!digest64.startsWith("0"));
                        //TODO: mudar para min 4 zeros
                        PrivateKey priv = loadPrivKey(tempC.getUsername());

                        //sign the hash with the client's private key
                        Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipherHash.init(Cipher.ENCRYPT_MODE, priv);
                        byte[] hashBytes = Base64.getDecoder().decode(digest64);
                        byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
                        String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

                        ServerReturn r = s.requestMyProofs(tempC,tempC.getUsername(),loc3,loc4,rid[0], signedHash, hashInt);

                        if(r.getReports() == null || r.getServerProof() == null){
                            tempF.appendInformation("\n");
                            tempF.appendInformation(" [REQUEST TO SERVER]  MY WITNESSED REPORTS");
                            tempF.appendInformation(" [REQUEST TO SERVER]  DENIED");
                            return;
                        }

                        Cipher rsaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                        rsaCipher.init(Cipher.DECRYPT_MODE, netToSym.get(s));

                        String serverSignature = r.getServerProof();
                        int nonceServerSign = Integer.parseInt((serverSignature.split(" ")[1]));
                        String signServerHash = serverSignature.split(" ")[4];
                        String timeServerSign = serverSignature.split(" ")[7];
                        String stringTohash = tempC.getUsername() + nonceServerSign + timeServerSign + epi + epf;
                        String verifySignRet = verifyServerSign(signServerHash, stringTohash, k);
                        System.out.println("================================= "+stringTohash);
                        if(verifySignRet.equals("Correct") && rid[0] == r.getRid()){
                            if(verifiySignatureW(r.getReports(),s,1)==1) {
                                readList.put(s, r);
                            }
                            if (!receiveNonce.containsKey("server" +(k))) {
                                receiveNonce.put("server"+(k), nonceServerSign);
                            }else if (receiveNonce.get("server"+(k)) < nonceServerSign) {
                                receiveNonce.replace("server"+(k), nonceServerSign);
                            } else {
                                tempF.appendInformation("\t\t\tPossilble replay attack");
                                return;
                            }
                        }else {
                            System.out.println("SERVER SIGN HASH DOESN'T MATCH THE DATA (GET REPORTS)");
                        }

                    }

                    // verify cardinality
                    if(readList.size() > (servers + F) / 2){
                        //verify highest value
                        ServerInterface maxKey = null;
                        String timestamp = "";
                        String temp = "";
                        for(ServerInterface key: readList.keySet()){
                            temp = highestVal(readList.get(key).getReports());
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
                        reports = readList.get(maxKey).getReports();
                    }

                    tempF.appendInformation("\n");
                    tempF.appendInformation(" [REQUEST TO SERVER]  MY WITNESSED REPORTS");
                    readList.clear();
                    Cipher rsaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    System.out.println( netToSym.get(sr));
                    rsaCipher.init(Cipher.DECRYPT_MODE, netToSym.get(sr));
                    Iterator i = reports.iterator();
                    int j = 0;

                    while (i.hasNext()) {

                        Report re = (Report) i.next();

                        byte[] hashBytes1 = java.util.Base64.getDecoder().decode(re.getEncryptedInfo());
                        byte[] chunk = rsaCipher.doFinal(hashBytes1);
                        String info = new String(chunk,UTF_8);
                        System.out.println("====================================== "+info);
                        info = info.split("=")[0];

                        re.setPosX(Integer.parseInt(info.split("w")[0].split("q")[1]));
                        re.setPosY(Integer.parseInt(info.split("w")[1].split("q")[1]));
                        re.setEpoch(Integer.parseInt(info.split("w")[2].split("q")[1].split("p")[0]));

                        j++;
                        tempF.appendInformation("\t\t ====== REPORT #"+j);
                        tempF.appendInformation("\t\t\tRECEIVED THE SERVER PROOF OF LOCATION FROM - "+ re.getUsername());
                        tempF.appendInformation("\t\t\tUSER SIGNATURE: " + re.getUserSignature() + "NONCE: " + re.getNonce() + "TIMESTAMP: " + re.getTimeStamp());
                        tempF.appendInformation("\t\t\tPOS: (" + re.getPosX() + "," + re.getPosY() + ") AT EPOCH " + re.getEpoch());
                        tempF.appendInformation("\t\t\tWITNESS: " + re.getWitness());
                        tempF.appendInformation("\t\t\tWITNESS SIGNATURE: " + re.getWitnessSignature());
                        tempF.appendInformation("\t\t\tWITNESS NONCE: " + re.getWitnessNonce() + "WITNESS TIMESTAMP: " + re.getWitnessTimeStamp());

                    }

                }  catch (IOException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        };
        worker.start();



    }

    /*========================================== CONNECTION TIMEOUTS =================================================*/

    private String retry(ClientInterface it, String username,Report message) throws InterruptedException, IOException, NotBoundException {
        String serverSignature;
        ServerInterface s;
        Thread thread = new Thread(this);
        thread.start();
        thread.join();
        int serverNumber = (this.servers % serverCount) + 1;
        serverCount++;
        s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER"+(serverNumber));
        System.out.println("retry???");
        serverSignature = s.submitLocationReport(this.getClientInterface(),this.getUsername(),message,this.writerTimeStamp.get(),"");
        return serverSignature;
    }

    private void retrySub(ClientInterface it, String username, int i) throws InterruptedException, IOException, NotBoundException {
        ServerInterface s;
        Thread thread = new Thread(this);
        thread.start();
        thread.join();
        s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER"+(i));
        s.subscribe(this.getClientInterface(),this.getUsername(), this.getKey(i-1));
    }

    @Override
    public void run(){
        ServerInterface s = null;
        int tries = 0;
        while(s == null && tries < 5){
            System.out.println("New try.");
            try {
                Thread.sleep(2000);
                s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER"+(this.servers));
            } catch (InterruptedException e) {
                /*exit*/
            } catch (RemoteException | MalformedURLException | NotBoundException e){
                /*Try new connection in 2 seconds*/
                System.out.println("Retrying connection to server.");
            }
            tries++;
        }
    }

    /*================================================ 1,N BYZANTINE =================================================*/

    private void bonrrInit(){
        this.ackList = new HashMap<>();
        this.readList = new HashMap<>();
        this.anwsers = new HashMap<>();
        this.writerTimeStamp = new AtomicInteger(0);
        this.requestId = new AtomicInteger(0);
        this.timeStamp = new AtomicInteger(0);
        this.signature = null;
        this.val = null;
        this.readingState = false;
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

    public int verifiySignatureW(ArrayList<Report> reportList, ServerInterface sr, int flag){
        for(int j = 0; j < reportList.size(); j++){
            try {

                Cipher rsaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                rsaCipher.init(Cipher.DECRYPT_MODE, this.networkTosymKey.get(sr));

                Report re = (Report) reportList.get(j);

                byte[] hashBytes1 = java.util.Base64.getDecoder().decode(re.getEncryptedInfo());
                byte[] chunk = rsaCipher.doFinal(hashBytes1);
                String info = new String(chunk, UTF_8);

                System.out.println("============= "+info);
                info = info.split("=")[0];

                re.setPosX(Integer.parseInt(info.split("w")[0].split("q")[1]));
                re.setPosY(Integer.parseInt(info.split("w")[1].split("q")[1]));
                re.setEpoch(Integer.parseInt(info.split("w")[2].split("q")[1].split("p")[0]));

                byte[] hashBytes3 = java.util.Base64.getDecoder().decode(re.getWitness());
                byte[] chunk2 = rsaCipher.doFinal(hashBytes3);
                String witness =  new String(chunk2, UTF_8);

                re.setWitness(witness);

                if(flag == 1){
                    System.out.println("================================= "+re.getUsername());
                    byte[] hashBytes4 = java.util.Base64.getDecoder().decode(re.getUsername());
                    byte[] chunk3 = rsaCipher.doFinal(hashBytes4);
                    String username =  new String(chunk3, UTF_8);

                    re.setUsername(username);
                }


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
                System.out.println("server sign " + serverSignature + " checkh "+ checkHash);
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

    /*================================================== MAIN ========================================================*/

    public static void main(String[] args) {

        try {
            /* Barney, do something.*/
        } catch (Exception e) {
            System.out.println("Exception in main: " + e);
            e.printStackTrace();
        }
    }
}
