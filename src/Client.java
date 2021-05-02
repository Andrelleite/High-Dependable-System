import com.sun.security.jgss.GSSUtil;

import javax.crypto.*;
import javax.swing.plaf.synth.SynthOptionPaneUI;
import java.io.*;
import java.lang.reflect.Array;
import java.net.MalformedURLException;
import java.rmi.*;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

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
    private SecretKey symKey;
    private String key;
    private int epoch;
    private int hasError = 0;
    private Map<Integer, Pair<Integer,Integer>> moveList = new HashMap<Integer, Pair<Integer,Integer>>();
    public ConcurrentHashMap<String,Integer> sendNonce= new ConcurrentHashMap<String, Integer>();
    public  ConcurrentHashMap<String,Integer> receiveNonce= new ConcurrentHashMap<String, Integer>();
    private List<String> clientsWithError = new ArrayList<String>();
    private OutputManager fileMan;
    private int gridNumber;

    public Map<Integer, Pair<Integer, Integer>> getMoveList() {
        return moveList;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public ClientInterface getClientInterface() {
        return clientInterface;
    }

    public void setClientInterface(ClientInterface clientInterface) {
        this.clientInterface = clientInterface;
    }

    public SecretKey getSymKey() {
        return symKey;
    }

    public OutputManager getFileMan(){ return this.fileMan; }

    public void setSymKey(SecretKey symKey) {
        this.symKey = symKey;
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

    public void setPassword(String password){
        this.password = password;
    }

    public String getPassword(){
        return password;
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
        try{
            ServerInterface s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");

            SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            System.out.println("lado do client: " + encodedKey);
            this.setSymKey(secretKey);

            PublicKey pub = loadPublicKey("server");

            Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipherRSA.init(Cipher.ENCRYPT_MODE, pub);
            byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
            byte[] cipherBytes = cipherRSA.doFinal(keyBytes);
            String encryptedKey = Base64.getEncoder().encodeToString(cipherBytes);

            this.setKey(encryptedKey);

            s.subscribe(this.getClientInterface(),this.getUsername(), encryptedKey);

        } catch (ConnectException ev){
            try {
                retrySub(this.getClientInterface(),this.getUsername());
            } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                return;
            }
        } catch (RemoteException | MalformedURLException | NotBoundException e){
            try {
                retrySub(this.getClientInterface(),this.getUsername());
            } catch (ConnectException ev){
                try {
                    retrySub(this.getClientInterface(),this.getUsername());
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

    public void setUsername(String username,String origin){
        this.username = username;
    }

    public Client(int grid) throws RemoteException {
        super();
        this.gridNumber = grid;
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

    public Report generateLocationReportWitness(ClientInterface c, String username, int userEpoch, String signature, int nonce) throws RemoteException{
        try {
            this.fileMan.appendInformation("\n");
            this.fileMan.appendInformation(" [REQUEST TO BE WITNESS]  PROOF OF LOCATION FROM " + username);
            String verifyRet = verifySenderSignature(username, signature,String.valueOf(userEpoch),nonce);
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

                        if(distance <= 15 && usernameFile.equals(username)){ //aqui o "0" depois é substituido pelo epoch atual

                            int nonceSend = 1;
                            if(!sendNonce.containsKey(usernameFile)){
                                sendNonce.put(usernameFile, nonceSend);
                            }else {
                                nonceSend = sendNonce.get(usernameFile);
                                nonceSend += 1;
                                sendNonce.replace(usernameFile, nonceSend);
                            }

                            String s = username + nonceSend + this.getUsername() + userEpoch;// this.getCoordinate1() + this.getCoordinate2();
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

                            Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                            cipherReport.init(Cipher.ENCRYPT_MODE, this.getSymKey());

                            String info = "posXq" + this.getCoordinate1() + "wposYq" + this.getCoordinate2();

                            //byte[] infoBytes = Base64.getDecoder().decode(info);
                            byte[] cipherBytes1 = cipherReport.doFinal(info.getBytes());
                            String loc = Base64.getEncoder().encodeToString(cipherBytes1);

                            this.fileMan.appendInformation("\t\tSENDER SIGNATURE: NONCE: " + nonce + " | SIGNATURE: " + signature);

                            Report userReport = new Report(c,-1,-1,userEpoch,username,"",-1,this.getUsername(),signedHash,nonceSend,loc);
                            return userReport;
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

            String verifyHash = message.getUsername() + message.getWitnessNonce() + message.getWitness() + message.getEpoch(); // message.getPosXWitness() + message.getPosYWitness();


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

    public String verifySenderSignature(String user, String digitalSignature, String epoch, int nonce) {
        try {

            PublicKey pub = loadPublicKey(user);

            //String s01 =  nonce + user + epoch;

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pub);
            byte[] hashBytes1 = java.util.Base64.getDecoder().decode(digitalSignature);
            byte[] chunk = rsaCipher.doFinal(hashBytes1);
            String signature = Base64.getEncoder().encodeToString(chunk);

            String verifyHash =  nonce + user + epoch;
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

                    String s01 =  nonceSend + this.getUsername() + this.getEpoch(); //+ this.getCoordinate1() + this.getCoordinate2();
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


                    message = h.generateLocationReportWitness(this.getClientInterface(),this.getUsername(), this.getEpoch(),digitalSignature, nonceSend);

                    if(message == null){

                        this.fileMan.appendInformation("\t\t\treport is null");
                        return;
                    }

                    if(message.getC() != this.getClientInterface() && !message.getUsername().equals(this.getUsername()) && message.getEpoch() != this.epoch && !message.getWitness().equals(userToContact)){
                        this.fileMan.appendInformation("\t\t\treport don't pass");
                        return;
                    }

                    String verifyRet = verifyWitnessSignature(message, h);
                    if(verifyRet.equals(("Error"))){
                        this.fileMan.appendInformation("\t\t\treport witness signature is wrong");
                        return;
                    }

                    int witnessNonce = message.getWitnessNonce();
                    try {

                        if (!receiveNonce.containsKey(userToContact)) {
                            receiveNonce.put(userToContact, witnessNonce);
                        }else if (receiveNonce.get(userToContact) < witnessNonce) {
                            receiveNonce.replace(userToContact, witnessNonce);
                        } else {
                            this.fileMan.appendInformation("\t\t\tPossilble replay attack");
                            return;
                        }
                    }
                    catch (Exception e) {
                        System.out.println("Malformed report");
                        e.printStackTrace();
                    }


                    //TODO: mudar quando for mais que 1 server
                    int nonceServer = 1;
                    if(!sendNonce.containsKey("server")){
                        sendNonce.put("server", nonceServer);
                    }else {
                        nonceServer = sendNonce.get("server");
                        nonceServer += 1;
                        sendNonce.replace("server", nonceServer);
                    }

                    String s1 = this.getUsername() + nonceServer  + this.getEpoch() + this.getCoordinate1() + this.getCoordinate2();
                    PrivateKey priv = loadPrivKey(this.getUsername());

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

                    Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipherReport.init(Cipher.ENCRYPT_MODE, this.getSymKey());

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
                    message.setUserSignature(signedHash);

                    // REPORT SUBMISSION
                    try{
                        ServerInterface s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
                        serverSignature = s.submitLocationReport(this.getClientInterface(),this.getUsername(),message);
                        this.fileMan.appendInformation("\t\tSERVER SIGNATURE:" + serverSignature);
                        System.out.println("SERVER SIGNATURE:" + serverSignature);
                    } catch (ConnectException ev){
                        try {
                            serverSignature = retry(this.getClientInterface(),this.getUsername(),message);
                            System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                        } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                            System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                            return;
                        }
                    } catch (RemoteException | MalformedURLException | NotBoundException e){
                        try {
                            serverSignature = retry(this.getClientInterface(),this.getUsername(),message);
                            System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                        } catch (ConnectException ev){
                            serverSignature = retry(this.getClientInterface(),this.getUsername(),message);
                            System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                        } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                            System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                            return;
                        }
                    }

                    if(serverSignature.equals("")){
                        this.fileMan.appendInformation("\t\tSOMETHING WRONG HAPPENED, NO RETURN FROM THE SERVER");
                    }else if(serverSignature.equals("null")){
                        this.fileMan.appendInformation("\t\tSOMETHING WRONG HAPPENED, RETURN NOT SIGNED");
                    }else {

                        int nonceServerSign = Integer.parseInt((serverSignature.split(" ")[1]));

                        String signServerHash = serverSignature.split(" ")[4];

                        String stringTohash = this.username + nonceServerSign + this.getEpoch();

                        String verifySignRet = verifyServerSign(signServerHash, stringTohash);

                        if(verifySignRet.equals("Correct")){
                            //TODO: mudar quando houver mais que 1 server

                            if (!receiveNonce.containsKey("server")) {
                                receiveNonce.put("server", nonceServerSign);
                            }else if (receiveNonce.get("server") < nonceServerSign) {
                                receiveNonce.replace("server", nonceServerSign);
                            } else {
                                this.fileMan.appendInformation("\t\t\tPossilble replay attack");
                                return;
                            }
                        }else {
                            System.out.println("SERVER SIGN HASH DOESN'T MATCH THE DATA (REQUEST LOCATION PROOF)");
                        }
                    }

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

    private String verifyServerSign(String serverHash, String userToHash) {

        try {
            PublicKey pub = loadPublicKey("server");

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

    public void getReports(String ep) throws RemoteException{

        try {
            ServerInterface s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");

            //get server public key
            /*FileInputStream fis01 = new FileInputStream("src/keys/serverPub.key");
            byte[] encoded2 = new byte[fis01.available()];
            fis01.read(encoded2);
            fis01.close();
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded2);
            KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
            PublicKey pub = keyFacPub.generatePublic(publicKeySpec);

            Cipher cipherReport = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipherReport.init(Cipher.ENCRYPT_MODE, pub);*/

            Cipher cipherReport = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipherReport.init(Cipher.ENCRYPT_MODE, this.getSymKey());

            byte[] cipherBytes3 = cipherReport.doFinal(ep.getBytes());
            String loc3 = Base64.getEncoder().encodeToString(cipherBytes3);


            //TODO: mudar quando for mais que 1 server
            int nonceServer = 1;
            if(!sendNonce.containsKey("server")){
                sendNonce.put("server", nonceServer);
            }else {
                nonceServer = sendNonce.get("server");
                nonceServer += 1;
                sendNonce.replace("server", nonceServer);
            }

            ServerReturn r = s.obtainLocationReport(this.getClientInterface(),loc3,this.getUsername());

            if(r.getReports() == null || r.getServerProof() == null){
                this.fileMan.appendInformation("\n");
                this.fileMan.appendInformation(" [REQUEST TO SERVER]  MY REPORTS");
                this.fileMan.appendInformation(" [REQUEST TO SERVER]  DENIED");
                return;
            }

            Cipher rsaCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, this.getSymKey());

            String serverSignature = r.getServerProof();

            int nonceServerSign = Integer.parseInt((serverSignature.split(" ")[1]));

            String signServerHash = serverSignature.split(" ")[4];

            String stringTohash = this.username + nonceServerSign + this.getEpoch();

            String verifySignRet = verifyServerSign(signServerHash, stringTohash);

            if(verifySignRet.equals("Correct")){
                //System.out.println("CORRECT SERVER SIGNATURE");
                //TODO: mudar quando houver mais que 1 server

                if (!receiveNonce.containsKey("server")) {
                    receiveNonce.put("server", nonceServerSign);
                }else if (receiveNonce.get("server") < nonceServerSign) {
                    receiveNonce.replace("server", nonceServerSign);
                } else {
                    this.fileMan.appendInformation("\t\t\tPossilble replay attack");
                    return;
                }
            }else {
                System.out.println("SERVER SIGN HASH DOESN'T MATCH THE DATA (GET REPORTS)");
            }
            this.fileMan.appendInformation("\n");
            this.fileMan.appendInformation(" [REQUEST TO SERVER]  MY REPORTS");
            int j = 0;
            Iterator i = r.getReports().iterator();
            while (i.hasNext()) {

                Report re = (Report) i.next();

                byte[] hashBytes1 = java.util.Base64.getDecoder().decode(re.getEncryptedInfo());
                byte[] chunk = rsaCipher.doFinal(hashBytes1);
                String info = Base64.getEncoder().encodeToString(chunk);
                info = info.split("=")[0];

                re.setPosX(Integer.parseInt(info.split("w")[0].split("q")[1]));
                re.setPosY(Integer.parseInt(info.split("w")[1].split("q")[1]));
                //re.setEpoch(Integer.parseInt(info.split("w")[2].split("q")[1]));

                re.setEpoch(Integer.parseInt(ep));

                byte[] hashBytes3 = java.util.Base64.getDecoder().decode(re.getWitness());
                byte[] chunk2 = rsaCipher.doFinal(hashBytes3);
                String witness =  new String(chunk2, UTF_8);

                re.setWitness(witness);

                j++;
                this.fileMan.appendInformation("\t\t ====== REPORT #"+j);
                this.fileMan.appendInformation("\t\t\tRECEIVED THE SERVER PROOF OF LOCATION FROM - "+ re.getUsername());
                this.fileMan.appendInformation("\t\t\tUSER SIGNATURE: " + re.getUserSignature() + "NONCE: " + re.getNonce());
                this.fileMan.appendInformation("\t\t\tPOS: (" + re.getPosX() + "," + re.getPosY() + ") AT EPOCH " + re.getEpoch());
                this.fileMan.appendInformation("\t\t\tWITNESS: " + re.getWitness());
                this.fileMan.appendInformation("\t\t\tWITNESS SIGNATURE: " + re.getWitnessSignature());
                this.fileMan.appendInformation("\t\t\tWITNESS NONCE: " + re.getWitnessNonce());

            }

        } catch (NotBoundException e) {
            System.out.println();
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
        } /*catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } */catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

    }

    /*========================================== CONNECTION TIMEOUTS =================================================*/

    private String retry(ClientInterface it, String username,Report message) throws InterruptedException, IOException, NotBoundException {
        String serverSignature;
        ServerInterface s;
        Thread thread = new Thread(this);
        thread.start();
        thread.join();
        s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
        serverSignature = s.submitLocationReport(this.getClientInterface(),this.getUsername(),message);
        return serverSignature;
    }

    private void retrySub(ClientInterface it, String username) throws InterruptedException, IOException, NotBoundException {
        ServerInterface s;
        Thread thread = new Thread(this);
        thread.start();
        thread.join();
        s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
        s.subscribe(this.getClientInterface(),this.getUsername(), this.getKey());
    }

    @Override
    public void run(){
        ServerInterface s = null;
        int tries = 0;
        while(s == null && tries < 5){
            System.out.println("New try.");
            try {
                Thread.sleep(2000);
                s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
            } catch (InterruptedException e) {
                /*exit*/
            } catch (RemoteException | MalformedURLException | NotBoundException e){
                /*Try new connection in 2 seconds*/
                System.out.println("Retrying connection to server.");
            }
            tries++;
        }
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
