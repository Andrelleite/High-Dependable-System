import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.plaf.synth.SynthOptionPaneUI;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Array;
import java.net.MalformedURLException;
import java.rmi.*;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.util.*;

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
    private ClientInterface clientInterface;
    private int coordinate1;
    private int coordinate2;
    private int epoch;
    private int hasError = 0;
    private Map<Integer, Pair<Integer,Integer>> moveList = new HashMap<Integer, Pair<Integer,Integer>>();
    private List<String> clientsWithError = new ArrayList<String>();


    public ClientInterface getClientInterface() {
        return clientInterface;
    }

    public void setClientInterface(ClientInterface clientInterface) {
        this.clientInterface = clientInterface;
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
            requestLocationProof();
            getReports();
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

    public void setUsername(String username) {
        this.username = username;
        // REPORT SUBMISSION
        try{
            ServerInterface s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
            s.subscribe(this.getClientInterface(),this.getUsername());
        }catch (RemoteException | MalformedURLException | NotBoundException e){
            try {
                retrySub(this.getClientInterface(),this.getUsername());
            } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                return;
            }
        }
    }

    public Client() throws RemoteException {
        super();
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
            //coordenadas falsas
            File myObj = new File("src/grid/grid1.txt");
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

    }

    public Report generateLocationReportWitness(ClientInterface c, String username, int userEpoch) throws RemoteException{
        try {
            File myObj = new File("src/grid/grid1.txt");
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
                        double x2 = Double.parseDouble(coord1);
                        double y2 = Double.parseDouble(coord2);
                        int x1 = moveList.get(userEpoch).getFirst();
                        int y1 = moveList.get(userEpoch).getSecond();
                        double distaceCalc = Math.sqrt((Math.pow((x1-x2),2) + Math.pow((y1-y2),2)));
                        int distance = (int) distaceCalc;

                        if(distance <= 15 && usernameFile.equals(username)){ //aqui o "0" depois é substituido pelo epoch atual

                            //Get time
                            String time = java.time.LocalTime.now().toString();

                            String s = username + time + this.getUsername() + this.getEpoch();

                            //get client private key
                            FileInputStream fis0 = new FileInputStream("src/keys/" + this.getUsername() + "Priv.key");
                            byte[] encoded1 = new byte[fis0.available()];
                            fis0.read(encoded1);
                            fis0.close();
                            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded1);
                            KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
                            PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

                            //Hash message
                            byte[] messageByte0 = s.getBytes();
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


                            Report userReport = new Report(c,-1,-1,this.epoch,username,"","",this.getUsername(),signedHash,time);
                            return userReport;
                        }
                    }
                } catch (NumberFormatException ex) { // handle your exception
                    System.out.println("Malformed input found!");
                    this.setError(1);
                } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException e) {
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
            File myObj = new File("src/grid/grid1.txt");
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

                        if (usersNearby.size() == 5){
                            return usersNearby;
                        }
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
            FileInputStream fis1 = new FileInputStream("src/keys/" + message.getWitness() + "Pub.key");
            byte[] decoded1 = new byte[fis1.available()];
            fis1.read(decoded1);
            fis1.close();
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decoded1);
            KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
            PublicKey pub = keyFacPub.generatePublic(publicKeySpec);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pub);
            byte[] hashBytes1 = java.util.Base64.getDecoder().decode(message.getWitnessSignature());
            byte[] chunk = rsaCipher.doFinal(hashBytes1);
            String witSiganture = Base64.getEncoder().encodeToString(chunk);

            String verifyHash = message.getUsername() + message.getWitnessTimeStamp() + message.getWitness() + message.getEpoch();
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
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
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
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return "Error";
    }

    public void requestLocationProof() throws InterruptedException, IOException, ClassNotFoundException {

        ArrayList<String> usersToContact = findUser();
        Report message = null;

        if(usersToContact.size() != 0){
            Iterator i = usersToContact.iterator();
            while (i.hasNext()) {
                String userToContact = (String) i.next();
                System.out.println(this.username + " trying to contact " + userToContact);
                try {
                    ClientInterface h = (ClientInterface) Naming.lookup("rmi://127.0.0.1:7001/" + userToContact);
                    message = h.generateLocationReportWitness(this.getClientInterface(),this.getUsername(), this.epoch);
                    if(message == null){
                        return;
                    }

                    if(message.getC() != this.getClientInterface() && !message.getUsername().equals(this.getUsername()) && message.getEpoch() != this.epoch && !message.getWitness().equals(userToContact)){
                        return;
                    }

                    String verifyRet = verifyWitnessSignature(message, h);
                    if(verifyRet.equals(("Error"))){
                        return;
                    }

                    //message.setPosX(this.getCoordinate1());
                    //message.setPosY(this.getCoordinate2());

                    //Get time
                    LocalTime clientTime = LocalTime.now();
                    String time = clientTime.toString();

                    try{
                        LocalTime witTime = LocalTime.parse(message.getWitnessTimeStamp());
                        //4 segundos para possíveis atrasos na rede
                        LocalTime clientTimeThreshold = clientTime.plusSeconds(4);
                        if(clientTimeThreshold.compareTo(witTime) < 0){
                            System.out.println("Possilble replay attack");
                            return;
                        }
                    }
                    catch (DateTimeParseException e) {
                        System.out.println("Malformed report");
                        e.printStackTrace();
                    }

                    String s1 = this.getUsername() + time  + this.getEpoch() + this.getCoordinate1() + this.getCoordinate2();

                    //get client private key
                    FileInputStream fis0 = new FileInputStream("src/keys/" + this.getUsername() + "Priv.key");
                    byte[] encoded1 = new byte[fis0.available()];
                    fis0.read(encoded1);
                    fis0.close();
                    PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded1);
                    KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
                    PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

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

                    //encrypt the report's sensitive information

                    //get server public key
                    FileInputStream fis01 = new FileInputStream("src/keys/serverPub.key");
                    byte[] encoded2 = new byte[fis01.available()];
                    fis01.read(encoded2);
                    fis01.close();
                    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded2);
                    KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
                    PublicKey pub = keyFacPub.generatePublic(publicKeySpec);

                    Cipher cipherReport = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipherReport.init(Cipher.ENCRYPT_MODE, pub);

                    String info = "posXq" + this.getCoordinate1() + "wposYq" + this.getCoordinate2() + "wepochq" + message.getEpoch();
                    message.setEpoch(-1);

                    byte[] infoBytes = Base64.getDecoder().decode(info);
                    byte[] cipherBytes1 = cipherReport.doFinal(infoBytes);
                    String loc = Base64.getEncoder().encodeToString(cipherBytes1);

                    message.setEncryptedInfo(loc);

                    //byte[] witnessBytes = Base64.getDecoder().decode(message.getWitness());
                    byte[] cipherBytes3 = cipherReport.doFinal(message.getWitness().getBytes());
                    String loc3 = Base64.getEncoder().encodeToString(cipherBytes3);


                    message.setWitness(loc3);

                    message.setTimeStamp(time);
                    message.setUserSignature(signedHash);

                    // REPORT SUBMISSION
                    try{
                        ServerInterface s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
                        String serverSignature = s.submitLocationReport(this.getClientInterface(),this.getUsername(),message);
                        System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                    }catch (RemoteException | MalformedURLException | NotBoundException e){
                        try {
                            String serverSignature = retry(this.getClientInterface(),this.getUsername(),message);
                            System.out.println("->>>>>> SERVER SIGNATURE:" + serverSignature);
                        } catch (InterruptedException | IOException | NotBoundException interruptedException) {
                            System.out.println("SERVICE IS DOWN. COME BACK LATER.");
                            return;
                        }
                    }

                } catch (Exception e) {
                    System.out.println("user + " + userToContact + " nao foi encontrado");
                    System.out.println("Exception in main: " + e);
                    e.printStackTrace();
                }
            }
        }
        else{
            System.out.println(this.getUsername() + " não tem users perto.");
        }

    }

    public void getReports() throws RemoteException{

        try {
            ServerInterface s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");

            String epoch = ""+this.epoch;

            //get server public key
            FileInputStream fis01 = new FileInputStream("src/keys/serverPub.key");
            byte[] encoded2 = new byte[fis01.available()];
            fis01.read(encoded2);
            fis01.close();
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded2);
            KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
            PublicKey pub = keyFacPub.generatePublic(publicKeySpec);

            Cipher cipherReport = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipherReport.init(Cipher.ENCRYPT_MODE, pub);

            byte[] cipherBytes3 = cipherReport.doFinal(epoch.getBytes());
            String loc3 = Base64.getEncoder().encodeToString(cipherBytes3);

            ServerReturn r = s.obtainLocationReport(this.getClientInterface(),loc3,this.getUsername());

            FileInputStream fis0 = new FileInputStream("src/keys/"+this.getUsername()+"Priv.key");
            byte[] encoded1 = new byte[fis0.available()];
            fis0.read(encoded1);
            fis0.close();
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded1);
            KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
            PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, priv);

            Iterator i = r.getReports().iterator();
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

                System.out.println("===============================================================================================");
                System.out.println("RECEIVED THE SERVER PROOF OF LOCATION FROM - "+ re.getUsername());
                System.out.println("USER SIGNATURE: " + re.getUserSignature());
                System.out.println("TIMESTAMP: " + re.getTimeStamp());
                System.out.println("POS: (" + re.getPosX() + "," + re.getPosY() + ") AT EPOCH " + re.getEpoch());
                System.out.println("WITNESS: " + re.getWitness());
                System.out.println("WITNESS SIGNATURE: " + re.getWitnessSignature());
                System.out.println("WITNESS TIMESTAMP: " + re.getWitnessTimeStamp());
                System.out.println("===============================================================================================");

            }

        } catch (NotBoundException e) {
            e.printStackTrace();
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
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
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
        s.subscribe(this.getClientInterface(),this.getUsername());
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
