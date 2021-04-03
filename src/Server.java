import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.MalformedURLException;
import java.rmi.*;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

public class Server extends UnicastRemoteObject implements ServerInterface, Serializable{

    private static final long serialVersionUID = 1L;
    public static int GRIDDIMENISION = 40;
    private HashMap<String,ClientInterface> allSystemUsers;
    private ArrayList<Report> reps;
    private ServerInterface server;
    private boolean imPrimary;
    private String IPV4;
    private int portRMI;

    //=======================CONNECTION=================================================================================

    public Server() throws IOException, NotBoundException, ClassNotFoundException {
        this.IPV4 = "127.0.0.1";
        this.portRMI = 7000;
        synchronize(); // Updates the reports in list to the latest in file
        evaluateData(0); // Evaluate reliability of users with reports delivered
        this.server = retryConnection(7000);
        if (!imPrimary) {
            checkPrimaryServer(this.server);
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
                Naming.rebind("rmi://"+this.IPV4+":" + this.portRMI + "/SERVER", server);
                imPrimary = true;
                state = true;
            } catch (MalformedURLException | RemoteException ex) {
                /*wait silently*/
            }
        }
        System.out.println("I'm in.");
    }

    private ServerInterface retryConnection(int port) throws NotBoundException, IOException {

        ServerInterface serverInt = null;
        Server server = this;
        System.out.println("SERVER IS ONLINE AT "+this.IPV4);

        try {
            LocateRegistry.createRegistry(port);
            Naming.rebind("rmi://"+this.IPV4+":" + port + "/SERVER", server);
            imPrimary = true;
            System.out.println("I'm the primary");
        } catch (ExportException ex) {
            imPrimary = false;
            System.out.println("I'm the backup");
            serverInt = (ServerInterface) Naming.lookup("rmi://"+this.IPV4+":" + port + "/SERVER");
            System.out.println("Connetion to primary succeded...");
        }

        System.out.println("Server ready...");
        return serverInt;
    }

    //=======================SERVER-SYS=================================================================================

    public void subscribe(ClientInterface c, String user) throws RemoteException{
        this.allSystemUsers.put(user,c);
        try {
            updateUsers();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String echo(String message) throws RemoteException {
        System.out.println("received " + message);
        return message;
    }

    //=======================USER-METHODS===============================================================================

    public String submitLocationReport(ClientInterface c,String user, Report locationReport) throws RemoteException{
        String verifyRet = verifyLocationReport(c, user, locationReport);
        if(verifyRet.equals("Correct")){
            System.out.println("===============================================================================================");
            System.out.println("RECEIVED A NEW PROOF OF LOCATION FROM - "+user);
            System.out.println("USER SIGNATURE: " + locationReport.getUserSignature());
            System.out.println("TIMESTAMP: " + locationReport.getTimeStamp());
            System.out.println("POS: (" + locationReport.getPosX() + "," + locationReport.getPosY() + ") AT EPOCH " + locationReport.getEpoch());
            System.out.println("WITNESS: " + locationReport.getWitness());
            System.out.println("WITNESS SIGNATURE: " + locationReport.getWitnessSignature() );
            System.out.println("WITNESS TIMESTAMP: " + locationReport.getWitnessTimeStamp());
            System.out.println("===============================================================================================");

            this.reps.add(locationReport);
            try {

                updateReports();

                //Get time
                String time = java.time.LocalTime.now().toString();

                String s1 = user + time + locationReport.getEpoch();

                //get client private key
                FileInputStream fis0 = new FileInputStream("src/keys/serverPriv.key");
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

                String finalS = "time: " + time + " | signature: " + signedHash;

                return finalS;

            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException e) {
                e.printStackTrace();
                System.out.println("Things went sideways :(");
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }

        return "null";
    }

    public ArrayList<Report> obtainLocationReport(ClientInterface c, int epoch) throws IOException, ClassNotFoundException {
        return fetchReports(c,epoch);

    }


    //=======================AUTHORITY-METHODS==========================================================================

    public ArrayList<Report> obtainLocationReport(String user, int epoch){

        System.out.println("_______________________________________________________________________");
        System.out.println("LOCATION REPORTS REGARDING "+user+" REQUEST BY HA");
        System.out.println("BIG BROTHER IS REQUESTING");
        ArrayList<Report> clientReports = (ArrayList<Report>) this.reps.clone();
        for(int i = 0; i < clientReports.size();i++){
            if(!clientReports.get(i).getUsername().toUpperCase().equals(user.toUpperCase())){
                clientReports.remove(i);
                i--;
            }else if(clientReports.get(i).getEpoch() != epoch){
                clientReports.remove(i);
                i--;
            }
        }
        System.out.println("REQUEST SIZE "+clientReports.size());
        System.out.println("REQUEST COMPLETE");
        return clientReports;

    }

    public ArrayList<Report> obtainUsersAtLocation(int[] pos, int epoch){

        System.out.println("_______________________________________________________________________");
        System.out.println("ALL LOCATION REPORTS FOR POSITION ("+pos[0]+","+pos[1]+") AT EPOCH "+epoch+" REQUEST BY HA");
        System.out.println("BIG BROTHER IS REQUESTING");
        ArrayList<Report> clientReports = (ArrayList<Report>) this.reps.clone();
        for(int i = 0; i < clientReports.size();i++){
            if(clientReports.get(i).getPosY() != pos[1]){
                if(clientReports.get(i).getPosX() != pos[0]) {
                    clientReports.remove(i);
                    i--;
                }
            }else if(clientReports.get(i).getPosX() != pos[0]){
                clientReports.remove(i);
                i--;
            }else if(clientReports.get(i).getEpoch() != epoch){
                clientReports.remove(i);
                i--;
            }
        }
        cleanRepetition(clientReports,0);
        System.out.println("REQUEST SIZE "+clientReports.size());
        System.out.println("REQUEST COMPLETE");
        return clientReports;
    }

    //=======================DATA-FILES-METHODS=========================================================================

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
        }

    }

    private void synchronize() throws IOException, ClassNotFoundException {

        File file = new File("ClientReports.txt");
        File fileu = new File("SystemUsers.txt");

        if (file.length() == 0){
            this.reps = new ArrayList<>();
            System.out.println("Array is empty. Next update will make it usable.");
        }
        else{
            ObjectInputStream ois = new ObjectInputStream(
                                    new FileInputStream(file));
            this.reps = (ArrayList<Report>) ois.readObject();
            System.out.println("LOAD SUCCESSFUL");
            System.out.println("SIZE OF LOAD "+this.reps.size());
            for (Report entry : this.reps) {
                System.out.println(entry.getUsername() +" ("+entry.getPosX()+","+entry.getPosY()+") "+entry.getEpoch());
            }
            ois.close();
        }

        if (fileu.length() == 0){
            this.allSystemUsers = new HashMap<>();
            System.out.println("Array is empty. Next update will make it usable.");
        }
        else{
            ObjectInputStream ois = new ObjectInputStream(
                                    new FileInputStream(fileu));
            this.allSystemUsers = (HashMap<String, ClientInterface>) ois.readObject();
            System.out.println("LOAD SUCCESSFUL");
            System.out.println("SIZE OF LOAD "+this.allSystemUsers.size());
            for (String key : this.allSystemUsers.keySet()) {
                System.out.println("Interface: "+key+" is "+this.allSystemUsers.get(key));
            }
            ois.close();
        }


    }

    private void updateReports() throws IOException {

        File file=new File("ClientReports.txt");
        ObjectOutputStream oos= new ObjectOutputStream(
                                new FileOutputStream(file));
        oos.writeObject(this.reps);
        System.out.println("FILE R UPDATED. NEW SIZE "+this.reps.size());
        oos.close();

    }

    private void updateUsers() throws IOException{

        File file=new File("SystemUsers.txt");
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

    private void evaluateData(int epoch){

        String wit;
        int minDist = 7;
        double dist = 0.0;
        double proofs,fails;
        HashMap<String,int[]> mapping = new HashMap<>();
        HashMap<String,Double> evaluation = new HashMap<>();

        System.out.println("\n=====================================================EVALUATING EPOCH "+epoch);
        for(Report rep : this.reps){
            mapping.put(rep.getUsername(),new int[]{rep.getPosX(),rep.getPosY()});
        }
        for(String key : mapping.keySet()){
            proofs = fails =  0;
            for(Report rep : this.reps){
                if(rep.getWitness().equals(key)){
                    dist = Math.sqrt(Math.pow((rep.getPosX()-mapping.get(key)[0]),2)+Math.pow((rep.getPosY()-mapping.get(key)[1]),2));
                    System.out.print(key+" -w> "+rep.getUsername()+" Factual Distance: "+dist);
                    if(dist >= minDist){
                        System.out.println(" *Byzantine Alert* ");
                        fails++;
                    }else{
                        System.out.println(" *OK* ");
                    }
                    proofs++;
                }
            }
            if(proofs != 0){
                evaluation.put(key, (double) (fails/proofs));
            }else{
                evaluation.put(key, 0.0);
            }
        }
        for(String key : evaluation.keySet()) {
            System.out.print("| "+key + " rate of misses: "+evaluation.get(key)+" ");
        }
        System.out.println("\n=====================================================EVALUATION DONE\n");
    }

    private String verifyLocationReport(ClientInterface c,String user, Report locationReport) {
        //witness signature
        try {
            FileInputStream fis1 = new FileInputStream("src/keys/" + locationReport.getWitness() + "Pub.key");
            byte[] decoded1 = new byte[fis1.available()];
            fis1.read(decoded1);
            fis1.close();
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decoded1);
            KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
            PublicKey pub = keyFacPub.generatePublic(publicKeySpec);

            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pub);
            byte[] hashBytes1 = java.util.Base64.getDecoder().decode(locationReport.getWitnessSignature());
            byte[] chunk = rsaCipher.doFinal(hashBytes1);
            String witSignature = Base64.getEncoder().encodeToString(chunk);

            String verifyHash = locationReport.getUsername() + locationReport.getWitnessTimeStamp() + locationReport.getWitness() + locationReport.getEpoch();
            byte[] messageByte1 = verifyHash.getBytes();
            MessageDigest digest1 = MessageDigest.getInstance("SHA-256");
            digest1.update(messageByte1);
            byte[] digestByte1 = digest1.digest();
            String digest64si = Base64.getEncoder().encodeToString(digestByte1);

            if(!witSignature.equals(digest64si)){
                return "Error";
            }

            //User Signature
            FileInputStream fis2 = new FileInputStream("src/keys/" + locationReport.getUsername() + "Pub.key");
            byte[] decoded2 = new byte[fis2.available()];
            fis2.read(decoded2);
            fis2.close();
            X509EncodedKeySpec publicKeySpecUser = new X509EncodedKeySpec(decoded2);
            KeyFactory keyFacPubUser = KeyFactory.getInstance("RSA");
            PublicKey pubClient = keyFacPubUser.generatePublic(publicKeySpecUser);

            rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pubClient);
            byte[] hashBytes2 = java.util.Base64.getDecoder().decode(locationReport.getUserSignature());
            byte[] chunk2 = rsaCipher.doFinal(hashBytes2);
            String userSignature = Base64.getEncoder().encodeToString(chunk2);

            verifyHash = locationReport.getUsername() + locationReport.getTimeStamp()  + locationReport.getEpoch() + locationReport.getPosX() + locationReport.getPosY();
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

            //Get time
            LocalTime clientTime = LocalTime.now();

            try{
                LocalTime witTime = LocalTime.parse(locationReport.getWitnessTimeStamp());
                LocalTime userTime = LocalTime.parse(locationReport.getWitnessTimeStamp());

                //4 segundos para possíveis atrasos na rede
                LocalTime serverWitTimeThreshold = clientTime.plusSeconds(8);
                LocalTime serverUserTimeThreshold = clientTime.plusSeconds(4);

                if(serverWitTimeThreshold.compareTo(witTime) < 0 && serverUserTimeThreshold.compareTo(userTime) < 0){
                    System.out.println("Possilble replay attack");
                    return "Error";
                }
            }
            catch (DateTimeParseException e) {
                System.out.println("Malformed report");
                e.printStackTrace();
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
        return "Correct";
    }

    //=======================MAIN=======================================================================================

    public static void main(String args[]) {
        try {
            Server server = new Server();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NotBoundException e) {
            System.out.println("?RETRYING CONNECTION?");
        }

    }
}
