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
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

public class Server extends UnicastRemoteObject implements ServerInterface, Serializable{

    private static final long serialVersionUID = 1L;
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
        String decryptedHash = "";
        String finalMessage = "null";

        try{
            //get client public key
            FileInputStream fis = new FileInputStream("src/keys/pub.key");
            byte[] encoded = new byte[fis.available()];
            fis.read(encoded);
            fis.close();
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encoded);
            KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
            PublicKey pub = keyFacPub.generatePublic(pubSpec);

            String hash = message.split(" | ")[2];
            String content = message.split(" | ")[0];

            //decrypt the hash
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, pub);
            byte[] hashBytesTime = Base64.getDecoder().decode(hash);
            byte[] chunk1 = rsaCipher.doFinal(hashBytesTime);
            decryptedHash = Base64.getEncoder().encodeToString(chunk1);

            //Hash message
            byte[] messageByte = content.getBytes();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(messageByte);
            byte[] digestByte = digest.digest();
            String digestB64 = Base64.getEncoder().encodeToString(digestByte);

            if(digestB64.equals(decryptedHash)){
                System.out.println("DEU CARALHO");
                finalMessage = message;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        try {
            //get server private key
            FileInputStream fis = new FileInputStream("src/keys/priv.key");
            byte[] encoded = new byte[fis.available()];
            fis.read(encoded);
            fis.close();
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
            PrivateKey priv = keyFacPriv.generatePrivate(privSpec);

            //Hash message
            byte[] messageByte = finalMessage.getBytes();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(messageByte);
            byte[] digestByte = digest.digest();
            String digestB64 = Base64.getEncoder().encodeToString(digestByte);

            //sign the hash with the server's private key
            Cipher cipherHash = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipherHash.init(Cipher.ENCRYPT_MODE, priv);
            byte[] hashBytes = Base64.getDecoder().decode(digestB64);
            byte[] finalHashBytes = cipherHash.doFinal(hashBytes);
            String signedHash = Base64.getEncoder().encodeToString(finalHashBytes);

            finalMessage = finalMessage + " | " + signedHash;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }


        return finalMessage;
    }

    //=======================USER-METHODS===============================================================================

    public void submitLocationReport(ClientInterface c,String user, Report locationReport) throws RemoteException{
        System.out.println("===============================================================================================");
        System.out.println("RECEIVED A NEW PROOF OF LOCATION FROM - "+user);
        System.out.println("POS: (" + locationReport.getPosX() + "," + locationReport.getPosY() + ") AT EPOCH " + locationReport.getEpoch());
        System.out.println("WITNESS: " + locationReport.getWitness());
        System.out.println("WITNESS SIGNATURE: " + locationReport.getWitnessSignature() );
        System.out.println("===============================================================================================");

        this.reps.add(locationReport);
        try {
            updateReports();
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Things went sideways :(");
        }
    }

    public ArrayList<Report> obtainLocationReport(ClientInterface c, int epoch) throws IOException, ClassNotFoundException {
        //verificar se a assinatura é falsa
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
