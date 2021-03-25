import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.MalformedURLException;
import java.rmi.*;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Server extends UnicastRemoteObject implements ServerInterface, Serializable{

    private static final long serialVersionUID = 1L;
    private ArrayList<ClientInterface> clients;
    private ArrayList<Report> reps;
    private boolean imPrimary;
    private String IPV4;
    private int portRMI;

    //=======================CONNECTION=================================================================================

    public Server() throws IOException, NotBoundException {
        this.IPV4 = "127.0.0.1";
        this.portRMI = 7000;
        this.clients = new ArrayList<>();
        this.reps = new ArrayList<>();
        ServerInterface server = retryConnection(7000);
        if (!imPrimary) {
            checkPrimaryServer(server);
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
        this.clients.add(c);
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
        System.out.println("RECEIVED A NEW PROOF OF LOCATION FROM - "+user);
        System.out.println("POS: (" + locationReport.getPosX() + "," + locationReport.getPosY() + ") AT EPOCH " + locationReport.getEpoch());
        System.out.println("WITNESS: " + locationReport.getWitness());
        System.out.println("WITNESS SIGNATURE: " + locationReport.getWitnessSignature() );
        //Report newReport = new Report(c,x,y,epoch,user);
        this.reps.add(locationReport);
        try {
            updateReports();
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Things went sideways :(");
        }
    }

    public List<Report> obtainLocationReport(ClientInterface c, int epoch) throws IOException, ClassNotFoundException {

        return fetchReports(c,epoch);

    }

    //=======================USER-METHODS===============================================================================

    private void updateReports() throws IOException {

        File file=new File("ClientReports.txt");
        ObjectOutputStream oos= new ObjectOutputStream(
                                new FileOutputStream(file));
        oos.writeObject(this.reps);
        oos.close();
    }

    private List<Report> fetchReports(ClientInterface c, int epoch) throws IOException, ClassNotFoundException {

        //String user = c.getUserId();
        File file=new File("ClientReports.txt");
        ObjectInputStream ois = new ObjectInputStream(
                                new FileInputStream(file));
        ArrayList<Report> clientReports = (ArrayList<Report>) ois.readObject();
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
        ois.close();
        return clientReports;
    }

    //=======================MAIN=======================================================================================

    public static void main(String args[]) {
        try {
            Server server = new Server();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NotBoundException e) {
            System.out.println("?RETRYING CONNECTION?");
        }

    }
}
