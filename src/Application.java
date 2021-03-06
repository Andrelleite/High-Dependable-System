import java.io.*;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.util.*;

class Simulation{

    private String epoch;
    private int f,fline,u,ha;
    private List<Byzantine> byzantines;
    private List<HAClient> authorities;
    private Map<String,Integer> clientEpochs;
    private List<Client> clients;
    private List<Server> servers;
    private List<Thread> workers;
    private List<String> clientsName;
    private int fileNumber;
    private String N;


    public Simulation(Map<String,Integer> clientEpochs, List<Client> clients, int filenumber) throws IOException, NotBoundException, InterruptedException, ClassNotFoundException {
        this.byzantines = new ArrayList<>();
        this.authorities = new ArrayList<>();
        this.workers = new ArrayList<>();
        this.servers = new ArrayList<>();
        this.clientEpochs = clientEpochs;
        this.clients = clients;
        this.epoch = "0";
        this.fileNumber = filenumber;
        simulate("simulate"+filenumber);
    }

    private void startServer(String cardinal) throws NotBoundException, IOException, ClassNotFoundException {

        int n = (3*this.f) + 1;
        System.out.println("REPLICAS: "+n);
        this.N = String.valueOf(n);
        LocateRegistry.createRegistry(7000);

        for(int i = 0; i < n; i++){
            try {
                System.out.println("Starting server replica number "+(i+1));
                this.servers.add(new Server(this.f,this.fline,(i+1),n));
                this.servers.get(i).setPassword("server" + (i+1));
            }  catch (NotBoundException | IOException | ClassNotFoundException e) {
                System.out.println("sit.");
            }
        }

        for(int i = 0; i < n; i++){
            this.servers.get(i).connectToNetwork(this.servers.get(i).getInterface());
        }

    }

    private void serverUp(int i) throws NotBoundException, IOException, ClassNotFoundException {

        int n = (2*this.f) + 1;
        try {
            System.out.println("Starting server replica number "+(i+1));
            this.servers.add(new Server(this.f,this.fline,(i+1),n));
            this.servers.get(i).setPassword("server" + (i+1));
        }  catch (NotBoundException | IOException | ClassNotFoundException e) {
            System.out.println("sit.");
        }

        this.servers.get(i).connectToNetwork(this.servers.get(i).getInterface());

    }

    private void startAuthorities() throws NotBoundException, IOException, ClassNotFoundException {

        String username;
        for(int i = 0; i < this.ha; i++) {
            HAClient ha = new HAClient(Integer.parseInt(this.N),this.f,(i+1));
            this.authorities.add(ha);
            this.authorities.get(i).handshake();
        }
    }

    private void startClients(){

        String username;
        for(int i = 0; i < this.u; i++){
            int byz = 0;
            username = "user"+(i+1);
            for(int j = 0; j < this.byzantines.size() && byz == 0; j++){
                if(this.byzantines.get(j).getUsername().equals(username)){
                    byz = 1;
                }
            }
            if(byz == 0){
                try {
                    System.out.println("-------- NEW CLIENT "+username+" -------");
                    Client client = new Client(this.fileNumber,Integer.parseInt(this.N),this.f);
                    String url = "rmi://127.0.0.1:7001/" + username;
                    Naming.rebind(url, client);
                    ClientInterface h = (ClientInterface) Naming.lookup("rmi://127.0.0.1:7001/" + username);
                    client.setClientInterface(h);
                    client.setUsername(username);
                    client.setPassword(username);
                    client.loadMoves();
                    this.clients.add(client);
                    System.out.println("new client added : " + username);
                } catch (RemoteException | MalformedURLException | NotBoundException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    private void setClientsName (){
        List<String> clientsNames = new ArrayList<>();

        Iterator<Client> itr = this.clients.iterator();
        while (itr.hasNext()) {
            Client client = itr.next();
            if(!clientsNames.contains(client.getUsername())){
                clientsNames.add(client.getUsername());
            }
        }

        Iterator<Byzantine> itrb = this.byzantines.iterator();
        while (itrb.hasNext()) {
            Byzantine client = itrb.next();
            if(!clientsNames.contains(client.getUsername())){
                clientsNames.add(client.getUsername());
            }
        }

        clientsNames.add("ha");
        clientsName = clientsNames;
    }

    private int setValue(String regex){
        int value;
        value = Integer.parseInt(regex.split(",")[1]);
        return value;
    }

    private void setByzantines(String regex) throws RemoteException, MalformedURLException, NotBoundException {
        String username = regex.split(",")[0];
        Byzantine bad = new Byzantine(this.fileNumber,Integer.parseInt(this.N),this.f);
        System.out.println("------Setting Byzantine user: "+username+"------");
        String url = "rmi://127.0.0.1:7001/" + username;
        Naming.rebind(url, bad);
        ClientInterface h = (ClientInterface) Naming.lookup("rmi://127.0.0.1:7001/" + username);
        bad.setClientInterface(h);
        bad.setUsername(username);
        bad.setPassword(username);
        bad.loadMoves();
        System.out.println("new client added : " + username);
        this.byzantines.add(bad);
    }

    private void verifyClient(String username) throws IOException, InterruptedException, ClassNotFoundException {

        int flag = 0;

        for(int i = 0; i < this.byzantines.size() && flag == 0; i++){
            if(this.byzantines.get(i).getUsername().equals(username)){
                flag = 1;
            }
        }

        for(int i = 0; i < this.clients.size() && flag == 0; i++){
            if(this.clients.get(i).getUsername().equals(username)){
                flag = 1;
                this.clients.get(i).setEpoch(Integer.parseInt(this.epoch));
            }
        }


    }

    private void sendProofReq() throws IOException, InterruptedException, ClassNotFoundException {

        List<String> clientsWithError = new ArrayList<>();

        System.out.println("\nEpoch : " + this.epoch + "\n");
        Iterator<Client> itr = this.clients.iterator();
        while (itr.hasNext()) {
            Client client = itr.next();
            if (client.getHasError() == 1) {
                itr.remove();
                clientsWithError.add(client.getUsername());
            }else{
                client.setClientsWithError(clientsWithError);
                client.setEpoch(Integer.parseInt(this.epoch));
            }
        }

        Iterator<Byzantine> itrb = this.byzantines.iterator();
        while (itrb.hasNext()) {
            Byzantine client = itrb.next();
            if (client.getHasError() == 1) {
                itrb.remove();
                clientsWithError.add(client.getUsername());
            }else{
                client.setClientsWithError(clientsWithError);
                client.setEpoch(Integer.parseInt(this.epoch));
            }
        }

        Iterator<Client> itr1 = this.clients.iterator();
        while (itr1.hasNext()) {
            Client client = itr1.next();
            client.setRequestLocationProof();
        }

        Iterator<Byzantine> itr2 = this.byzantines.iterator();
        while (itr2.hasNext()) {
            Byzantine client = (Byzantine) itr2.next();
            client.setRequestLocationProof();
        }

    }

    private void sendProofReqFake(String username, String target) throws IOException, InterruptedException, ClassNotFoundException {
        int flag = 0;
        String original;
        System.out.println("=================================== I'M TRICK WOW YA ====================================");
        for(int i = 0; i < this.byzantines.size() && flag == 0; i++){
            if(this.byzantines.get(i).getUsername().equals(username)){
                original = this.byzantines.get(i).getUsername();
                this.byzantines.get(i).getFileMan().appendInformation("\n");
                this.byzantines.get(i).getFileMan().appendInformation(" TRYING TO FAKE IDENTITY FROM "+username+" TO "+target);
                this.byzantines.get(i).setUsername(target,original);
                this.byzantines.get(i).setRequestLocationProof();
                this.byzantines.get(i).setUsername(original,original);
                flag = 1;
            }
        }
    }

    private void spyOnReports(String epoch, String byz, String victim) throws RemoteException, InterruptedException {
        int flag = 0;
        String original;
        System.out.println("=================================== I'M GONNA WOW YA ====================================");
        for(int i = 0; i < this.byzantines.size() && flag == 0; i++){
            if(this.byzantines.get(i).getUsername().equals(byz)){
                original = this.byzantines.get(i).getUsername();
                this.byzantines.get(i).getFileMan().appendInformation("\n");
                this.byzantines.get(i).getFileMan().appendInformation(" TRYING TO FAKE IDENTITY FROM "+byz+" TO "+victim);
                this.byzantines.get(i).setUsername(victim,original);
                this.byzantines.get(i).getReports(epoch);
                this.byzantines.get(i).setUsername(original,original);
                flag = 1;
            }
        }
    }

    private void sendReportReq(String username,String epoch) throws IOException, InterruptedException, ClassNotFoundException {
        int flag = 0;
        for(int i = 0; i < this.clients.size() && flag == 0; i++){
            if(this.clients.get(i).getUsername().equals(username)){
                this.clients.get(i).getReports(epoch);
                flag = 1;
            }
        }
        for(int i = 0; i < this.byzantines.size() && flag == 0; i++){
            if(this.byzantines.get(i).getUsername().equals(username)){
                this.byzantines.get(i).getReports(epoch);
                flag = 1;
            }
        }
    }

    private void sendWitnessReq(String username,String epi,String epf) throws IOException, InterruptedException, ClassNotFoundException {
        int flag = 0;
        for(int i = 0; i < this.clients.size() && flag == 0; i++){
            if(this.clients.get(i).getUsername().equals(username)){
                this.clients.get(i).getMyWitnessProofs(epi,epf);
                flag = 1;
            }
        }
        for(int i = 0; i < this.byzantines.size() && flag == 0; i++){
            if(this.byzantines.get(i).getUsername().equals(username)){
                this.byzantines.get(i).getMyWitnessProofs(epi,epf);
                flag = 1;
            }
        }
    }

    private void instructionMan(String regex) throws IOException, NotBoundException, ClassNotFoundException, InterruptedException {

        String x,y;
        String user;
        String epoch;
        String[] generated = regex.split(",");
        String origin = generated[0];
        String request = generated[1];

        if(origin.equals("generateproofs")){
            if(!this.epoch.equals(request)){
                this.epoch = request;
                System.out.println("EPOCH MOVED TO "+this.epoch);
                /*Server need correction*/
                this.servers.get(0).verifyF(Integer.parseInt(this.epoch)-1);
            }
            try {
                sendProofReq();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }else if(origin.equals("fake")){
            System.out.println(origin+" is requesting his reports.");
            try {
                sendProofReqFake(generated[2],generated[3]);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }else if(request.equals("request")){
            System.out.println(origin+" is requesting his reports.");
            try {
                sendReportReq(origin,generated[2]);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }else if(request.equals("witness")){
            System.out.println(origin+" is requesting his witnessed reports.");
            try {
                sendWitnessReq(origin,generated[2],generated[3]);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }else if(generated[2].startsWith("user")){
            if(origin.equals("ha")){
                user = regex.split(",")[2];
                System.out.println("**AUTHORITY "+request+" REQUESTING**");
                this.authorities.get(Integer.parseInt(request)-1).communicate(this.authorities.get(Integer.parseInt(request)-1).getServerInterface(),2,user,"0","0",generated[3]);
                System.out.println("HA is requesting "+user+" location.");
            }
        }else if(generated[2].equals("position")){
            x = generated[3];
            y = generated[4];
            epoch = regex.split(",")[5];
            if(origin.equals("ha")){
                System.out.println("HA"+request+" is requesting users history at this location: ("+x+","+y+") at epoch "+ epoch);
                this.authorities.get(Integer.parseInt(request)-1).communicate(this.authorities.get(Integer.parseInt(request)-1).getServerInterface(),1,"",x,y,epoch);
            }
        }else if(request.equals("down")){
            System.out.println("Simulate Server Crash or Connection drop.");
            this.servers.get(Integer.parseInt(generated[2])-1).shutdown();
        }else if(request.equals("up")){
            System.out.println("Turn on Server.");
            serverUp(Integer.parseInt(generated[2])-1);
            //setClientsName();
            this.servers.get(Integer.parseInt(generated[2])-1).setClients(clientsName);
            this.servers.get(Integer.parseInt(generated[2])-1).setPassword("server"+(Integer.parseInt(generated[2])));
            this.servers.get(Integer.parseInt(generated[2])-1).loadSymmetricKeys();
        }else if(origin.equals("spy")){
            if(request.equals("report")){
                spyOnReports(generated[2],generated[3],generated[4]);
            }
        }


    }

    private void simulate(String file) throws IOException, NotBoundException, InterruptedException, ClassNotFoundException {

        int flag = 0;
        int lineCounter = 0;
        File simulation = new File("src/grid/"+file+".txt");
        Scanner reader = new Scanner(simulation);
        System.out.println("====================== SIMULATION HAS STARTED ======================");
        while (reader.hasNextLine() && flag == 0) {
            String line = reader.nextLine();

            if(lineCounter == 0){
                this.f = setValue(line);
                this.fline = Integer.parseInt(line.split(",")[2]);
                System.out.println("F: "+this.f+" F': "+this.fline);
                startServer(line);
                System.out.println("======================ALL SERVERS ARE ONLINE======================");
            }else if(lineCounter == 1){
                this.u = setValue(line);
            }else if(lineCounter == 2){
                this.ha = setValue(line);
                startAuthorities();
            }else if(lineCounter < this.f+3){
                setByzantines(line);
            }else if(line.equals("endsim")){
                flag = 1;
            }else if(line.equals("setupclients")){
                System.out.println("CLIENTS");
                startClients();
            }else{
                Thread worker = new Thread(){
                    @Override
                    public void run(){
                        try {
                            instructionMan(line);
                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (NotBoundException e) {
                            e.printStackTrace();
                        } catch (ClassNotFoundException e) {
                            e.printStackTrace();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                };
                worker.start();
                if(line.split(",")[0].equals("generateproofs")){
                    worker.join();
                }else{
                    System.out.println("======================================================= "+line);
                    this.workers.add(worker);
                }
                Thread.sleep(1000);
            }
            lineCounter++;
        }
        /*Server need correction*/
        this.servers.get(0).verifyF(Integer.parseInt(this.epoch));
        for(int i = 0; i < this.workers.size(); i++){
            this.workers.get(i).join();
        }
    }

}

public class Application {

    public static void cleanTemporaryFiles(){
        File tempCr = new File("TempClientReports.txt");
        File tempSu = new File("TempSystemUsers.txt");
        if (tempCr.delete()) {
            System.out.println("Deleted the file: " + tempCr.getName());
        } else {
            System.out.println("Failed to delete the file.");
        }
        if (tempSu.delete()) {
            System.out.println("Deleted the file: " + tempSu.getName());
        } else {
            System.out.println("Failed to delete the file.");
        }
    }

    public static void gridGenerator(int u, int number, int maxEpochs, int gridLimit){

        String dir = "src/grid/grid"+number+".txt";
        Random random;
        FileWriter fw = null;
        BufferedWriter bw = null;
        PrintWriter out = null;
        PrintWriter writer = null;
        int x,y;

        try {

            /*File Initializer*/
            writer = new PrintWriter(dir, "UTF-8");
            writer.print("");
            writer.close();

            /*File Information Addition*/
            fw = new FileWriter(dir, true);
            bw = new BufferedWriter(fw);
            out = new PrintWriter(bw);
            for(int j = 0; j <= maxEpochs; j++){
                random = new Random(j+25);
                for(int i = 0; i < u; i++){
                    x = random.nextInt(gridLimit);
                    y = random.nextInt(gridLimit);
                    if(j == maxEpochs && i+1 == u){
                        out.print("user"+(i+1)+", "+j+", "+x+", "+y);
                    }else{
                        out.println("user"+(i+1)+", "+j+", "+x+", "+y);
                    }
                }
            }
            out.close();
        } catch (IOException e) {
            /*Handler for exception*/
        }
        finally {
            if(out != null)
                out.close();
            try {
                if(bw != null)
                    bw.close();
            } catch (IOException e) {
                /*Handler for exception*/
            }
            try {
                if(fw != null)
                    fw.close();
            } catch (IOException e) {
                /*Handler for exception*/
            }
        }

    }

    public static void main(String[] args) throws InterruptedException, IOException, ClassNotFoundException, NotBoundException {

        int epoch = 0;
        int lastEpoch = 0;
        int numberOfUsers = 0;
        List<Client> clientsList = new ArrayList<>();
        List<String> clientsWithError = new ArrayList<>();
        Map<String, Integer> initClients = new HashMap<String, Integer>();
        LocateRegistry.createRegistry(7001);
        int filenumber;
        int flag = 0;
        int lineCounter = 0;

        cleanTemporaryFiles();
        PrintWriter writer = new PrintWriter("ClientReports.txt");
        writer.print("");
        writer.close();

        writer = new PrintWriter("SystemUsers.txt");
        writer.print("");
        writer.close();


        System.out.print("NUMBER OF SIMULATION: ");
        Scanner scan = new Scanner(System.in);
        filenumber = scan.nextInt();


        File s = new File("src/grid/simulate"+filenumber+".txt");
        Scanner reader = new Scanner(s);
        while (reader.hasNextLine() && flag == 0) {
            String line = reader.nextLine();
            if(lineCounter == 2) {
                numberOfUsers = Integer.parseInt(line.split(",")[1]);
                flag = 1;
            }
            lineCounter++;
        }
        System.out.println("NUMBER OF USERS: "+numberOfUsers);
        reader.close();
        //gridGenerator(numberOfUsers,filenumber,2,40);

        /* Load epochs and users*/
        try {
            File myObj = new File("src/grid/grid"+filenumber+".txt");
            reader = new Scanner(myObj);
            while (reader.hasNextLine()) {
                String data = reader.nextLine();
                String username = data.split(",")[0];
                String epochString = data.split(",")[1];
                int tempEpoch = Integer.parseInt(epochString.split(" ")[1]);
                if(tempEpoch > lastEpoch) lastEpoch = tempEpoch;
                if(!initClients.containsKey(username)){
                    initClients.put(username, tempEpoch);
                }

            }
            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }


        Simulation simulation = new Simulation(initClients,clientsList,filenumber);
        System.exit(1);

    }
}
