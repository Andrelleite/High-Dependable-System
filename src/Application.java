import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.ExportException;
import java.util.*;

import static java.rmi.Naming.*;

class Simulation{

    private String epoch;
    private int f,fline,u,ha;
    private List<Byzantine> byzantines;
    private List<HAClient> authorities;
    private Map<String,Integer> clientEpochs;
    private List<Client> clients;
    private Server server;
    private List<Thread> workers;

    public Simulation(Map<String,Integer> clientEpochs, List<Client> clients) throws IOException, NotBoundException, InterruptedException, ClassNotFoundException {
        this.byzantines = new ArrayList<>();
        this.authorities = new ArrayList<>();
        this.workers = new ArrayList<>();
        this.clientEpochs = clientEpochs;
        this.clients = clients;
        this.epoch = "0";
        simulate();
    }

    private void startServer() throws NotBoundException, IOException, ClassNotFoundException {
        try {
            this.server = new Server(this.f);
        }  catch (NotBoundException | IOException | ClassNotFoundException e) {
            e.printStackTrace();
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
                    Client client = new Client();
                    String url = "rmi://127.0.0.1:7001/" + username;
                    Naming.rebind(url, client);
                    client.setUsername(username);
                    ClientInterface h = (ClientInterface) Naming.lookup("rmi://127.0.0.1:7001/" + username);
                    client.setClientInterface(h);
                    client.loadMoves();
                    this.clients.add(client);
                    System.out.println("new client added : " + username);
                } catch (RemoteException | MalformedURLException | NotBoundException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    private int setValue(String regex){
        int value;
        value = Integer.parseInt(regex.split(",")[1]);
        return value;
    }

    private void setByzantines(String regex) throws RemoteException, MalformedURLException, NotBoundException {
        String username = regex.split(",")[0];
        Byzantine bad = new Byzantine();
        System.out.println("------Setting Byzantine user: "+username+"------");
        bad.setUsername(username);
        String url = "rmi://127.0.0.1:7001/" + username;
        Naming.rebind(url, bad);
        ClientInterface h = (ClientInterface) Naming.lookup("rmi://127.0.0.1:7001/" + username);
        bad.setClientInterface(h);
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
        for(int i = 0; i < this.byzantines.size() && flag == 0; i++){
            if(this.byzantines.get(i).getUsername().equals(username)){
                original = this.byzantines.get(i).getUsername();
                this.byzantines.get(i).fakeIdentity(target,original);
                this.byzantines.get(i).setRequestLocationProof();
                this.byzantines.get(i).fakeIdentity(original,original);
                flag = 1;
            }
        }
    }

    private void spyOnReports(String epoch, String byz, String victim) throws RemoteException {
        int flag = 0;
        String original;
        System.out.println("=================================== I'M GONNA WOW YA ====================================");
        for(int i = 0; i < this.byzantines.size() && flag == 0; i++){
            if(this.byzantines.get(i).getUsername().equals(byz)){
                original = this.byzantines.get(i).getUsername();
                this.byzantines.get(i).fakeIdentity(victim,original);
                this.byzantines.get(i).getReports(epoch);
                this.byzantines.get(i).fakeIdentity(original,original);
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

    private void instructionMan(String regex) throws IOException, NotBoundException, ClassNotFoundException {

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
            }
            try {
                sendProofReq();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }else if(request.equals("fake")){
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
        }else if(request.startsWith("user")){
            if(origin.equals("ha")){
                user = regex.split(",")[1];
                this.authorities.get(0).handshake(2,"user1","0","0","0");
                System.out.println("HA is requesting "+user+" location.");
            }
        }else if(request.equals("position")){
            x = generated[2];
            y = generated[3];
            epoch = regex.split(",")[4];
            if(origin.equals("ha")){
                System.out.println("HA is requesting users history at this location: ("+x+","+y+") at epoch "+ epoch);
                this.authorities.get(0).handshake(1,"none",x,y,epoch);
            }
        }else if(request.equals("down")){
            System.out.println("Simulate Server Crash or Connection drop.");
            this.server.shutdown();
            this.server = null;
        }else if(request.equals("up")){
            System.out.println("Turn on Server.");
            startServer();
        }else if(origin.equals("spy")){
            if(request.equals("report")){
                spyOnReports(generated[2],generated[3],generated[4]);
            }
        }


    }

    private void simulate() throws IOException, NotBoundException, InterruptedException, ClassNotFoundException {

        int flag = 0;
        int lineCounter = 0;
        File simulation = new File("src/grid/simulate.txt");
        Scanner reader = new Scanner(simulation);
        System.out.println("====================== SIMULATION HAS STARTED ======================");
        while (reader.hasNextLine() && flag == 0) {
            String line = reader.nextLine();

            if(lineCounter == 0){
                this.f = setValue(line);
                this.fline = Integer.parseInt(line.split(",")[2]);
                System.out.println("F: "+this.f+" F': "+this.fline);
                startServer();
            }else if(lineCounter == 1){
                this.u = setValue(line);
            }else if(lineCounter == 2){
                this.ha = setValue(line);
                HAClient ha = new HAClient();
                this.authorities.add(ha);
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
                        }
                    }
                };
                worker.start();
                this.workers.add(worker);
                Thread.sleep(1000);
            }

            lineCounter++;
        }
        for(int i = 0; i < this.workers.size(); i++){
            this.workers.get(i).join();
        }
    }

}


public class Application {

    public static void main(String[] args) throws InterruptedException, IOException, ClassNotFoundException, NotBoundException {

        int epoch = 0;
        int lastEpoch = 0;
        List<Client> clientsList = new ArrayList<>();
        List<String> clientsWithError = new ArrayList<>();
        Map<String, Integer> initClients = new HashMap<String, Integer>();
        LocateRegistry.createRegistry(7001);

        /* Load epochs and users*/
        try {
            File myObj = new File("src/grid/grid1.txt");
            Scanner reader = new Scanner(myObj);
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
            System.out.println(lastEpoch);
            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        Simulation simulation = new Simulation(initClients,clientsList);
        System.exit(1);

        System.out.println(initClients.entrySet());
        //fim da ultima epoch
        while(epoch <= lastEpoch){
            if(initClients.containsValue(epoch)){
                int finalEpoch = epoch; //to use epoch in lambda expression
                initClients.forEach((key, value) -> {
                    if(finalEpoch == value) {
                        try {
                            Client client = new Client();
                            String url = "rmi://127.0.0.1:7001/" + key;
                            rebind(url, client);
                            client.setUsername(key);
                            ClientInterface h = (ClientInterface) Naming.lookup("rmi://127.0.0.1:7001/" + key);
                            client.setClientInterface(h);
                            System.out.println("->>>>>>>>> " + client.getClientInterface());
                            client.loadMoves();
                            clientsList.add(client);
                            System.out.println("new client added : " + key);
                        } catch (RemoteException | MalformedURLException | NotBoundException e) {
                            e.printStackTrace();
                        }
                    }
                });
            }
            System.out.println("\nEpoch : " + epoch + "\n");
            Iterator<Client> itr = clientsList.iterator();
            while (itr.hasNext()) {
                Client client = itr.next();
                if (client.getHasError() == 1) {
                    itr.remove();
                    clientsWithError.add(client.getUsername());
                    /*try {
                        unbind("rmi://127.0.0.1:7001/" + client.getUsername());
                    } catch (RemoteException | NotBoundException | MalformedURLException e) {
                        e.printStackTrace();
                    }*/
                }else{
                    client.setClientsWithError(clientsWithError);
                    client.setEpoch(epoch);
                }
            }
            Iterator<Client> itr1 = clientsList.iterator();
            while (itr1.hasNext()) {
                Client client = itr1.next();
                client.setRequestLocationProof();
            }

            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            epoch += 1;
            clientsWithError.clear();
        }
    }
}
