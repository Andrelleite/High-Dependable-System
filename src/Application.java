import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.*;

import static java.rmi.Naming.*;

public class Application {
    public static void main(String[] args) {
        int epoch = 0;
        List<Client> clientsList = new ArrayList<>();
        List<String> clientsWithError = new ArrayList<>();
        Map<String, Integer> initClients = new HashMap<String, Integer>();
        try {
            LocateRegistry.createRegistry(7001);
            Server s1 = new Server();
        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (NotBoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            File myObj = new File("src/grid/grid1.txt");
            Scanner reader = new Scanner(myObj);
            while (reader.hasNextLine()) {
                String data = reader.nextLine();
                String username = data.split(",")[0];
                if(!initClients.containsKey(username)){
                    String epochString = data.split(",")[1];
                    int tempEpoch = Integer.parseInt(epochString.split(" ")[1]);
                    initClients.put(username, tempEpoch);
                }
            }
            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        System.out.println(initClients.entrySet());
        //fim da ultima epoch
        while(true){
            if(initClients.containsValue(epoch)){
                int finalEpoch = epoch; //to use epoch in lambda expression
                initClients.forEach((key, value) -> {
                    if(finalEpoch == value) {
                        try {
                            Client client = new Client();

                            String url = "rmi://127.0.0.1:7001/" + key;
                            rebind(url, client);
                            client.setUsername(key);
                            client.loadMoves();
                            clientsList.add(client);
                            System.out.println("new client added : " + key);
                        } catch (RemoteException | MalformedURLException e) {
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
                    try {
                        unbind("rmi://127.0.0.1:7001/" + client.getUsername());
                    } catch (RemoteException e) {
                        e.printStackTrace();
                    } catch (NotBoundException e) {
                        e.printStackTrace();
                    } catch (MalformedURLException e) {
                        e.printStackTrace();
                    }
                }else{
                    client.setClientsWithError(clientsWithError);
                    client.setEpoch(epoch);
                }
            }

            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            epoch += 1;

        }
    }
}
