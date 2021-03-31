import java.io.File;
import java.io.FileNotFoundException;
import java.lang.reflect.Array;
import java.rmi.*;
import java.rmi.server.UnicastRemoteObject;
import java.util.*;

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

public class Client extends UnicastRemoteObject implements ClientInterface{
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

    public void setEpoch(int epoch) {
        this.epoch = epoch;
        if(moveList.containsKey(epoch)){
            this.setCoordinate1(moveList.get(epoch).getFirst());
            this.setCoordinate2(moveList.get(epoch).getSecond());
            requestLocationProof();
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

    public void setBizantino(int value) {
        this.hasError = value;
    }

    public String getUsername(){
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
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
            this.setBizantino(1);
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
                        moveList.put(epoch, new Pair(x2, y2));
                    } catch (NumberFormatException ex) { // handle your exception
                        System.out.println("Malformed input found!");
                        this.setBizantino(1);
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
                            //verificar parametros
                            Report userReport = new Report(c,this.getCoordinate1(),this.getCoordinate2(),this.epoch,username,this.getUsername(),"assinatura");
                            return userReport;
                        }
                    }
                } catch (NumberFormatException ex) { // handle your exception
                    System.out.println("Malformed input found!");
                    this.setBizantino(1);
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
                    this.setBizantino(1);
                }
            }
            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        return usersNearby;
    }

    public void requestLocationProof(){

        ArrayList<String> usersToContact = findUser();

        if(usersToContact.size() != 0){
            Iterator i = usersToContact.iterator();
            while (i.hasNext()) {
                String userToContact = (String) i.next();
                System.out.println(this.username + " trying to contact " + userToContact);
                try {
                    ClientInterface h = (ClientInterface) Naming.lookup("rmi://127.0.0.1:7001/" + userToContact);
                    Report message = h.generateLocationReportWitness(this.getClientInterface(),this.getUsername(), this.epoch);
                    if(message == null){
                        return;
                    }
                    //verificar estrutura do report
                    message.setPosX(this.getCoordinate1());
                    message.setPosY(this.getCoordinate2());

                    ServerInterface s = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
                    s.submitLocationReport(this.getClientInterface(),this.getUsername(),message);

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

    public static void main(String[] args) {

        try {
        } catch (Exception e) {
            System.out.println("Exception in main: " + e);
            e.printStackTrace();
        }
    }
}
