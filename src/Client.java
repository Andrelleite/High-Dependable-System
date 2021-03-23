import java.io.File;
import java.io.FileNotFoundException;
import java.rmi.*;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.Scanner;

public class Client extends UnicastRemoteObject implements ClientInterface{
    private static final long serialVersionUID = 1L;

    private String username;
    private int coordinate1;
    private int coordinate2;
    private int epoch;

    public void setCoordinate1(int coordinate1) {
        this.coordinate1 = coordinate1;
    }

    public void setCoordinate2(int coordinate2) {
        this.coordinate2 = coordinate2;
    }

    public void setEpoch(int epoch) {
        this.epoch = epoch;
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

    public String findUser() {
        try {
            File myObj = new File("src/grid/grid1.txt");
            Scanner reader = new Scanner(myObj);
            while (reader.hasNextLine()) {
                String data = reader.nextLine();
                String username = data.split(",")[0];
                String epochString = data.split(",")[1];
                int epoch = Integer.parseInt(epochString.split(" ")[1]);
                String coord1 = data.split(",")[2];
                String coord2 = data.split(",")[3];
                double x2 = Double.parseDouble(coord1);
                double y2 = Double.parseDouble(coord2);
                double x1 = 10;
                double y1 = 20;
                double distaceCalc = Math.sqrt((Math.pow(x2,2) - Math.pow(x1,2)) + (Math.pow(y2,2) - Math.pow(y1,2)));
                int distance = (int) distaceCalc;

                if(distance <= 7 && !username.equals("user1") && epoch == 0){ //aqui o "user1" e o "0" depois são substituidos pelos atributos do cliente
                    return username;
                }
            }
            reader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();

        }

        return "ok";
    }

    public void requestLocationProof(){
        String userToContact = findUser();

        System.out.println(this.username + " trying to contact " + userToContact);

        try {
            ClientInterface h = (ClientInterface) Naming.lookup("rmi://localhost:7000/" + userToContact);
            String message = h.echo("bruh");
            System.out.println( userToContact + " said: " + message);
        } catch (Exception e) {
            System.out.println("Exception in main: " + e);
            e.printStackTrace();
        }

    }

    public static void main(String[] args) {

        try {
            ServerInterface h = (ServerInterface) Naming.lookup("rmi://localhost:7000/tracking");
            String message = h.echo("bruh");
            System.out.println("Server: " + message);
        } catch (Exception e) {
            System.out.println("Exception in main: " + e);
            e.printStackTrace();
        }
    }
}
