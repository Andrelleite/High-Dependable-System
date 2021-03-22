import java.rmi.*;
import java.rmi.server.UnicastRemoteObject;

public class Client extends UnicastRemoteObject implements ClientInterface{
    private static final long serialVersionUID = 1L;

    public Client() throws RemoteException {
        super();
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
