import java.net.MalformedURLException;
import java.rmi.*;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.*;
import java.util.ArrayList;

public class Server extends UnicastRemoteObject implements ServerInterface{

    private static final long serialVersionUID = 1L;
    private ArrayList<ClientInterface> clients;

    public Server() throws RemoteException {
        super();
        this.clients = new ArrayList<>();
    }

    public String echo(String message) throws RemoteException {
        System.out.println("print do lado do servidor...!.");
        return message;
    }

    public void submitLocationReport() throws RemoteException{

    }

    // =========================================================
    public static void main(String[] args) {

        try {
            Server h = new Server();
            Registry r = LocateRegistry.createRegistry(7000);
            r.rebind("tracking", h);
            System.out.println("Server ready.");
        } catch (RemoteException re) {
            System.out.println("Exception: " + re);
        }

    }

}
