import java.rmi.*;
import java.util.ArrayList;

public interface ClientInterface extends Remote {
    public String getUsername() throws RemoteException;
    public String echo(String message) throws RemoteException;
    public Report generateLocationReportWitness(ClientInterface c, String username) throws RemoteException;
}