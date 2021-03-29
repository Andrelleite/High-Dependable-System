import java.rmi.*;
import java.util.ArrayList;

public interface ClientInterface extends Remote {
    public String echo(String message) throws RemoteException;
    public Report generateLocationReportWitness(ClientInterface c, String username, int userEpoch) throws RemoteException;
}
