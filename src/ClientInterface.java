import java.rmi.*;
import java.util.List;

public interface ClientInterface extends Remote {
    public String getUsername() throws RemoteException;
    public String echo(String message) throws RemoteException;
    public List<Report> generateLocationReportWitness(ClientInterface c, String username, int userEpoch, String signature, int nonce, String time) throws RemoteException;
    public void getReports(String ep) throws RemoteException;
}
