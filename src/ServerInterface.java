import java.rmi.*;
import java.util.ArrayList;

public interface ServerInterface extends Remote {
    public String echo(String message) throws RemoteException;
}
