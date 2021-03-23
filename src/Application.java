import java.io.File;
import java.io.FileNotFoundException;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;

public class Application {
    public static void main(String[] args){

        try {
            Client c1 = new Client();
            c1.setUsername("user1");
            c1.setCoordinate1(10);
            c1.setCoordinate2(20);

            Client c3 = new Client();
            c3.setUsername("user3");
            c3.setCoordinate1(10);
            c3.setCoordinate2(15);


            Registry r = LocateRegistry.createRegistry(7000);
            r.rebind("user3", c3);

            c1.requestLocationProof();
        } catch (RemoteException re) {
            System.out.println("Exception: " + re);
        }
    }
}
