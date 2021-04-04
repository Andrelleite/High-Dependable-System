import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.*;
import java.util.ArrayList;
import java.util.IdentityHashMap;

public class HAClient extends Thread{

    private String entity;
    private ServerInterface h;
    private IdentityHashMap<Integer,Integer> identity;

    public HAClient(){
        super();
        handshake();
    }

    private void handshake(){
        try {
            try {
                this.h = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
                communicate(this.h);
            }catch (RemoteException | MalformedURLException | NotBoundException e){
                retry();
            }
        } catch (Exception e) {
            System.out.println("Exception in main: " + e);
            e.printStackTrace();
        }
    }

    private void communicate(ServerInterface h) throws IOException, ClassNotFoundException {

        ArrayList<Report> reports;

        /* All users location report at specific epochs *test* */
        System.out.println("$$$ USERS AT: ("+10+","+20+") IN EPOCH"+2+" $$$");
        reports = (ArrayList<Report>) h.obtainUsersAtLocation(new int[]{10,20},2).getReports();
        if(reports != null){
            for(int i = 0; i < reports.size(); i++){
                System.out.println("\tENTRY "+(i+1)+": "+reports.get(i).getUsername());
            }
        }else{
            System.out.println("No entries for that combination.");
        }

        /* Specific user report at specific epochs *test* */
        System.out.println("$$$ LOCATIONS OF USER: "+"user1"+" $$$");
        reports = (ArrayList<Report>) h.obtainLocationReport("user1",2).getReports();
        if(reports != null){
            for(int i = 0; i < reports.size(); i++){
                System.out.println("\tENTRY "+(i+1)+": "+
                        reports.get(i).getUsername()+" -> ("+
                        reports.get(i).getPosX()+","+reports.get(i).getPosY()+")");
            }
        }else{
            System.out.println("No entries for that combination.");
        }

    }

    //=======================THREAD CONNECTION==========================================================================

    private void retry() throws InterruptedException, IOException, ClassNotFoundException {
        Thread thread = new Thread(this);
        thread.start();
        thread.join();
        communicate(this.h);
    }

    @Override
    public void run(){
        while(this.h == null){
            System.out.println("New try.");
            try {
                Thread.sleep(2000);
                this.h = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
            } catch (InterruptedException e) {
                /*exit*/
            } catch (RemoteException | MalformedURLException | NotBoundException e){
                /*Try new connection in 2 seconds*/
            }
        }
    }

    //====================================MAIN==========================================================================

    public static void main(String[] args) {
        HAClient ha = new HAClient();
    }
}
