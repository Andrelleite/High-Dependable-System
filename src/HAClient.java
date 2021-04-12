import javax.print.attribute.standard.RequestingUserName;
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
    }

    public void handshake(int op,String user,String x, String y, String epoch){
        try {
            try {
                this.h = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
                communicate(this.h, op,user,x,y,epoch);
            }catch (RemoteException | MalformedURLException | NotBoundException e){
                retry(op,user,x,y,epoch);
            }
        } catch (Exception e) {
            System.out.println("Exception in main: " + e);
            e.printStackTrace();
        }
    }

    private void communicate(ServerInterface h, int op,String user,String x, String y, String epoch) throws IOException, ClassNotFoundException {

        ArrayList<Report> reports;
        System.setProperty("java.rmi.transport.tcp.responseTimeout", "2000");
        try {
            if(op == 1){
                /* All users location report at specific epochs *test* */
                System.out.println("$$$ USERS AT: "+x+","+y+" IN EPOCH "+epoch+" $$$");
                reports = (ArrayList<Report>) h.obtainUsersAtLocation("hauser", x+","+y,epoch).getReports();
                if(reports != null){
                    for(int i = 0; i < reports.size(); i++){
                        System.out.println("\tENTRY "+(i+1)+": "+reports.get(i).getUsername());
                    }
                }else{
                    System.out.println("No entries for that combination.");
                }
            }else if(op == 2){
                /* Specific user report at specific epochs *test* */
                System.out.println("$$$ LOCATIONS OF USER: "+user+" at epoch "+epoch+" $$$");
                reports = (ArrayList<Report>) h.obtainLocationReport(user,epoch).getReports();
                if(reports != null){
                    for(int i = 0; i < reports.size(); i++){
                        System.out.println("\tENTRY "+(i+1)+": "+
                                reports.get(i).getUsername()+" -> ("+
                                reports.get(i).getPosX()+","+reports.get(i).getPosY()+")");
                    }
                }else{
                    System.out.println("No entries for that combination.");
                }
            }else{
                System.out.println("OP Code unavailable");
            }
        }catch (ConnectException | UnmarshalException | InterruptedException e){
            try {
                this.h = null;
                retry(op,user,x,y,epoch);
            } catch (InterruptedException interruptedException) {
                System.out.println("SERVICE IS DOWN. COME BACK LATER.");
            }
        }

    }

    //=======================THREAD CONNECTION==========================================================================

    private void retry(int op,String user,String x, String y, String epoch) throws InterruptedException, IOException, ClassNotFoundException {
        Thread thread = new Thread(this);
        thread.start();
        thread.join();
        if(this.h == null){
            System.out.println("SERVICE IS DOWN. COME BACK LATER.");
            return;
        }else{
            communicate(this.h,op,user,x,y,epoch);
        }
    }

    @Override
    public void run(){
        int tries = 0;
        while(this.h == null && tries < 5){
            System.out.println("New try.");
            try {
                Thread.sleep(2000);
                this.h = (ServerInterface) Naming.lookup("rmi://127.0.0.1:7000/SERVER");
            } catch (InterruptedException e) {
                /*exit*/
            } catch (RemoteException | MalformedURLException | NotBoundException e){
                /*Try new connection in 2 seconds*/
            }
            tries++;
        }
    }

    //====================================MAIN==========================================================================

    public static void main(String[] args) {
        HAClient ha = new HAClient();
    }
}
