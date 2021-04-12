/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.*;
import java.rmi.*;
import java.rmi.server.UnicastRemoteObject;
import java.util.*;

/**
 * Final Version
 * @author AndreLl
 * @author Joao
 */


public class ClientTest extends UnicastRemoteObject implements ClientInterface {

    private static final long serialVersionUID = 1L;
    public static int GRIDDIMENISION = 40;

    private String username;
    private ClientInterface clientInterface;
    private int coordinate1;
    private int coordinate2;
    private int epoch;
    private int hasError = 0;
    private Map<Integer, Pair<Integer,Integer>> moveList = new HashMap<Integer, Pair<Integer,Integer>>();
    private List<String> clientsWithError = new ArrayList<String>();

    //===================CONSTRUTCTOR===================================================================================


    public ClientTest() throws RemoteException {
        super();
        this.username = "user1";
    }

    //=======================METHODS====================================================================================

    public void getReports() throws RemoteException{

    };

    protected void makeConnection(){

        try {
            try{
                String user = "user4";
                String witness = "user3";
                Report n = new Report(this,23,37,0,user,"",witness,"Signature","","","");
                ServerInterface server = (ServerInterface) Naming.lookup("rmi://127.0.0.1:" + 7000 + "/SERVER");
                server.subscribe(this,user,"");
                server.submitLocationReport(this,user,n);

                ServerReturn s = server.obtainLocationReport("user1","0");
                System.out.println("bruhhhh + " + s.getServerProof());
                ArrayList<Report> reports = s.getReports();
                if(reports != null){
                    for(int i = 0; i < reports.size(); i++){
                        System.out.println("\tENTRY "+(i+1)+": "+reports.get(i).getUsername());
                    }
                }else{
                    System.out.println("No entries for that combination.");
                }
            }catch (UnmarshalException | ConnectException e) {
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        } catch (IOException | NotBoundException e) {
            System.out.println("Exception in RMIClient main: " + e);
        }
    }

    public String getUsername() throws RemoteException{
        return this.username;
    }

    @Override
    public String echo(String message) throws RemoteException {
        return null;
    }

    @Override
    public Report generateLocationReportWitness(ClientInterface c, String username, int userEpoch) throws RemoteException {
        return null;
    }

    //======================MAIN========================================================================================

    /**
     *  Inicia o cliente e a conexão ao RMI server.
     * @param args
     * @throws IOException
     * @throws NotBoundException
     * @throws ClassNotFoundException
     */
    public static void main(String args[]) throws RemoteException {
        ClientTest me = new ClientTest();
        me.makeConnection();
    }


}
