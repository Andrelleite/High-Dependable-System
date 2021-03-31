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

    protected void makeConnection(){

        try {
            try{
                Report n = new Report(this,10,20,2,"user5","user2","bllalalalla");
                ServerInterface server = (ServerInterface) Naming.lookup("rmi://127.0.0.1:" + 7000 + "/SERVER");
                server.submitLocationReport(this,"user3",n);
            }catch (UnmarshalException | ConnectException e) {
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
