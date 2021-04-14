/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.*;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

/**
 * Final Version
 * @author AndreLl
 */

public interface ServerInterface extends Remote, Serializable {

    public void subscribe(ClientInterface c, String user, String key) throws RemoteException;
    public String echo(String message) throws RemoteException;
    public String submitLocationReport(ClientInterface c,String user, Report locationReport) throws RemoteException, InterruptedException;
    public ServerReturn obtainLocationReport(ClientInterface c, String epoch,String username) throws IOException, ClassNotFoundException, InterruptedException;
    public ServerReturn obtainLocationReport(String user, String epoch) throws IOException, ClassNotFoundException, InterruptedException;
    public ServerReturn obtainUsersAtLocation(String pos, String epoch) throws IOException, ClassNotFoundException, InterruptedException;

}
