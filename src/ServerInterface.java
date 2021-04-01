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

    public void subscribe(ClientInterface c, String user) throws RemoteException;
    public String echo(String message) throws RemoteException;
    public String submitLocationReport(ClientInterface c,String user, Report locationReport) throws RemoteException;
    public List<Report> obtainLocationReport(ClientInterface c, int epoch) throws IOException, ClassNotFoundException;
    public List<Report> obtainLocationReport(String user, int epoch) throws IOException, ClassNotFoundException;
    public List<Report> obtainUsersAtLocation(int[] pos, int epoch) throws IOException, ClassNotFoundException;

}
