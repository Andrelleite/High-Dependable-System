import java.io.Serializable;
import java.util.ArrayList;

public class ServerReturn implements Serializable {

    private String serverProof;
    private int rid;
    private ArrayList<Report> reports;


    public ServerReturn(String serverProof, ArrayList<Report> reports, int id) {
        this.serverProof = serverProof;
        this.reports = reports;
        this.rid = id;
    }

    public String getServerProof() {
        return serverProof;
    }

    public ArrayList<Report> getReports() {
        return reports;
    }

    public int getRid(){ return this.rid; }


}
