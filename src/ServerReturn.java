import java.io.Serializable;
import java.util.ArrayList;

public class ServerReturn implements Serializable {

    private String serverProof;
    private ArrayList<Report> reports;


    public ServerReturn(String serverProof, ArrayList<Report> reports) {
        this.serverProof = serverProof;
        this.reports = reports;
    }

    public String getServerProof() {
        return serverProof;
    }

    public ArrayList<Report> getReports() {
        return reports;
    }
}
