import java.io.Serializable;

public class Report implements Serializable {

    private ClientInterface c;
    private String username;
    private String userSignature;
    private String witness;
    private String witnessSignature;
    private int posX;
    private int posY;
    private int epoch;
    private String timeStamp;
    private String witnessTimeStamp;

    public Report(ClientInterface cl, int x, int y, int ep, String user,String userSignature,String timeStamp, String witness, String witnessSignature, String witnessTimeStamp){
        this.c = cl;
        this.posX = x;
        this.posY = y;
        this.epoch = ep;
        this.username = user;
        this.userSignature = userSignature;
        this.timeStamp = timeStamp;
        this.witness = witness;
        this.witnessSignature = witnessSignature;
        this.witnessTimeStamp = witnessTimeStamp;
    }

    public ClientInterface getC() {
        return this.c;
    }

    public int getPosX() {
        return this.posX;
    }

    public int getPosY() {
        return this.posY;
    }

    public int getEpoch() {
        return this.epoch;
    }

    public String getUsername() {return this.username;}

    public void setPosX(int posX) {
        this.posX = posX;
    }

    public void setPosY(int posY) {
        this.posY = posY;
    }

    public String getWitness() {
        return witness;
    }

    public String getWitnessSignature() {
        return witnessSignature;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public String getUserSignature() {
        return userSignature;
    }

    public String getWitnessTimeStamp() {
        return witnessTimeStamp;
    }

    public void setUserSignature(String userSignature) {
        this.userSignature = userSignature;
    }

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }
}
