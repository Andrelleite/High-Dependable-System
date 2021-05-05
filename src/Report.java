import java.io.Serializable;

public class Report implements Serializable {

    private ClientInterface c;
    private String username;
    private long serverId;
    private String userSignature;
    private String witness;
    private String witnessSignature;
    private int posX;
    private int posY;
    private int epoch;
    private String encryptedInfo;
    private int Nonce;
    private int witnessNonce;
    private String timeStamp;
    private String witnessTimeStamp;
    private String witnessPos;
    private int posXWitness;
    private int posYWitness;

    public Report(ClientInterface cl, int x, int y, int ep, String user, String userSignature, int Nonce, String timeStamp, String witness, String witnessSignature, int witnessNonce,String witnessTimeStamp , String witnessPos, long serverId) {
        this.c = cl;
        this.posX = x;
        this.posY = y;
        this.epoch = ep;
        this.username = user;
        this.userSignature = userSignature;
        this.timeStamp = timeStamp;
        this.Nonce = Nonce;
        this.witness = witness;
        this.witnessSignature = witnessSignature;
        this.witnessNonce = witnessNonce;
        this.witnessTimeStamp = witnessTimeStamp;
        this.witnessPos = witnessPos;
        this.serverId = serverId;
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

    public long getServerId() {
        return this.serverId;
    }

    public String getUsername() {
        return this.username;
    }

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

    public int getNonce() {
        return Nonce;
    }

    public String getUserSignature() {
        return userSignature;
    }

    public int getWitnessNonce() {
        return witnessNonce;
    }

    public void setUserSignature(String userSignature) {
        this.userSignature = userSignature;
    }

    public void setNonce(int Nonce) {
        this.Nonce = Nonce;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(String timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getWitnessTimeStamp() {
        return witnessTimeStamp;
    }

    public void setEncryptedInfo(String encryptedInfo) {
        this.encryptedInfo = encryptedInfo;
    }

    public String getEncryptedInfo() {
        return encryptedInfo;
    }

    public void setEpoch(int epoch) {
        this.epoch = epoch;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setWitness(String witness) {
        this.witness = witness;
    }

    public int getPosXWitness() {
        return posXWitness;
    }

    public int getPosYWitness() {
        return posYWitness;
    }

    public void setPosXWitness(int posXWitness) {
        this.posXWitness = posXWitness;
    }

    public void setPosYWitness(int posYWitness) {
        this.posYWitness = posYWitness;
    }

    public String getWitnessPos() {
        return witnessPos;
    }

}
