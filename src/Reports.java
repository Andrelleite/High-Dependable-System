import java.io.Serializable;

public class Reports implements Serializable {

    private ClientInterface c;
    private String username;
    private int posX;
    private int posY;
    private int epoch;

    public Reports(ClientInterface cl, int x, int y, int ep,String user){
        this.c = cl;
        this.posX = x;
        this.posY = y;
        this.epoch = ep;
        this.username = user;
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

}
