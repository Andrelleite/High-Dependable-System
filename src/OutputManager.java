import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.io.*;
import java.time.LocalDateTime;


public class OutputManager {

    private String dir;
    private String owner;

    public OutputManager(String filename, String fileOwner){
        this.dir = "output/"+filename+".txt";
        this.owner = fileOwner;
    }

    public void initFile() throws FileNotFoundException, UnsupportedEncodingException {
        PrintWriter writer = new PrintWriter(this.dir, "UTF-8");
        writer.println("=================== "+this.owner+" Output File ===================");
        writer.close();
    }

    public void appendInformation(String line){
        FileWriter fw = null;
        BufferedWriter bw = null;
        PrintWriter out = null;
        LocalDateTime now = LocalDateTime.now();
        String hour = String.valueOf(now.getHour());
        String minute = String.valueOf(now.getMinute());
        String second = String.valueOf(now.getSecond());
        try {
            fw = new FileWriter(this.dir, true);
            bw = new BufferedWriter(fw);
            out = new PrintWriter(bw);
            out.println(hour+":"+minute+":"+second+" -> "+line);
            out.close();
        } catch (IOException e) {
            /*Handler for exception*/
        }
        finally {
            if(out != null)
                out.close();
            try {
                if(bw != null)
                    bw.close();
            } catch (IOException e) {
                /*Handler for exception*/
            }
            try {
                if(fw != null)
                    fw.close();
            } catch (IOException e) {
                /*Handler for exception*/
            }
        }
    }

}