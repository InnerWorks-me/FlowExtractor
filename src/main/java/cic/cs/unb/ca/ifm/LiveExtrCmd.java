package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.Sys;
import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.BasicPacketInfo;
import cic.cs.unb.ca.jnetpcap.FlowFeature;
import cic.cs.unb.ca.jnetpcap.FlowGenerator;
import cic.cs.unb.ca.jnetpcap.PacketReader;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import java.io.File;
import java.util.ArrayList;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.List;
import java.util.Scanner;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import swing.common.SwingUtils;
import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.PcapIfWrapper;
import cic.cs.unb.ca.jnetpcap.worker.LoadPcapInterfaceWorker;
import cic.cs.unb.ca.jnetpcap.worker.TrafficFlowWorker;
import java.awt.event.ActionEvent;
import java.beans.PropertyChangeEvent;
import javax.swing.SwingWorker;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.PcapIf;
import swing.common.TextFileFilter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;




public class LiveExtrCmd {
    public static final Logger logger = LoggerFactory.getLogger(Cmd.class);


    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Please specify a command.");
            System.exit(1);
        }

        LiveFlowExtractor flowExtractor = new LiveFlowExtractor();
        Scanner scanner = new Scanner(System.in);

        String command = args[0];
        switch (command) {
            case "start":
                if (args.length < 2) {
                    System.err.println("Please specify a network interface."); 
                    System.exit(1);
                }
                String ifName = args[1];
                flowExtractor.start(ifName);
                    // Console loop to keep the program running.
                while (flowExtractor.running) {
                }
                //break;

            case "stop":
                flowExtractor.stop();
                break;

            default:
                System.err.println("Unknown command: " + command);
                System.exit(1);
        }
    }

    static class LiveFlowExtractor {
        private TrafficFlowWorker mWorker;
        private String path;
        private ExecutorService csvWriterThread;
        public boolean running;

        public LiveFlowExtractor() {
            init();
            // Your initialization logic here.
            this.path = FlowMgr.getInstance().getAutoSaveFile();
            System.out.println(path);
        }

        private void init() {
            csvWriterThread = Executors.newSingleThreadExecutor();
        }

        public void destroy() {
            csvWriterThread.shutdown();
        }

        public void start(String ifName) {
            if (mWorker != null && !mWorker.isCancelled()) {
                System.out.println("A worker is already running.");
                return;
            }
            
            mWorker = new TrafficFlowWorker(ifName);
            mWorker.addPropertyChangeListener(event -> {
                TrafficFlowWorker task = (TrafficFlowWorker)event.getSource();
                
                if ("progress".equals(event.getPropertyName())) {
                    System.out.println((String)event.getNewValue());
                } else if ("flow".equalsIgnoreCase(event.getPropertyName())) {
                    System.out.println("inserting flow");
                    insertFlow((BasicFlow)event.getNewValue());
                } else if ("state".equals(event.getPropertyName())) {
                    System.out.println(task);
                    switch (task.getState()) {
                        case DONE:
                            try {
                                //System.out.println((String)task.get());
                                System.out.println("done");
                                this.running=false;
                            } catch (CancellationException e) {
                                System.out.println("Pcap stop listening");
                            }
                            /* } catch (InterruptedException|java.util.concurrent.ExecutionException e) {
                                e.printStackTrace();
                            }  */
                            break;
                    } 
                } 
            });
            mWorker.execute();
            this.running = true;
        }

        public void stop() {
            if (mWorker != null) {
                mWorker.cancel(true);
            }
            this.running = false;
            destroy();
        }

        private void insertFlow(BasicFlow flow) {
            List<String> flowStringList = new ArrayList<>();
            String flowDump = flow.dumpFlowBasedFeaturesEx();
            flowStringList.add(flowDump);
            
            String header = FlowFeature.getHeader();
            String path = FlowMgr.getInstance().getSavePath();
            String filename = LocalDate.now().toString() + "_Flow.csv"; //ODO sub with ip here
            this.csvWriterThread.execute((Runnable)new InsertCsvRow(header, flowStringList, path, filename));
        }
    }

}