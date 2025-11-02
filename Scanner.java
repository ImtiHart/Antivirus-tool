/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package AntiVirus;

import java.io.*;
import java.security.MessageDigest;
import java.util.*;
import javax.swing.*;
import javax.swing.table.*;
import java.nio.file.Files;
import java.awt.event.*;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.Date;
import java.util.Random;
import java.time.LocalTime;
import java.util.Formatter;

public class Scanner extends javax.swing.JFrame {

    /**
     * Creates new form Logs
     */
    // === Data structures ===
    private List<File> filesToScan = new ArrayList<File>();
    private Map<String, Set<String>> knownBadHashes = new HashMap<String, Set<String>>();

    // counters and model
    private int scannedFiles = 0;
    private int threatsFound = 0;
    private DefaultTableModel tableModel;

    // SwingWorker for background scanning
    private SwingWorker<Void, ScanResult> scanWorker;

    // Pause/Resume synchronization
    private volatile boolean paused = false;
    private final Object pauseLock = new Object();

    // Quarantine manager instance (created but not shown until user opens the UI)
    private QuarantineManager quarantineManager = null;

    // Database integration - ADDED
    private DatabaseHelper dbHelper;
    private int currentScanId = -1;
    private long scanStartTime;
    private String currentScanType = "quick";
    private String currentScanPath = "";
    
    private long totalSizeGlobal;
    private String statusGlobal = "cancelled";

    // suspicious extensions (backup)
    private LinkedList<String> suspiciousExt = new LinkedList<String>(Arrays.asList(
            ".exe", ".dll", ".scr", ".bat", ".vbs", ".js", ".ps1", ".msi", ".sh", ".jar",".zip",".docm",".dotm",".xlsm",".xltm",".potm",".ppsm",".pptm",".img",".iso"));
    
    public Scanner() {
        initComponents();
        initScanner();
        initDatabase();
        testDatabaseConnection();// ADDED
        
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Scanner.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Scanner.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Scanner.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Scanner.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        
        String currentDir = System.getProperty("user.dir");
        
        
        String dirPath = currentDir + File.separator + "settings";

        // Create a File object representing the directory
        File directory = new File(dirPath);

        // Attempt to create the directory
        boolean dirCreated = directory.mkdir();
        
        enableSettings();
    }

    // === Initialize database - ADDED ===
    private void initDatabase() {
        dbHelper = new DatabaseHelper();
        if (!dbHelper.isConnected()) {
            JOptionPane.showMessageDialog(this, 
                "Database not connected. Scan results will not be saved.\n" +
                "Please check your MySQL configuration.", 
                "Database Warning", 
                JOptionPane.WARNING_MESSAGE);
        }
        
        // Add window listener to close database connection
        this.addWindowListener(new java.awt.event.WindowAdapter() {
            @Override
            public void windowClosing(java.awt.event.WindowEvent windowEvent) {
                cleanup();
            }
        });
    }
    
    private void testDatabaseConnection() {
        if (dbHelper.isConnected()) {
            System.out.println("✅ Connected to phpMyAdmin database!");

            // Test insert
            int testId = dbHelper.saveScanSummary("test", "/test/path", "test_file.txt", 
                10, 2, "complete", 1024, 5);

            if (testId != -1) {
                System.out.println("✅ Test data inserted successfully! Scan ID: " + testId);

                // You can now check phpMyAdmin to see this record
                JOptionPane.showMessageDialog(this, 
                    "Database test successful!\n" +
                    "Check phpMyAdmin → antivirus_db → scan_logs\n" +
                    "Look for scan ID: " + testId);
            }
        } else {
            JOptionPane.showMessageDialog(this, 
                "❌ Cannot connect to database!\n" +
                "Check:\n" +
                "1. MySQL service is running\n" +
                "2. Database 'antivirus_db' exists\n" +
                "3. Username/password is correct");
        }
    }
    // === Cleanup resources - ADDED ===
    private void cleanup() {
        if (dbHelper != null) {
            dbHelper.close();
        }
        if (scanWorker != null && !scanWorker.isDone()) {
            scanWorker.cancel(true);
        }
    }

    // Initialize scanner logic
    // === initialization of scanning logic ===
    private void initScanner() {
        // load malicious hashes (file in project root or specify absolute path)
        loadMaliciousHashesFromFile("malicious_hashes.txt");

        // table model setup
        tableModel = new DefaultTableModel(
                new Object[]{"File Name", "File Path", "Scan Time", "File State"}, 0
        );
        TableFiles.setModel(tableModel);

        // progress bar defaults
        ProgressBarScanning.setMinimum(0);
        ProgressBarScanning.setValue(0);

        // prepare quarantine manager (kept hidden until user opens it)
        quarantineManager = new QuarantineManager();
        quarantineManager.setVisible(false); // keep hidden; will be shown when user requests

        // ensure Pause button starts disabled until scanning begins
        ButPauseResume.setText("Pause");
        ButPauseResume.setEnabled(false);
    }

    // === load malicious hashes from file ===
    private void loadMaliciousHashesFromFile(String filePath) {
        knownBadHashes.put("SHA256", new HashSet<String>());
        knownBadHashes.put("MD5", new HashSet<String>());
        knownBadHashes.put("SHA1", new HashSet<String>());

        File f = new File(filePath);
        if (!f.exists()) {
            // no hash DB found — continue but warn user
            System.err.println("Warning: malicious_hashes.txt not found at: " + f.getAbsolutePath());
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                String[] parts = line.split("\\s+");
                if (parts.length >= 2) {
                    String type = parts[0].toUpperCase();
                    String hash = parts[1].toLowerCase();
                    if (knownBadHashes.containsKey(type)) {
                        knownBadHashes.get(type).add(hash);
                    }
                }
            }
            System.out.println("Loaded hashes: SHA256=" + knownBadHashes.get("SHA256").size()
                    + " MD5=" + knownBadHashes.get("MD5").size()
                    + " SHA1=" + knownBadHashes.get("SHA1").size());
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Error loading hash database: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // collect files recursively 
    private void collectFiles(File dir) {
        File[] list = dir.listFiles();
        if (list == null) return;
        for (File f : list) {
            if (f.isDirectory()) {
                collectFiles(f);
            } else {
                filesToScan.add(f);
            }
        }
    }

    // compute hash for file (generic) 
    private String computeFileHash(File file, String algorithm) {
        try (InputStream is = new BufferedInputStream(new FileInputStream(file))) {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            byte[] bytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    //  entropy calculation (Shannon) 
    private double calculateEntropy(File file) {
        try (InputStream is = new BufferedInputStream(new FileInputStream(file))) {
            long[] freq = new long[256];
            int read;
            byte[] buf = new byte[8192];
            long total = 0;
            while ((read = is.read(buf)) != -1) {
                for (int i = 0; i < read; i++) {
                    freq[buf[i] & 0xff]++;
                }
                total += read;
            }
            if (total == 0) return 0.0;
            double entropy = 0.0;
            for (int i = 0; i < 256; i++) {
                if (freq[i] == 0) continue;
                double p = (double) freq[i] / total;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
            return entropy; 
        } catch (Exception e) {
            return 0.0;
        }
    }

    //  heuristics: suspicious extension, entropy threshold, size anomalies 
    private boolean heuristicsFlag(File file) {
        String name = file.getName().toLowerCase();
        for (String ext : suspiciousExt) {
            if (name.endsWith(ext)) return true;
        }
        long size = file.length();
        // small executable script files can be suspicious if < 1 KB for some types (tunable)
        if (size > 0 && size < 512) {
            String ext = name.contains(".") ? name.substring(name.lastIndexOf(".")) : "";
            if (ext.equals(".exe") || ext.equals(".dll") || ext.equals(".jar")) {
                return true;
            }
        }
        // high entropy suggests packing/obfuscation — threshold tuned to 7.0 (0-8)
        double entropy = calculateEntropy(file);
        if (entropy >= 7.0) return true;

        return false;
    }

    // === Determine threat type for database - ADDED ===
    private String determineThreatType(File file) {
        // Check known hashes first
        try {
            String md5 = computeFileHash(file, "MD5");
            if (md5.length() > 0 && knownBadHashes.get("MD5").contains(md5)) 
                return "Known Malware (MD5)";
            
            String sha256 = computeFileHash(file, "SHA-256");
            if (sha256.length() > 0 && knownBadHashes.get("SHA256").contains(sha256)) 
                return "Known Malware (SHA256)";
            
            String sha1 = computeFileHash(file, "SHA-1");
            if (sha1.length() > 0 && knownBadHashes.get("SHA1").contains(sha1)) 
                return "Known Malware (SHA1)";
        } catch (Exception e) {
            // ignore hashing errors
        }
        
        // Check heuristics
        if (heuristicsFlag(file)) {
            return "Suspicious (Heuristics)";
        }
        
        return "Unknown Threat";
    }

    // determine file threat (hash + heuristics)
    private boolean isFileThreat(File file) {
        // check known hashes first (faster decision)
        try {
            String md5 = computeFileHash(file, "MD5");
            if (md5.length() > 0 && knownBadHashes.get("MD5").contains(md5)) return true;

            String sha1 = computeFileHash(file, "SHA-1");
            if (sha1.length() > 0 && knownBadHashes.get("SHA1").contains(sha1)) return true;

            String sha256 = computeFileHash(file, "SHA-256");
            if (sha256.length() > 0 && knownBadHashes.get("SHA256").contains(sha256)) return true;
        } catch (Exception e) {
            // ignore hashing errors, fallback to heuristics
        }

        // then heuristics
        return heuristicsFlag(file);
    }

    // start scanning using SwingWorker (background)
    private void startScanning() {
        // reset counters and UI
        scannedFiles = 0;
        threatsFound = 0;
        tableModel.setRowCount(0);
        TextFieldScan.setText("0");
        TextFieldThreats.setText("0");

        if (filesToScan.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No files to scan!");
            return;
        }

        ProgressBarScanning.setMinimum(0);
        ProgressBarScanning.setMaximum(filesToScan.size());
        ProgressBarScanning.setValue(0);

        // enable pause button
        ButPauseResume.setEnabled(true);
        ButPauseResume.setText("Pause");

        // === Database: Record scan start time and save to database - ADDED ===
        scanStartTime = System.currentTimeMillis();
        
        // Calculate total files size
        long totalSize = 0;
        for (File file : filesToScan) {
            totalSize += file.length();
        }
        
        totalSizeGlobal = totalSize;
        // Get appropriate file name for the scan
        String scanFileName = "Multiple Files";
        if (!filesToScan.isEmpty()) {
            scanFileName = filesToScan.get(0).getName() + (filesToScan.size() > 1 ? " + " + (filesToScan.size() - 1) + " more" : "");
        }
        
        // Save scan summary to database
        if (dbHelper.isConnected()) {
            currentScanId = dbHelper.saveScanSummary(
                currentScanType,
                currentScanPath,
                scanFileName,
                filesToScan.size(),
                0, // infected files starts at 0
                "running",
                totalSize,
                0 // duration starts at 0
            );
        }

        // create worker
        scanWorker = new SwingWorker<Void, ScanResult>() {
            @Override
            protected Void doInBackground() throws Exception {
                for (int i = 0; i < filesToScan.size(); i++) {
                    // respect cancellation
                    if (isCancelled()) break;

                    // pause support
                    synchronized (pauseLock) {
                        while (paused) {
                            pauseLock.wait();
                        }
                    }

                    File file = filesToScan.get(i);

                    // compute threat (hash + heuristics)
                    boolean threat = isFileThreat(file);

                    scannedFiles++;
                    if (threat) threatsFound++;

                    String time = new SimpleDateFormat("HH:mm:ss").format(new Date());
                    String status = threat ? "Threat" : "Clean";

                    // publish result to EDT
                    publish(new ScanResult(file.getName(), file.getAbsolutePath(), time, status));

                    // === Database: Save to database if connected - ADDED ===
                    if (dbHelper.isConnected() && currentScanId != -1) {
                        String threatType = threat ? determineThreatType(file) : null;
                        Date detectionTime = threat ? new Date() : null;
                        dbHelper.saveFileScanResult(
                            currentScanId,
                            file.getName(),
                            file.getAbsolutePath(),
                            threatType,
                            status,
                            detectionTime
                        );
                    }

                    // if threat, add to quarantine manager
                    if (threat) {
                        try {
                            if (quarantineManager == null) {
                                quarantineManager = new QuarantineManager();
                                quarantineManager.setVisible(false);
                            }
                            quarantineManager.incrementScannedCount(); // ensure summary is aware
                            quarantineManager.addThreatFile(file.getName(), file.getAbsolutePath());
                        } catch (Exception ex) {
                            // ignore UI errors from quarantine manager
                        }
                    } else {
                        // ensure scanned counter is forwarded even for clean files
                        try {
                            if (quarantineManager != null) quarantineManager.incrementScannedCount();
                        } catch (Exception ignored) {}
                    }

                    // Update progress property (0-100)
                    setProgress((int) ((scannedFiles * 100L) / filesToScan.size()));
                }
                return null;
            }

            @Override
            protected void process(List<ScanResult> chunks) {
                // runs on EDT - update table and widgets
                for (ScanResult r : chunks) {
                    tableModel.addRow(new Object[]{r.fileName, r.filePath, r.scanTime, r.status});
                }
                TextFieldScan.setText(String.valueOf(scannedFiles));
                TextFieldThreats.setText(String.valueOf(threatsFound));
                ProgressBarScanning.setValue(scannedFiles);
            }

            @Override
            protected void done() {
                // === Database: Calculate scan duration and update database - ADDED ===
                long scanDuration = (System.currentTimeMillis() - scanStartTime) / 1000;
                
                // Update scan summary in database
                if (dbHelper.isConnected() && currentScanId != -1) {
                    String status = isCancelled() ? "canceled" : "complete";
                    statusGlobal = status;
                    dbHelper.updateScanSummary(currentScanId, scannedFiles, threatsFound, status, (int)scanDuration);
                }
                
                if (isCancelled()) {
                    JOptionPane.showMessageDialog(Scanner.this, "Scan stopped.");
                } else {
                    JOptionPane.showMessageDialog(Scanner.this, 
                        "Scan completed!\n" +
                        "Files scanned: " + scannedFiles + "\n" +
                        "Threats found: " + threatsFound + "\n" +
                        "Duration: " + scanDuration + " seconds");
                    logCreation();
                }
                ButPauseResume.setEnabled(false);
                ButPauseResume.setText("Pause");
            }
        };

        // listen to progress property for potential UI binding
        scanWorker.addPropertyChangeListener(evt -> {
            if ("progress".equals(evt.getPropertyName())) {
                // could map to a determinate progress bar (percentage) if desired
            }
        });

        scanWorker.execute();
    }

    // stop/cancel scanning
    private void stopScanning() {
        if (scanWorker != null && !scanWorker.isDone()) {
            scanWorker.cancel(true);
        }
        // reset pause state
        paused = false;
        synchronized (pauseLock) {
            pauseLock.notifyAll();
        }
        ButPauseResume.setEnabled(false);
        ButPauseResume.setText("Pause");
    }

    // === Pause/Resume toggle ===
    private void togglePauseResume() {
        if (scanWorker == null) return; // nothing to pause
        if (!paused) {
            paused = true;
            ButPauseResume.setText("Resume");
        } else {
            synchronized (pauseLock) {
                paused = false;
                pauseLock.notifyAll();
            }
            ButPauseResume.setText("Pause");
        }
    }

    // === helper class for publish/process ===
    private static class ScanResult {
        final String fileName, filePath, scanTime, status;
        ScanResult(String a, String b, String c, String d) { fileName=a; filePath=b; scanTime=c; status=d; }
    }
    
    // === Settings instantiated ===
    
    private void enableSettings(){
        LinkedList<String> extentions = new LinkedList<String>();
        File settingsFile = new File("settings" + File.separator + "Settings.txt");
        
        if(!settingsFile.exists() || settingsFile.length() == 0){
            try {
                FileWriter fwc = new FileWriter("settings" + File.separator + "Settings.txt");
                
                
                for (String x: suspiciousExt){
                    fwc.write("T\n");
                }
                
                fwc.close();
            } catch (IOException ex) {
                System.getLogger(Scanner.class.getName()).log(System.Logger.Level.ERROR, (String) null, ex);
            }
        } else {
            try (BufferedReader read = new BufferedReader(new FileReader(settingsFile.getAbsolutePath()))){
                String textLine;
                boolean tamp = false;
                for (String x : suspiciousExt){
                    textLine = read.readLine();
                    
                    if (textLine.equals("T")) {
                        extentions.add(x);
                    } else if (textLine.equals("F")){
                        
                    } else {
                        JOptionPane.showMessageDialog(null, "File tampered with. Default settings enabled");
                        tamp = true;
                        break;
                    }
                }
                
                if (tamp) {
                    
                } else {
                    suspiciousExt = extentions;
                    System.out.println("Ext Settings En");
                }
                
               read.close();
               System.out.println("Settings Established");
                
            } catch (IOException e){
                System.out.println("Error Reading");
            }
        } 
    }
    
    private void logCreation(){
        
        LocalTime timeS = LocalTime.now();
        LocalDate timeD = LocalDate.now();
        String TD = "" + timeD;
        String TP = "" + timeS;
        String aPath = currentScanPath;
        String fileName = aPath.substring(aPath.lastIndexOf("\\") + 1, aPath.length());
        int scannedFilesNum = scannedFiles;
        int infecFiles = threatsFound;
        String status = statusGlobal;
        String scanType = currentScanType;
        long filesSize = totalSizeGlobal;
        long duration =  (System.currentTimeMillis() - scanStartTime) / 1000;
        
        
        try {
            FileWriter fw = new FileWriter("logs" + File.separator + "Master Log.txt",true);
            FileWriter fw2 = new FileWriter("logs" + File.separator + "Recent Log.txt",true);
            StringBuilder lg = new StringBuilder();
            Formatter formatLog = new Formatter(lg);
            formatLog.format("\n\nDate: %s\nTime Stamp: %s\nAbsolute Path: %s\nFolder Name: %s\nScanned Files: %d"
                    + "\nInfected Files: %d\nStatus: %s\nScan Type: %s\nTotal Files Size: %d"
                    + "\nScan Duration: %d",TD, TP,aPath,fileName,scannedFiles,threatsFound,status,scanType,filesSize,duration);
            
            fw.append("" + lg);
            fw.close();
            
            fw2 = new FileWriter("logs" + File.separator + "Recent Log.txt",true);
            fw2.append("" + lg);
            fw2.close();
        } catch (IOException e){
            System.out.println("Log Error");
        }
       
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        ButCustomScan = new javax.swing.JButton();
        ButFullScan = new javax.swing.JButton();
        ButStartScanning = new javax.swing.JButton();
        ButStopScanning = new javax.swing.JButton();
        jButton5 = new javax.swing.JButton();
        ButQuarantine = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        ProgressBarScanning = new javax.swing.JProgressBar();
        jLabel3 = new javax.swing.JLabel();
        jSeparator1 = new javax.swing.JSeparator();
        jLabel4 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        TableFiles = new javax.swing.JTable();
        ButExit = new javax.swing.JButton();
        ButBack = new javax.swing.JButton();
        TextFieldThreats = new javax.swing.JTextField();
        TextFieldScan = new javax.swing.JTextField();
        ButPauseResume = new javax.swing.JButton();
        jLabel5 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jPanel1.setBackground(new java.awt.Color(0, 16, 68));

        jLabel1.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        jLabel1.setForeground(new java.awt.Color(153, 153, 153));
        jLabel1.setText("Scan Type:");

        ButCustomScan.setBackground(new java.awt.Color(0, 0, 51));
        ButCustomScan.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        ButCustomScan.setForeground(new java.awt.Color(255, 255, 255));
        ButCustomScan.setText("Custom");
        ButCustomScan.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ButCustomScanActionPerformed(evt);
            }
        });

        ButFullScan.setBackground(new java.awt.Color(0, 0, 51));
        ButFullScan.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        ButFullScan.setForeground(new java.awt.Color(255, 255, 255));
        ButFullScan.setText("Full");
        ButFullScan.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ButFullScanActionPerformed(evt);
            }
        });

        ButStartScanning.setBackground(new java.awt.Color(0, 0, 51));
        ButStartScanning.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        ButStartScanning.setForeground(new java.awt.Color(255, 255, 255));
        ButStartScanning.setText("Start");
        ButStartScanning.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ButStartScanningActionPerformed(evt);
            }
        });

        ButStopScanning.setBackground(new java.awt.Color(0, 0, 51));
        ButStopScanning.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        ButStopScanning.setForeground(new java.awt.Color(255, 255, 255));
        ButStopScanning.setText("Stop");
        ButStopScanning.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ButStopScanningActionPerformed(evt);
            }
        });

        jButton5.setBackground(new java.awt.Color(0, 0, 51));
        jButton5.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        jButton5.setForeground(new java.awt.Color(255, 255, 255));
        jButton5.setText("Logs");
        jButton5.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jButton5MouseClicked(evt);
            }
        });

        ButQuarantine.setBackground(new java.awt.Color(0, 0, 51));
        ButQuarantine.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        ButQuarantine.setForeground(new java.awt.Color(255, 255, 255));
        ButQuarantine.setText("Quarantine");
        ButQuarantine.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ButQuarantineActionPerformed(evt);
            }
        });

        jLabel2.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(153, 153, 153));
        jLabel2.setText("Scanning Status");

        ProgressBarScanning.setBackground(new java.awt.Color(102, 102, 102));

        jLabel3.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(153, 153, 153));
        jLabel3.setText("Files Scanned");

        jLabel4.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        jLabel4.setForeground(new java.awt.Color(153, 153, 153));
        jLabel4.setText("Threats");

        TableFiles.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        TableFiles.setForeground(new java.awt.Color(102, 102, 102));
        TableFiles.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "File Name", "File Path", "Scan Time", "File State"
            }
        ));
        jScrollPane1.setViewportView(TableFiles);

        ButExit.setBackground(new java.awt.Color(0, 0, 51));
        ButExit.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        ButExit.setForeground(new java.awt.Color(255, 255, 255));
        ButExit.setText("Exit");
        ButExit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ButExitActionPerformed(evt);
            }
        });

        ButBack.setBackground(new java.awt.Color(0, 0, 51));
        ButBack.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        ButBack.setForeground(new java.awt.Color(255, 255, 255));
        ButBack.setText("Back");
        ButBack.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ButBackActionPerformed(evt);
            }
        });

        TextFieldThreats.setEditable(false);
        TextFieldThreats.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        TextFieldThreats.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                TextFieldThreatsActionPerformed(evt);
            }
        });

        TextFieldScan.setEditable(false);
        TextFieldScan.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        TextFieldScan.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                TextFieldScanActionPerformed(evt);
            }
        });

        ButPauseResume.setBackground(new java.awt.Color(0, 0, 51));
        ButPauseResume.setFont(new java.awt.Font("Microsoft YaHei UI", 0, 12)); // NOI18N
        ButPauseResume.setForeground(new java.awt.Color(255, 255, 255));
        ButPauseResume.setText("Pause/Resume");
        ButPauseResume.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ButPauseResumeActionPerformed(evt);
            }
        });

        jLabel5.setFont(new java.awt.Font("Microsoft YaHei UI", 1, 36)); // NOI18N
        jLabel5.setForeground(new java.awt.Color(255, 255, 255));
        jLabel5.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel5.setText("Scanner");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                .addGap(0, 21, Short.MAX_VALUE)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(108, 108, 108))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addComponent(ButBack)
                        .addGap(18, 18, 18)
                        .addComponent(ButExit)
                        .addContainerGap())
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 691, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(16, 16, 16))))
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(297, 297, 297)
                        .addComponent(jButton5)
                        .addGap(27, 27, 27)
                        .addComponent(ButQuarantine)
                        .addGap(34, 34, 34)
                        .addComponent(ButPauseResume))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(33, 33, 33)
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(ProgressBarScanning, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addGroup(jPanel1Layout.createSequentialGroup()
                                                .addGap(36, 36, 36)
                                                .addComponent(jLabel3)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(TextFieldScan, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addGap(179, 179, 179)
                                                .addComponent(jLabel4)
                                                .addGap(18, 18, 18)
                                                .addComponent(TextFieldThreats, javax.swing.GroupLayout.PREFERRED_SIZE, 49, javax.swing.GroupLayout.PREFERRED_SIZE))
                                            .addGroup(jPanel1Layout.createSequentialGroup()
                                                .addComponent(ButStartScanning)
                                                .addGap(28, 28, 28)
                                                .addComponent(ButStopScanning))
                                            .addComponent(jLabel2))
                                        .addGroup(jPanel1Layout.createSequentialGroup()
                                            .addComponent(ButCustomScan)
                                            .addGap(387, 387, 387)))
                                    .addComponent(ButFullScan, javax.swing.GroupLayout.PREFERRED_SIZE, 75, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(0, 0, Short.MAX_VALUE)))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addComponent(jLabel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 63, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(16, 16, 16)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(ButCustomScan)
                    .addComponent(jLabel1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(ButFullScan)
                .addGap(30, 30, 30)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(ButStartScanning)
                    .addComponent(ButStopScanning)
                    .addComponent(jButton5)
                    .addComponent(ButQuarantine)
                    .addComponent(ButPauseResume))
                .addGap(18, 18, 18)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(ProgressBarScanning, javax.swing.GroupLayout.PREFERRED_SIZE, 17, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(jLabel4)
                    .addComponent(TextFieldThreats, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(TextFieldScan, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(2, 2, 2)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(88, 88, 88)
                        .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 324, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 29, Short.MAX_VALUE)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(ButExit)
                    .addComponent(ButBack))
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void ButExitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ButExitActionPerformed
        cleanup(); // ADDED: Cleanup database connection
        System.exit(0);
        stopScanning();
    }//GEN-LAST:event_ButExitActionPerformed

    private void ButCustomScanActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ButCustomScanActionPerformed
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selectedDir = chooser.getSelectedFile();
            filesToScan.clear();
            collectFiles(selectedDir);
            currentScanType = "custom"; // ADDED: Set scan type for database
            currentScanPath = selectedDir.getAbsolutePath(); // ADDED: Set scan path for database
            JOptionPane.showMessageDialog(this,
                    "Custom scan started on: " + selectedDir.getAbsolutePath() +
                            "\nFiles found: " + filesToScan.size());
            startScanning();
        }
    }//GEN-LAST:event_ButCustomScanActionPerformed

    private void ButBackActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ButBackActionPerformed
        cleanup(); // ADDED: Cleanup database connection
        Back();
    }//GEN-LAST:event_ButBackActionPerformed

    private void ButStartScanningActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ButStartScanningActionPerformed
        if (filesToScan.isEmpty()) {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                File selectedDir = chooser.getSelectedFile();
                filesToScan.clear();
                collectFiles(selectedDir);
                currentScanType = "quick"; // ADDED: Set scan type for database
                currentScanPath = selectedDir.getAbsolutePath(); // ADDED: Set scan path for database
            } else {
                return;
            }
        }
        startScanning();
    }//GEN-LAST:event_ButStartScanningActionPerformed

    private void ButStopScanningActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ButStopScanningActionPerformed
        // TODO add your handling code here:
        stopScanning();
    }//GEN-LAST:event_ButStopScanningActionPerformed

    private void ButFullScanActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ButFullScanActionPerformed
        filesToScan.clear();
        File root = new File("C:/");
        if (!root.exists()) root = new File("/"); // fallback for Linux/Mac
        collectFiles(root);
        currentScanType = "full"; // ADDED: Set scan type for database
        currentScanPath = root.getAbsolutePath(); // ADDED: Set scan path for database
        JOptionPane.showMessageDialog(this,
                "Full scan started.\nFiles found: " + filesToScan.size());
        startScanning();

    }//GEN-LAST:event_ButFullScanActionPerformed

    private void TextFieldScanActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TextFieldScanActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_TextFieldScanActionPerformed

    private void TextFieldThreatsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TextFieldThreatsActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_TextFieldThreatsActionPerformed

    private void ButPauseResumeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ButPauseResumeActionPerformed
        // TODO add your handling code here:
        togglePauseResume();
    }//GEN-LAST:event_ButPauseResumeActionPerformed

    private void ButQuarantineActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ButQuarantineActionPerformed
        // TODO add your handling code here:
        // Show quarantine window (if created, bring to front)
        if (quarantineManager == null) quarantineManager = new QuarantineManager();
        quarantineManager.setVisible(true);
        quarantineManager.toFront();
        this.dispose();
        //QuarantineManager();
    }//GEN-LAST:event_ButQuarantineActionPerformed

    private void jButton5MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jButton5MouseClicked
       Log obj = new Log();
       obj.setVisible(true);
       cleanup();
       this.dispose();
    }//GEN-LAST:event_jButton5MouseClicked
     

    
     /*void QuarantineManager(){
        QuarantineManager quarantineManager=new QuarantineManager();
        quarantineManager.setVisible(true);
        this.dispose();
        
     }*/
     
     void Back(){
        try {
            MainPage mainPage = new MainPage();
            mainPage.setVisible(true);
            this.dispose();
        } catch (Exception e) {
            // if MainPage isn't used, just hide
            this.setVisible(false);
        }
        
     }
     
    /**
     * @param args the command line arguments
     */
//    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        
        /*
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Scanner.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Scanner.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Scanner.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Scanner.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        */
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        /*
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Scanner().setVisible(true);
            }
        });
*/
//    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton ButBack;
    private javax.swing.JButton ButCustomScan;
    private javax.swing.JButton ButExit;
    private javax.swing.JButton ButFullScan;
    private javax.swing.JButton ButPauseResume;
    private javax.swing.JButton ButQuarantine;
    private javax.swing.JButton ButStartScanning;
    private javax.swing.JButton ButStopScanning;
    private javax.swing.JProgressBar ProgressBarScanning;
    public javax.swing.JTable TableFiles;
    private javax.swing.JTextField TextFieldScan;
    private javax.swing.JTextField TextFieldThreats;
    private javax.swing.JButton jButton5;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSeparator jSeparator1;
    // End of variables declaration//GEN-END:variables
}
