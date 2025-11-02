/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package AntiVirus;

import java.sql.*;
import javax.swing.JOptionPane;

public class DatabaseHelper {
    private static final String URL = "jdbc:mysql://localhost:3306/antivirus_db";
    private static final String USER = "root"; // Change as needed
    private static final String PASSWORD = ""; // Change as needed
    
    private Connection connection;
    
    public DatabaseHelper() {
        initializeDatabase();
    }
    
    private void initializeDatabase() {
        try {
            // Load JDBC driver
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(URL, USER, PASSWORD);
            initializeTables();
        } catch (ClassNotFoundException e) {
            JOptionPane.showMessageDialog(null, 
                "MySQL JDBC Driver not found. Please add MySQL Connector/J to your project libraries.\n" + 
                "Download from: https://dev.mysql.com/downloads/connector/j/");
        } catch (SQLException e) {
            JOptionPane.showMessageDialog(null, 
                "Database connection failed: " + e.getMessage() + 
                "\nPlease ensure MySQL is running and database 'antivirus_db' exists.");
        }
    }
    
    private void initializeTables() {
        try (Statement stmt = connection.createStatement()) {
            // Create scan_logs table
            String scanLogsTable = "CREATE TABLE IF NOT EXISTS scan_logs (" +
                "id INT AUTO_INCREMENT PRIMARY KEY, " +
                "file_path VARCHAR(500) NOT NULL, " +
                "file_name VARCHAR(255) NOT NULL, " +
                "scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "scanned_files INT DEFAULT 0, " +
                "infected_files INT DEFAULT 0, " +
                "status ENUM('running', 'complete', 'failed', 'canceled') DEFAULT 'running', " +
                "threat_type VARCHAR(100), " +
                "detection_time TIMESTAMP NULL, " +
                "scan_type ENUM('quick', 'full', 'custom') DEFAULT 'quick', " +
                "total_files_size BIGINT DEFAULT 0, " +
                "scan_duration INT DEFAULT 0, " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)";
            stmt.execute(scanLogsTable);
            
            // Create file_scan_results table
            String fileResultsTable = "CREATE TABLE IF NOT EXISTS file_scan_results (" +
                "id INT AUTO_INCREMENT PRIMARY KEY, " +
                "scan_id INT, " +
                "file_name VARCHAR(255), " +
                "file_path VARCHAR(500), " +
                "threat_type VARCHAR(100), " +
                "status ENUM('Clean', 'Threat'), " +
                "detection_time TIMESTAMP NULL, " +
                "FOREIGN KEY (scan_id) REFERENCES scan_logs(id) ON DELETE CASCADE)";
            stmt.execute(fileResultsTable);
            
            System.out.println("Database tables initialized successfully");
            
        } catch (SQLException e) {
            System.err.println("Error initializing tables: " + e.getMessage());
        }
    }
    
    public int saveScanSummary(String scanType, String filePath, String fileName, int scannedFiles, 
                              int infectedFiles, String status, long totalSize, int duration) {
        if (connection == null) {
            System.err.println("Database connection is not available");
            return -1;
        }
        
        String sql = "INSERT INTO scan_logs (file_path, file_name, scan_type, scanned_files, infected_files, " +
                    "status, total_files_size, scan_duration) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement stmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, filePath);
            stmt.setString(2, fileName);
            stmt.setString(3, scanType);
            stmt.setInt(4, scannedFiles);
            stmt.setInt(5, infectedFiles);
            stmt.setString(6, status);
            stmt.setLong(7, totalSize);
            stmt.setInt(8, duration);
            
            int affectedRows = stmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Creating scan summary failed, no rows affected.");
            }
            
            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            } else {
                throw new SQLException("Creating scan summary failed, no ID obtained.");
            }
        } catch (SQLException e) {
            System.err.println("Error saving scan summary: " + e.getMessage());
            return -1;
        }
    }
    
    public void saveFileScanResult(int scanId, String fileName, String filePath, 
                                  String threatType, String status, java.util.Date detectionTime) {
        if (connection == null || scanId == -1) return;
        
        String sql = "INSERT INTO file_scan_results (scan_id, file_name, file_path, " +
                    "threat_type, status, detection_time) VALUES (?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, scanId);
            stmt.setString(2, fileName);
            stmt.setString(3, filePath);
            stmt.setString(4, threatType);
            stmt.setString(5, status);
            
            if (detectionTime != null) {
                stmt.setTimestamp(6, new Timestamp(detectionTime.getTime()));
            } else {
                stmt.setNull(6, Types.TIMESTAMP);
            }
            
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Error saving file scan result: " + e.getMessage());
        }
    }
    
    public void updateScanSummary(int scanId, int scannedFiles, int infectedFiles, 
                                String status, int duration) {
        if (connection == null || scanId == -1) return;
        
        String sql = "UPDATE scan_logs SET scanned_files = ?, infected_files = ?, " +
                    "status = ?, scan_duration = ?, detection_time = NOW() WHERE id = ?";
        
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, scannedFiles);
            stmt.setInt(2, infectedFiles);
            stmt.setString(3, status);
            stmt.setInt(4, duration);
            stmt.setInt(5, scanId);
            
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Error updating scan summary: " + e.getMessage());
        }
    }
    
    /*
    public void logFromDB(int scanId){
        if (connection == null || scanId == -1) return;
        
        String sql = "UPDATE scan_logs SET scanned_files = ?, infected_files = ?, " +
                    "status = ?, scan_duration = ?, detection_time = NOW() WHERE id = ?";
        
       sql =    "SELECT scan_logs " +
                "FROM information_schema.tables " +
                "WHERE TABLE_SCHEMA = 'antivirus_db' " +
                "ORDER BY UPDATE_TIME DESC " +
                "LIMIT 1;";
       
       String logDataPath = "C:\\Users\\mjacu\\OneDrive\\Documents\\University Folder\\Software Design 2\\Software Design Semester Project\\UTD Build\\Imtiyaaz Build\\Anti-Virus Tool\\logs\\Recent Log.txt";
       
       
    }
    */
    
    
    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                System.out.println("Database connection closed");
            }
        } catch (SQLException e) {
            System.err.println("Error closing database connection: " + e.getMessage());
        }
    }
    
    public boolean isConnected() {
        try {
            return connection != null && !connection.isClosed();
        } catch (SQLException e) {
            return false;
        }
    }
}





