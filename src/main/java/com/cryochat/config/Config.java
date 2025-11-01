package com.cryochat.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class Config {
    private int port = 7070;
    private String adminPassword = "admin123";
    private String dataDir = "CryoChat";

    public static Config load() throws IOException {
        Config config = new Config();
        Path configFile = Paths.get("config.conf");

        if (Files.exists(configFile)) {
            Properties props = new Properties();
            props.load(Files.newInputStream(configFile));

            config.port = Integer.parseInt(props.getProperty("port", "7070"));
            config.adminPassword = props.getProperty("admin_password", "admin123");
            config.dataDir = props.getProperty("data_dir", "CryoChat");
        } else {
            createDefaultConfig(configFile);
        }

        // Create data directory
        Files.createDirectories(Paths.get(config.dataDir));

        return config;
    }

    private static void createDefaultConfig(Path configFile) throws IOException {
        String defaultConfig = """
            # CryoChat Server Configuration
            port=7070
            
            # Admin password
            admin_password=admin123
            
            # Data storage directory
            data_dir=CryoChat
            """;
        Files.writeString(configFile, defaultConfig);
    }

    // Getters
    public int getPort() { return port; }
    public String getAdminPassword() { return adminPassword; }
    public String getDataDir() { return dataDir; }
}