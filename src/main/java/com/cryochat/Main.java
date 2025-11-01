package com.cryochat;

import com.cryochat.server.CryoChatServer;
import com.cryochat.config.Config;

public class Main {
    public static void main(String[] args) {
        try {
            System.out.println("Starting CryoChat server...");

            Config config = Config.load();
            CryoChatServer server = new CryoChatServer(config);

            // Ensure admin directory exists
            server.ensureAdminDirectory();

            server.start();

            // Add shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\nShutting down server...");
                server.stop();
                System.out.println("Server stopped");
            }));

            System.out.println("Server running, press Ctrl+C to exit");

            // Keep main thread running
            Thread.currentThread().join();

        } catch (Exception e) {
            System.err.println("Server startup failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}