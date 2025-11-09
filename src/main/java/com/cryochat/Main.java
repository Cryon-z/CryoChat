package com.cryochat;

import com.cryochat.server.CryoChatServer;
import com.cryochat.config.Config;

public class Main {
    public static void main(String[] args) {
        try {
            System.out.println("Starting CryoChat server...");

            // 设置窗口标题（Windows）
            try {
                if (System.getProperty("os.name").toLowerCase().contains("windows")) {
                    // Windows下设置控制台标题
                    new ProcessBuilder("cmd", "/c", "title CryoChat Server").inheritIO().start().waitFor();
                }
            } catch (Exception e) {
                // 忽略标题设置错误
                System.out.println("Note: Could not set window title");
            }

            Config config = Config.load();

            // 创建主服务器（现在包含管理员功能）
            CryoChatServer server = new CryoChatServer(config);

            // Ensure admin directory exists
            server.ensureAdminDirectory();

            // 启动服务器（现在包含管理员功能）
            server.start();

            // Add shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\nShutting down server...");
                server.stop();
                System.out.println("Server stopped");
            }));

            System.out.println("Server running on port " + config.getPort());
            System.out.println("Web interface: http://localhost:" + config.getPort() + "/CryoChat/");
            System.out.println("Admin interface: http://localhost:" + config.getPort() + "/CryoChat/admin/");
            System.out.println("Press Ctrl+C to exit");

            // Keep main thread running
            Thread.currentThread().join();

        } catch (Exception e) {
            System.err.println("Server startup failed: " + e.getMessage());
            e.printStackTrace();

            // 添加等待用户输入，以便查看错误信息
            System.out.println("Press Enter to exit...");
            try {
                System.in.read();
            } catch (Exception ex) {
                // 忽略错误
            }
        }
    }
}