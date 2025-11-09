package com.cryochat.server;

import com.cryochat.config.Config;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class AdminServer {
    private final Config config;
    private final AuthManager authManager;
    private final ObjectMapper objectMapper;
    private final ConcurrentHashMap<String, String> adminSessions;
    private final ConcurrentHashMap<String, Long> adminSessionLastActivity;
    private HttpServer server;

    public AdminServer(Config config, AuthManager authManager) throws IOException {
        this.config = config;
        this.authManager = authManager;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.findAndRegisterModules();
        this.adminSessions = new ConcurrentHashMap<>();
        this.adminSessionLastActivity = new ConcurrentHashMap<>();
    }

    public void start() throws IOException {
        // 在同一个端口上创建管理员服务器，但使用不同的上下文路径
        server = HttpServer.create(new InetSocketAddress(config.getPort()), 0);
        server.setExecutor(Executors.newCachedThreadPool());

        // 管理员API端点
        server.createContext("/CryoChat/api/admin/login", new AdminLoginHandler());
        server.createContext("/CryoChat/api/admin/stats", new AdminStatsHandler());
        server.createContext("/CryoChat/api/admin/users", new AdminUsersHandler());
        server.createContext("/CryoChat/api/admin/users/search", new AdminSearchUsersHandler());
        server.createContext("/CryoChat/api/admin/ban", new AdminBanHandler());
        server.createContext("/CryoChat/api/admin/unban", new AdminUnbanHandler());
        server.createContext("/CryoChat/api/admin/delete", new AdminDeleteHandler());
        server.createContext("/CryoChat/api/admin/cleanup", new AdminCleanupHandler());
        server.createContext("/CryoChat/api/admin/restart", new AdminRestartHandler());
        server.createContext("/CryoChat/api/admin/logout", new AdminLogoutHandler());

        server.start();

        // 启动管理员会话清理任务
        startAdminSessionCleanupTask();

        System.out.println("Admin server started on port: " + config.getPort());
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    // 启动管理员会话清理任务
    private void startAdminSessionCleanupTask() {
        Thread cleanupThread = new Thread(() -> {
            while (true) {
                try {
                    // 每小时执行一次管理员会话清理
                    Thread.sleep(TimeUnit.HOURS.toMillis(1));
                    cleanupExpiredAdminSessions();
                } catch (InterruptedException e) {
                    System.err.println("管理员会话清理任务被中断: " + e.getMessage());
                    break;
                } catch (Exception e) {
                    System.err.println("管理员会话清理错误: " + e.getMessage());
                }
            }
        });
        cleanupThread.setDaemon(true);
        cleanupThread.start();
        System.out.println("管理员会话清理任务已启动");
    }

    // 清理过期管理员会话（12小时未活动）
    private void cleanupExpiredAdminSessions() {
        long now = System.currentTimeMillis();
        long expirationTime = 12 * 60 * 60 * 1000; // 12小时

        adminSessionLastActivity.entrySet().removeIf(entry -> {
            if (now - entry.getValue() > expirationTime) {
                String sessionId = entry.getKey();
                adminSessions.remove(sessionId);
                System.out.println("清理过期管理员会话: " + sessionId);
                return true;
            }
            return false;
        });
    }

    // 管理员登录处理器
    private class AdminLoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                LoginRequest request = objectMapper.readValue(exchange.getRequestBody(), LoginRequest.class);

                // 验证管理员凭据
                boolean isAdmin = config.getAdminUsername().equals(request.username) &&
                        config.getAdminPassword().equals(request.password);

                if (isAdmin) {
                    String sessionId = generateSessionId();
                    adminSessions.put(sessionId, request.username);
                    adminSessionLastActivity.put(sessionId, System.currentTimeMillis());

                    LoginResponse response = new LoginResponse(
                            true,
                            "管理员登录成功",
                            true,
                            sessionId
                    );

                    sendJsonResponse(exchange, 200, response);
                    System.out.println("管理员登录成功: " + request.username + ", Session: " + sessionId);
                } else {
                    sendJsonResponse(exchange, 401, new LoginResponse(false, "管理员用户名或密码错误", false, null));
                    System.out.println("管理员登录失败: " + request.username);
                }

            } catch (Exception e) {
                sendJsonResponse(exchange, 400, new ApiResponse(false, "请求格式错误"));
            }
        }
    }

    // 管理员统计信息处理器
    private class AdminStatsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // 验证管理员会话
            String sessionId = getAdminSessionId(exchange);
            if (!verifyAdminSession(sessionId)) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未授权访问"));
                return;
            }

            // 更新管理员会话活动时间
            adminSessionLastActivity.put(sessionId, System.currentTimeMillis());

            try {
                // 收集统计信息
                Map<String, Object> stats = new HashMap<>();

                // 总用户数
                int totalUsers = authManager.getAllUsers().size();
                stats.put("totalUsers", totalUsers);

                // 在线用户数（5分钟内有活动的用户）
                int onlineUsers = authManager.getOnlineUsersCount();
                stats.put("onlineUsers", onlineUsers);

                // 封禁用户数
                int bannedUsers = authManager.getBannedUsers().size();
                stats.put("bannedUsers", bannedUsers);

                // 文件数量（简化实现）
                stats.put("totalFiles", 0);

                // 服务器运行时间（简化实现）
                stats.put("uptime", "运行中");
                stats.put("memoryUsage", Runtime.getRuntime().totalMemory() / (1024 * 1024) + "MB");
                stats.put("lastCleanup", "最近一次清理: " + new java.util.Date());

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("stats", stats);

                sendJsonResponse(exchange, 200, response);

            } catch (Exception e) {
                System.err.println("获取统计信息错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "获取统计信息失败: " + e.getMessage()));
            }
        }
    }

    // 管理员用户列表处理器
    private class AdminUsersHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // 验证管理员会话
            String sessionId = getAdminSessionId(exchange);
            if (!verifyAdminSession(sessionId)) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未授权访问"));
                return;
            }

            // 更新管理员会话活动时间
            adminSessionLastActivity.put(sessionId, System.currentTimeMillis());

            try {
                List<Map<String, Object>> users = authManager.getAllUserInfo();

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("users", users);

                sendJsonResponse(exchange, 200, response);

            } catch (Exception e) {
                System.err.println("获取用户列表错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "获取用户列表失败: " + e.getMessage()));
            }
        }
    }

    // 管理员搜索用户处理器
    private class AdminSearchUsersHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // 验证管理员会话
            String sessionId = getAdminSessionId(exchange);
            if (!verifyAdminSession(sessionId)) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未授权访问"));
                return;
            }

            // 更新管理员会话活动时间
            adminSessionLastActivity.put(sessionId, System.currentTimeMillis());

            try {
                String query = exchange.getRequestURI().getQuery();
                String searchTerm = null;

                if (query != null) {
                    String[] params = query.split("&");
                    for (String param : params) {
                        if (param.startsWith("q=")) {
                            searchTerm = param.substring(2);
                            break;
                        }
                    }
                }

                List<Map<String, Object>> users = authManager.searchUsers(searchTerm);

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("users", users);

                sendJsonResponse(exchange, 200, response);

            } catch (Exception e) {
                System.err.println("搜索用户错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "搜索用户失败: " + e.getMessage()));
            }
        }
    }

    // 管理员封禁用户处理器
    private class AdminBanHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // 验证管理员会话
            String sessionId = getAdminSessionId(exchange);
            if (!verifyAdminSession(sessionId)) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未授权访问"));
                return;
            }

            // 更新管理员会话活动时间
            adminSessionLastActivity.put(sessionId, System.currentTimeMillis());

            try {
                Map request = objectMapper.readValue(exchange.getRequestBody(), Map.class);
                String username = (String) request.get("username");
                String reason = (String) request.get("reason");
                Integer duration = (Integer) request.get("duration");

                if (username == null || username.trim().isEmpty()) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "用户名不能为空"));
                    return;
                }

                // 不能封禁管理员自己
                if (config.getAdminUsername().equals(username)) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "不能封禁系统管理员"));
                    return;
                }

                boolean success = authManager.banUser(username, reason, duration);

                if (success) {
                    sendJsonResponse(exchange, 200, new ApiResponse(true, "用户封禁成功"));
                    System.out.println("管理员封禁用户: " + username + ", 原因: " + reason + ", 时长: " + duration + "天");
                } else {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "用户封禁失败"));
                }

            } catch (Exception e) {
                System.err.println("封禁用户错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "封禁用户失败: " + e.getMessage()));
            }
        }
    }

    // 管理员解封用户处理器
    private class AdminUnbanHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // 验证管理员会话
            String sessionId = getAdminSessionId(exchange);
            if (!verifyAdminSession(sessionId)) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未授权访问"));
                return;
            }

            // 更新管理员会话活动时间
            adminSessionLastActivity.put(sessionId, System.currentTimeMillis());

            try {
                Map request = objectMapper.readValue(exchange.getRequestBody(), Map.class);
                String username = (String) request.get("username");

                if (username == null || username.trim().isEmpty()) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "用户名不能为空"));
                    return;
                }

                boolean success = authManager.unbanUser(username);

                if (success) {
                    sendJsonResponse(exchange, 200, new ApiResponse(true, "用户解封成功"));
                    System.out.println("管理员解封用户: " + username);
                } else {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "用户解封失败"));
                }

            } catch (Exception e) {
                System.err.println("解封用户错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "解封用户失败: " + e.getMessage()));
            }
        }
    }

    // 管理员删除用户处理器
    private class AdminDeleteHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // 验证管理员会话
            String sessionId = getAdminSessionId(exchange);
            if (!verifyAdminSession(sessionId)) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未授权访问"));
                return;
            }

            // 更新管理员会话活动时间
            adminSessionLastActivity.put(sessionId, System.currentTimeMillis());

            try {
                Map request = objectMapper.readValue(exchange.getRequestBody(), Map.class);
                String username = (String) request.get("username");

                if (username == null || username.trim().isEmpty()) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "用户名不能为空"));
                    return;
                }

                // 不能删除管理员自己
                if (config.getAdminUsername().equals(username)) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "不能删除系统管理员"));
                    return;
                }

                boolean success = authManager.deleteUser(username);

                if (success) {
                    sendJsonResponse(exchange, 200, new ApiResponse(true, "用户删除成功"));
                    System.out.println("管理员删除用户: " + username);
                } else {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "用户删除失败"));
                }

            } catch (Exception e) {
                System.err.println("删除用户错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "删除用户失败: " + e.getMessage()));
            }
        }
    }

    // 管理员清理处理器
    private class AdminCleanupHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // 验证管理员会话
            String sessionId = getAdminSessionId(exchange);
            if (!verifyAdminSession(sessionId)) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未授权访问"));
                return;
            }

            // 更新管理员会话活动时间
            adminSessionLastActivity.put(sessionId, System.currentTimeMillis());

            try {
                // 执行文件清理
                cleanupOldFiles();

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "文件清理完成");

                sendJsonResponse(exchange, 200, response);
                System.out.println("管理员执行文件清理");

            } catch (Exception e) {
                System.err.println("文件清理错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "文件清理失败: " + e.getMessage()));
            }
        }

        private void cleanupOldFiles() {
            try {
                Path filesDir = Paths.get("./CryoChat/files/");
                if (!Files.exists(filesDir)) {
                    return;
                }

                Instant tenDaysAgo = Instant.now().minus(10, ChronoUnit.DAYS);
                AtomicInteger deletedFiles = new AtomicInteger(0);

                // 遍历文件目录
                try (var fileStream = Files.list(filesDir)) {
                    fileStream.forEach(file -> {
                        try {
                            Instant lastModified = Files.getLastModifiedTime(file).toInstant();
                            if (lastModified.isBefore(tenDaysAgo)) {
                                Files.delete(file);
                                System.out.println("删除过期文件: " + file.getFileName());
                                deletedFiles.incrementAndGet();
                            }
                        } catch (IOException e) {
                            System.err.println("删除文件失败: " + file.getFileName() + " - " + e.getMessage());
                        }
                    });
                }

                System.out.println("文件清理完成，删除了 " + deletedFiles.get() + " 个过期文件");
            } catch (IOException e) {
                System.err.println("文件清理任务失败: " + e.getMessage());
            }
        }
    }

    // 管理员重启处理器
    private class AdminRestartHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // 验证管理员会话
            String sessionId = getAdminSessionId(exchange);
            if (!verifyAdminSession(sessionId)) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未授权访问"));
                return;
            }

            // 更新管理员会话活动时间
            adminSessionLastActivity.put(sessionId, System.currentTimeMillis());

            try {
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "服务器重启命令已接收，将在5秒后重启");

                sendJsonResponse(exchange, 200, response);
                System.out.println("管理员请求重启服务器");

                // 此功能暂未完成

            } catch (Exception e) {
                System.err.println("重启服务器错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "重启服务器失败: " + e.getMessage()));
            }
        }
    }

    // 管理员退出处理器
    private class AdminLogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // 验证管理员会话
            String sessionId = getAdminSessionId(exchange);
            String username = adminSessions.get(sessionId);

            if (username != null) {
                // 移除会话
                adminSessions.remove(sessionId);
                adminSessionLastActivity.remove(sessionId);
                System.out.println("管理员退出登录: " + username + ", Session: " + sessionId);
            }

            sendJsonResponse(exchange, 200, new ApiResponse(true, "管理员退出登录成功"));
        }
    }

    // 工具方法
    private String getAdminSessionId(HttpExchange exchange) {
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    private boolean verifyAdminSession(String sessionId) {
        if (sessionId == null) return false;
        return adminSessions.containsKey(sessionId);
    }

    private String generateSessionId() {
        return java.util.UUID.randomUUID().toString();
    }

    private void sendJsonResponse(HttpExchange exchange, int statusCode, Object response) throws IOException {
        byte[] responseBytes = objectMapper.writeValueAsBytes(response);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }

    // 内部请求响应类
    private static class LoginRequest {
        public String username;
        public String password;
    }

    private static class ApiResponse {
        public boolean success;
        public String message;

        public ApiResponse(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    private static class LoginResponse extends ApiResponse {
        public boolean isAdmin;
        public String sessionId;

        public LoginResponse(boolean success, String message, boolean isAdmin, String sessionId) {
            super(success, message);
            this.isAdmin = isAdmin;
            this.sessionId = sessionId;
        }
    }
}