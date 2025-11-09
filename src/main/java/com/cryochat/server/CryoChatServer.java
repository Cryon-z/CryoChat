package com.cryochat.server;

import com.cryochat.config.Config;
import com.cryochat.model.Message;
import com.cryochat.model.FileInfo;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.concurrent.ExecutorService;

public class CryoChatServer {
    private final Config config;
    private final AuthManager authManager;
    private final ChatManager chatManager;
    private final FileManager fileManager;
    private final WebSocketHandler webSocketHandler;
    private final ObjectMapper objectMapper;
    private HttpServer server;
    private final ConcurrentHashMap<String, String> userSessions;
    private final ConcurrentHashMap<String, Long> lastMessageTime;
    private final ConcurrentHashMap<String, Long> sessionLastActivity;
    private final ConcurrentHashMap<String, Long> userLastActivity;
    private final ExecutorService fileUploadExecutor;

    // 管理员会话管理
    private final ConcurrentHashMap<String, String> adminSessions;
    private final ConcurrentHashMap<String, Long> adminSessionLastActivity;

    public CryoChatServer(Config config) throws IOException {
        this.config = config;
        this.authManager = new AuthManager(config);
        this.chatManager = new ChatManager(config.getDataDir());
        this.fileManager = new FileManager(config.getDataDir());
        this.webSocketHandler = new WebSocketHandler(chatManager, fileManager);
        this.objectMapper = new ObjectMapper();
        this.objectMapper.findAndRegisterModules();
        this.userSessions = new ConcurrentHashMap<>();
        this.lastMessageTime = new ConcurrentHashMap<>();
        this.sessionLastActivity = new ConcurrentHashMap<>();
        this.userLastActivity = new ConcurrentHashMap<>();

        // 初始化管理员会话管理
        this.adminSessions = new ConcurrentHashMap<>();
        this.adminSessionLastActivity = new ConcurrentHashMap<>();

        // 创建固定大小的线程池处理文件上传，避免卡死系统
        this.fileUploadExecutor = Executors.newFixedThreadPool(3);
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(config.getPort()), 0);
        server.setExecutor(Executors.newCachedThreadPool());

        // 所有路径都添加 /CryoChat 前缀
        String basePath = "/CryoChat";

        // Static file service - 处理 /CryoChat/ 路径
        server.createContext(basePath + "/", new StaticFileHandler());

        // API endpoints - 所有API都添加 /CryoChat 前缀
        server.createContext(basePath + "/api/login", new LoginHandler());
        server.createContext(basePath + "/api/register", new RegisterHandler());
        server.createContext(basePath + "/api/upload", new FileUploadHandler());
        server.createContext(basePath + "/api/download", new FileDownloadHandler());
        server.createContext(basePath + "/api/chat", new ChatHandler());
        server.createContext(basePath + "/api/chat/history", new ChatHistoryHandler());
        server.createContext(basePath + "/api/users/online", new OnlineUsersHandler());
        server.createContext(basePath + "/api/sse", new SSEHandler());
        server.createContext(basePath + "/api/logout", new LogoutHandler());
        server.createContext(basePath + "/api/heartbeat", new HeartbeatHandler());

        // 管理员API端点
        server.createContext(basePath + "/api/admin/login", new AdminLoginHandler());
        server.createContext(basePath + "/api/admin/stats", new AdminStatsHandler());
        server.createContext(basePath + "/api/admin/users", new AdminUsersHandler());
        server.createContext(basePath + "/api/admin/users/search", new AdminSearchUsersHandler());
        server.createContext(basePath + "/api/admin/ban", new AdminBanHandler());
        server.createContext(basePath + "/api/admin/unban", new AdminUnbanHandler());
        server.createContext(basePath + "/api/admin/delete", new AdminDeleteHandler());
        server.createContext(basePath + "/api/admin/cleanup", new AdminCleanupHandler());
        server.createContext(basePath + "/api/admin/restart", new AdminRestartHandler());
        server.createContext(basePath + "/api/admin/logout", new AdminLogoutHandler());

        server.start();

        // 启动文件清理任务
        startFileCleanupTask();
        // 启动会话清理任务
        startSessionCleanupTask();
        // 启动管理员会话清理任务
        startAdminSessionCleanupTask();

        System.out.println("CryoChat server started on port: " + config.getPort());
        System.out.println("Please visit: http://localhost:" + config.getPort() + basePath + "/");
        System.out.println("Admin panel: http://localhost:" + config.getPort() + basePath + "/admin/");
        System.out.println("Other ports on localhost:" + config.getPort() + " remain available for other applications");
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
        if (fileUploadExecutor != null) {
            fileUploadExecutor.shutdown();
            try {
                if (!fileUploadExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    fileUploadExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                fileUploadExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    public void ensureAdminDirectory() {
        chatManager.ensureAdminDirectory();
    }

    // 获取AuthManager的方法
    public AuthManager getAuthManager() {
        return authManager;
    }

    // 启动文件清理任务
    private void startFileCleanupTask() {
        Thread cleanupThread = new Thread(() -> {
            while (true) {
                try {
                    // 每天执行一次清理
                    Thread.sleep(TimeUnit.DAYS.toMillis(1));
                    cleanupOldFiles();
                } catch (InterruptedException e) {
                    System.err.println("文件清理任务被中断: " + e.getMessage());
                    break;
                } catch (Exception e) {
                    System.err.println("文件清理错误: " + e.getMessage());
                }
            }
        });
        cleanupThread.setDaemon(true);
        cleanupThread.start();
        System.out.println("文件清理任务已启动");
    }

    // 启动会话清理任务
    private void startSessionCleanupTask() {
        Thread cleanupThread = new Thread(() -> {
            while (true) {
                try {
                    // 每小时执行一次会话清理
                    Thread.sleep(TimeUnit.HOURS.toMillis(1));
                    cleanupExpiredSessions();
                } catch (InterruptedException e) {
                    System.err.println("会话清理任务被中断: " + e.getMessage());
                    break;
                } catch (Exception e) {
                    System.err.println("会话清理错误: " + e.getMessage());
                }
            }
        });
        cleanupThread.setDaemon(true);
        cleanupThread.start();
        System.out.println("会话清理任务已启动");
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

    // 清理过期会话（24小时未活动）
    private void cleanupExpiredSessions() {
        long now = System.currentTimeMillis();
        long expirationTime = 24 * 60 * 60 * 1000; // 24小时

        sessionLastActivity.entrySet().removeIf(entry -> {
            if (now - entry.getValue() > expirationTime) {
                String sessionId = entry.getKey();
                String username = userSessions.get(sessionId);
                userSessions.remove(sessionId);
                if (username != null) {
                    userLastActivity.remove(username);
                }
                System.out.println("清理过期会话: " + sessionId);
                return true;
            }
            return false;
        });
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

    // 清理超过10天的文件
    private void cleanupOldFiles() {
        try {
            // 文件一律存放到 ./CryoChat/files/ 里面
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

    // 静态文件处理器
    private class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();

            // 移除 /CryoChat 前缀
            if (path.startsWith("/CryoChat")) {
                path = path.substring("/CryoChat".length());
            }

            // 处理管理员路径
            if (path.startsWith("/admin")) {
                if ("/admin".equals(path) || "/admin/".equals(path)) {
                    path = "/admin.html";
                }

                // 从资源文件加载管理员页面
                try (var input = getClass().getResourceAsStream(path)) {
                    if (input != null) {
                        byte[] data = input.readAllBytes();
                        exchange.getResponseHeaders().set("Content-Type", getContentType(path));
                        exchange.sendResponseHeaders(200, data.length);
                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(data);
                        }
                        return;
                    }
                }
            }

            if ("/".equals(path)) {
                path = "/chat.html";
            }

            // Security check
            if (path.contains("..")) {
                exchange.sendResponseHeaders(403, -1);
                return;
            }

            // Serve files from current directory or resource files
            Path filePath = Paths.get("." + path);
            if (!Files.exists(filePath)) {
                // Load from resource files
                try (var input = getClass().getResourceAsStream(path)) {
                    if (input != null) {
                        byte[] data = input.readAllBytes();
                        exchange.getResponseHeaders().set("Content-Type", getContentType(path));
                        exchange.sendResponseHeaders(200, data.length);
                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(data);
                        }
                        return;
                    }
                }
            } else {
                byte[] data = Files.readAllBytes(filePath);
                exchange.getResponseHeaders().set("Content-Type", getContentType(path));
                exchange.sendResponseHeaders(200, data.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(data);
                }
                return;
            }

            // File not found
            sendErrorResponse(exchange, 404, "File not found: " + path);
        }

        private String getContentType(String path) {
            if (path.endsWith(".html")) return "text/html; charset=utf-8";
            if (path.endsWith(".css")) return "text/css";
            if (path.endsWith(".js")) return "application/javascript";
            if (path.endsWith(".png")) return "image/png";
            if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
            if (path.endsWith(".json")) return "application/json";
            if (path.endsWith(".ico")) return "image/x-icon";
            return "text/plain; charset=utf-8";
        }
    }

    // 用户登录处理器
    private class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                LoginRequest request = objectMapper.readValue(exchange.getRequestBody(), LoginRequest.class);

                // 移除IP参数，完全基于用户名密码认证
                boolean authenticated = authManager.authenticate(request.username, request.password);

                if (authenticated) {
                    String sessionId = generateSessionId();
                    userSessions.put(sessionId, request.username);
                    sessionLastActivity.put(sessionId, System.currentTimeMillis());
                    userLastActivity.put(request.username, System.currentTimeMillis());

                    boolean isAdmin = authManager.isAdmin(request.username);

                    LoginResponse response = new LoginResponse(
                            true,
                            "登录成功",
                            isAdmin,
                            sessionId
                    );

                    // 设置cookie（会话cookie，浏览器关闭时过期）
                    String cookie = "session=" + sessionId + "; Path=/CryoChat; HttpOnly; SameSite=Lax";
                    exchange.getResponseHeaders().set("Set-Cookie", cookie);
                    sendJsonResponse(exchange, 200, response);

                    System.out.println("用户登录成功: " + request.username + ", Session: " + sessionId);
                } else {
                    sendJsonResponse(exchange, 401, new LoginResponse(false, "用户名或密码错误", false, null));
                    System.out.println("用户登录失败: " + request.username);
                }

            } catch (Exception e) {
                sendJsonResponse(exchange, 400, new ApiResponse(false, "请求格式错误"));
            }
        }
    }

    // 用户注册处理器
    private class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                LoginRequest request = objectMapper.readValue(exchange.getRequestBody(), LoginRequest.class);

                if (request.username == null || request.username.trim().isEmpty() ||
                        request.password == null || request.password.trim().isEmpty()) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "用户名和密码不能为空"));
                    return;
                }

                boolean registered = authManager.register(request.username.trim(), request.password);

                if (registered) {
                    sendJsonResponse(exchange, 200, new ApiResponse(true, "注册成功"));
                    System.out.println("用户注册成功: " + request.username);
                } else {
                    sendJsonResponse(exchange, 409, new ApiResponse(false, "用户名已存在"));
                }

            } catch (Exception e) {
                sendJsonResponse(exchange, 400, new ApiResponse(false, "注册失败: " + e.getMessage()));
            }
        }
    }

    // 文件上传处理器
    private class FileUploadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Verify session
            String sessionId = getSessionId(exchange);
            String username = userSessions.get(sessionId);
            if (username == null) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未登录"));
                return;
            }

            // 更新会话活动时间
            sessionLastActivity.put(sessionId, System.currentTimeMillis());
            userLastActivity.put(username, System.currentTimeMillis());

            // 使用线程池处理文件上传，避免阻塞主线程和卡死系统
            fileUploadExecutor.submit(() -> {
                try {
                    handleFileUploadInThread(exchange, username);
                } catch (Exception e) {
                    System.err.println("文件上传线程错误: " + e.getMessage());
                    try {
                        sendJsonResponse(exchange, 500, new ApiResponse(false, "文件上传错误: " + e.getMessage()));
                    } catch (IOException ex) {
                        System.err.println("发送错误响应失败: " + ex.getMessage());
                    }
                }
            });
        }

        private void handleFileUploadInThread(HttpExchange exchange, String username) throws IOException {
            try {
                String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
                if (contentType == null || !contentType.startsWith("multipart/form-data")) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "不支持的Content-Type"));
                    return;
                }

                // 获取边界字符串
                String boundary = extractBoundary(contentType);
                if (boundary == null) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "无法解析边界"));
                    return;
                }

                // 读取请求体
                byte[] requestBody = exchange.getRequestBody().readAllBytes();
                System.out.println("接收到上传请求，用户: " + username + ", 数据大小: " + requestBody.length + " 字节");

                // 解析multipart数据
                MultipartParser parser = new MultipartParser(requestBody, boundary.getBytes(StandardCharsets.UTF_8));
                Map<String, String> textParts = parser.getTextParts();
                Map<String, byte[]> fileParts = parser.getFileParts();
                Map<String, String> fileNames = parser.getFileNames();

                // 获取目标用户
                String targetUser = textParts.get("targetUser");
                if (targetUser == null || targetUser.trim().isEmpty()) {
                    targetUser = "admin";
                }

                // 获取文件数据
                byte[] fileData = fileParts.get("file");
                String originalFilename = fileNames.get("file");

                if (fileData == null || originalFilename == null) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "未找到文件数据"));
                    return;
                }

                System.out.println("开始保存文件: " + originalFilename + ", 用户: " + username + ", 大小: " + fileData.length + " 字节");

                // 使用FileManager保存文件
                FileInfo fileInfo = fileManager.saveFile(username, originalFilename, fileData);

                // 创建文件信息响应
                Map<String, Object> responseFileInfo = new HashMap<>();
                responseFileInfo.put("originalName", fileInfo.getOriginalName());
                responseFileInfo.put("storedName", fileInfo.getStoredName());
                responseFileInfo.put("size", fileInfo.getSize());
                responseFileInfo.put("uploadTime", System.currentTimeMillis());
                responseFileInfo.put("downloadUrl", "/CryoChat/api/download?file=" + fileInfo.getStoredName());

                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", true);
                responseData.put("message", "文件上传成功");
                responseData.put("fileInfo", responseFileInfo);

                sendJsonResponse(exchange, 200, responseData);
                System.out.println("文件上传完成: " + originalFilename + ", 用户: " + username);

            } catch (Exception e) {
                System.err.println("文件上传错误: " + e.getMessage());
                e.printStackTrace();
                sendJsonResponse(exchange, 500, new ApiResponse(false, "文件上传错误: " + e.getMessage()));
            }
        }

        private String extractBoundary(String contentType) {
            String[] parts = contentType.split(";");
            for (String part : parts) {
                part = part.trim();
                if (part.startsWith("boundary=")) {
                    return part.substring(9).replace("\"", "");
                }
            }
            return null;
        }
    }

    // 文件下载处理器
    private class FileDownloadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Verify session
            String sessionId = getSessionId(exchange);
            String username = userSessions.get(sessionId);
            if (username == null) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未登录"));
                return;
            }

            // 更新会话活动时间
            sessionLastActivity.put(sessionId, System.currentTimeMillis());
            userLastActivity.put(username, System.currentTimeMillis());

            try {
                // Get file parameter from query
                String query = exchange.getRequestURI().getQuery();
                String fileName = null;

                if (query != null) {
                    String[] params = query.split("&");
                    for (String param : params) {
                        if (param.startsWith("file=")) {
                            fileName = param.substring(5);
                            break;
                        }
                    }
                }

                if (fileName == null || fileName.isEmpty()) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "文件名不能为空"));
                    return;
                }

                // Read file data using FileManager
                byte[] fileData = fileManager.getFile(fileName);

                // Set response headers
                exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
                exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
                exchange.sendResponseHeaders(200, fileData.length);

                // Send file data
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(fileData);
                }

                System.out.println("文件下载: " + fileName + ", 用户: " + username);

            } catch (Exception e) {
                System.err.println("文件下载错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "文件下载错误: " + e.getMessage()));
            }
        }
    }

    // 聊天消息处理器
    private class ChatHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Verify session
            String sessionId = getSessionId(exchange);
            String username = userSessions.get(sessionId);
            if (username == null) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未登录"));
                return;
            }

            // 更新会话活动时间
            sessionLastActivity.put(sessionId, System.currentTimeMillis());
            userLastActivity.put(username, System.currentTimeMillis());

            try {
                Message message = objectMapper.readValue(exchange.getRequestBody(), Message.class);
                message.setFrom(username);

                // 添加消息延迟检查，避免重复消息
                String messageKey = username + "_" + message.getContent() + "_" + message.getTo();
                long currentTime = System.currentTimeMillis();
                Long lastTime = lastMessageTime.get(messageKey);

                if (lastTime != null && (currentTime - lastTime) < 50) { // 50毫秒内重复的消息，忽略
                    System.out.println("忽略重复消息: " + messageKey);
                    sendJsonResponse(exchange, 200, new ApiResponse(true, "消息发送成功"));
                    return;
                }

                lastMessageTime.put(messageKey, currentTime);

                // 发送消息
                chatManager.sendMessage(message);
                sendJsonResponse(exchange, 200, new ApiResponse(true, "消息发送成功"));

                System.out.println("发送消息: " + username + " -> " + message.getTo() + ", 内容: " +
                        (message.getContent().length() > 50 ? message.getContent().substring(0, 50) + "..." : message.getContent()));

            } catch (Exception e) {
                System.err.println("发送消息错误: " + e.getMessage());
                sendJsonResponse(exchange, 400, new ApiResponse(false, "发送消息失败: " + e.getMessage()));
            }
        }
    }

    // 聊天历史处理器
    private class ChatHistoryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Verify session
            String sessionId = getSessionId(exchange);
            String username = userSessions.get(sessionId);
            if (username == null) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未登录"));
                return;
            }

            // 更新会话活动时间
            sessionLastActivity.put(sessionId, System.currentTimeMillis());
            userLastActivity.put(username, System.currentTimeMillis());

            try {
                // 清除消息时间缓存，避免重复消息检查
                lastMessageTime.entrySet().removeIf(entry -> entry.getKey().startsWith(username + "_"));

                // 从查询参数获取聊天类型和目标用户
                String query = exchange.getRequestURI().getQuery();
                String chatType = "group"; // 默认群聊
                String targetUser = "group";

                if (query != null) {
                    String[] params = query.split("&");
                    for (String param : params) {
                        if (param.startsWith("type=")) {
                            chatType = param.substring(5);
                        } else if (param.startsWith("target=")) {
                            targetUser = param.substring(7);
                        }
                    }
                }

                // 使用ChatManager获取聊天记录
                List<Message> messages = chatManager.getUserChatHistory(username, chatType, targetUser);

                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", true);
                responseData.put("messages", messages);
                responseData.put("refreshed", true);
                responseData.put("chatType", chatType);
                responseData.put("targetUser", targetUser);

                sendJsonResponse(exchange, 200, responseData);

                System.out.println("加载聊天记录: " + username + ", 类型: " + chatType + ", 目标: " + targetUser + ", 消息数量: " + messages.size());

            } catch (Exception e) {
                System.err.println("加载聊天记录错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "加载聊天记录错误: " + e.getMessage()));
            }
        }
    }

    // 在线用户处理器
    private class OnlineUsersHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Verify session
            String sessionId = getSessionId(exchange);
            String username = userSessions.get(sessionId);
            if (username == null) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未登录"));
                return;
            }

            // 更新会话活动时间
            sessionLastActivity.put(sessionId, System.currentTimeMillis());
            userLastActivity.put(username, System.currentTimeMillis());

            try {
                // 获取5分钟内有活动的用户作为在线用户
                long fiveMinutesAgo = System.currentTimeMillis() - (5 * 60 * 1000);
                List<String> onlineUsers = userLastActivity.entrySet().stream()
                        .filter(entry -> entry.getValue() > fiveMinutesAgo)
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toList());

                // 隐藏当前用户
                onlineUsers.remove(username);

                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", true);
                responseData.put("onlineUsers", onlineUsers);
                responseData.put("count", onlineUsers.size());

                sendJsonResponse(exchange, 200, responseData);

            } catch (Exception e) {
                System.err.println("获取在线用户错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "获取在线用户错误: " + e.getMessage()));
            }
        }
    }

    // SSE处理器
    private class SSEHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Verify session
            String sessionId = getSessionId(exchange);
            String username = userSessions.get(sessionId);
            if (username == null) {
                exchange.sendResponseHeaders(401, -1);
                return;
            }

            // 更新会话活动时间
            sessionLastActivity.put(sessionId, System.currentTimeMillis());
            userLastActivity.put(username, System.currentTimeMillis());

            // Set SSE headers
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            exchange.getResponseHeaders().set("Connection", "keep-alive");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
            exchange.sendResponseHeaders(200, 0);

            // Create SSE connection with heartbeat
            WebSocketHandler.SSEConnection sseConnection = new WebSocketHandler.SSEConnection() {
                private volatile boolean closed = false;

                @Override
                public void sendMessage(String message) throws IOException {
                    if (!closed) {
                        String sseMessage = "data: " + message + "\n\n";
                        exchange.getResponseBody().write(sseMessage.getBytes());
                        exchange.getResponseBody().flush();
                    }
                }

                @Override
                public void close() throws IOException {
                    closed = true;
                }

                @Override
                public boolean isClosed() {
                    return closed;
                }
            };

            // Register SSE connection
            webSocketHandler.addSSEConnection(username, sseConnection);

            // Start heartbeat thread
            startHeartbeat(sseConnection, exchange);

            System.out.println("SSE连接建立: " + username + ", Session: " + sessionId);
        }

        private void startHeartbeat(WebSocketHandler.SSEConnection connection, HttpExchange exchange) {
            Thread heartbeatThread = new Thread(() -> {
                try {
                    while (!connection.isClosed()) {
                        Thread.sleep(30000); // 30秒发送一次心跳
                        if (!connection.isClosed()) {
                            connection.sendMessage("{\"type\":\"heartbeat\"}");
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (IOException e) {
                    // 连接已关闭，正常退出
                    System.out.println("SSE心跳连接已关闭");
                }
            });
            heartbeatThread.setDaemon(true);
            heartbeatThread.start();
        }
    }

    // 用户退出处理器
    private class LogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Verify session
            String sessionId = getSessionId(exchange);
            String username = userSessions.get(sessionId);

            if (username != null) {
                // Remove session
                userSessions.remove(sessionId);
                sessionLastActivity.remove(sessionId);
                userLastActivity.remove(username);

                // Remove SSE connection
                webSocketHandler.removeSSEConnection(username);

                System.out.println("用户退出登录: " + username + ", Session: " + sessionId);
            }

            // Clear cookie
            exchange.getResponseHeaders().set("Set-Cookie", "session=; Path=/CryoChat; HttpOnly; SameSite=Lax; Max-Age=0");

            sendJsonResponse(exchange, 200, new ApiResponse(true, "退出登录成功"));
        }
    }

    // 心跳处理器
    private class HeartbeatHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // Verify session
            String sessionId = getSessionId(exchange);
            String username = userSessions.get(sessionId);
            if (username == null) {
                sendJsonResponse(exchange, 401, new ApiResponse(false, "未登录"));
                return;
            }

            // 更新会话活动时间
            sessionLastActivity.put(sessionId, System.currentTimeMillis());
            userLastActivity.put(username, System.currentTimeMillis());

            sendJsonResponse(exchange, 200, new ApiResponse(true, "心跳成功"));
        }
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

                // 此功能暂未完善

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
    private String getSessionId(HttpExchange exchange) {
        String cookie = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookie != null) {
            for (String part : cookie.split(";")) {
                if (part.trim().startsWith("session=")) {
                    return part.trim().substring(8);
                }
            }
        }
        return null;
    }

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

    private void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
        ApiResponse response = new ApiResponse(false, message);
        sendJsonResponse(exchange, statusCode, response);
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