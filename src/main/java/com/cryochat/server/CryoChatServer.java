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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

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
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(config.getPort()), 0);
        server.setExecutor(Executors.newCachedThreadPool());

        // Static file service
        server.createContext("/", new StaticFileHandler());

        // API endpoints
        server.createContext("/api/login", new LoginHandler());
        server.createContext("/api/register", new RegisterHandler());
        server.createContext("/api/upload", new FileUploadHandler());
        server.createContext("/api/download", new FileDownloadHandler());
        server.createContext("/api/chat", new ChatHandler());
        server.createContext("/api/chat/history", new ChatHistoryHandler());
        server.createContext("/api/users/online", new OnlineUsersHandler());
        server.createContext("/api/verify", new VerificationHandler());
        server.createContext("/api/sse", new SSEHandler());
        server.createContext("/api/logout", new LogoutHandler());
        server.createContext("/api/heartbeat", new HeartbeatHandler());

        server.start();

        // 启动文件清理任务
        startFileCleanupTask();
        // 启动会话清理任务
        startSessionCleanupTask();

        System.out.println("CryoChat server started on port: " + config.getPort());
        System.out.println("Please visit: http://localhost:" + config.getPort() + "/chat.html");
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    public void ensureAdminDirectory() {
        chatManager.ensureAdminDirectory();
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

    // 清理过期会话（24小时未活动）
    private void cleanupExpiredSessions() {
        long now = System.currentTimeMillis();
        long expirationTime = 24 * 60 * 60 * 1000; // 24小时

        sessionLastActivity.entrySet().removeIf(entry -> {
            if (now - entry.getValue() > expirationTime) {
                String sessionId = entry.getKey();
                userSessions.remove(sessionId);
                System.out.println("清理过期会话: " + sessionId);
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

    private class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
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
            return "text/plain; charset=utf-8";
        }
    }

    private class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                LoginRequest request = objectMapper.readValue(exchange.getRequestBody(), LoginRequest.class);

                boolean authenticated = authManager.authenticate(
                        request.username, request.password, getClientIp(exchange));

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

                    // 设置cookie过期时间（10天）
                    String cookie = "session=" + sessionId + "; Path=/; HttpOnly; SameSite=Lax";
                    if (request.rememberMe != null && request.rememberMe) {
                        cookie += "; Max-Age=" + (10 * 24 * 60 * 60); // 10天
                    }

                    exchange.getResponseHeaders().set("Set-Cookie", cookie);
                    sendJsonResponse(exchange, 200, response);
                } else {
                    sendJsonResponse(exchange, 401, new LoginResponse(false, "用户名或密码错误", false, null));
                }

            } catch (Exception e) {
                sendJsonResponse(exchange, 400, new ApiResponse(false, "请求格式错误"));
            }
        }
    }

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
                } else {
                    sendJsonResponse(exchange, 409, new ApiResponse(false, "用户名已存在"));
                }

            } catch (Exception e) {
                sendJsonResponse(exchange, 400, new ApiResponse(false, "注册失败: " + e.getMessage()));
            }
        }
    }

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

            try {
                // 解析multipart/form-data
                String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
                if (contentType == null || !contentType.startsWith("multipart/form-data")) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "不支持的Content-Type"));
                    return;
                }

                String boundary = contentType.substring(contentType.indexOf("boundary=") + 9);
                byte[] requestBody = exchange.getRequestBody().readAllBytes();

                // 简单的multipart解析
                Map<String, String> textParts = new HashMap<>();
                Map<String, byte[]> fileParts = new HashMap<>();
                Map<String, String> fileNames = new HashMap<>();

                String bodyStr = new String(requestBody, StandardCharsets.UTF_8);
                String[] parts = bodyStr.split("--" + boundary);

                for (String part : parts) {
                    if (part.contains("Content-Disposition: form-data")) {
                        // 解析字段名
                        String name = extractValue(part, "name=\"", "\"");
                        if (name != null) {
                            if (part.contains("filename=\"")) {
                                // 文件字段
                                String filename = extractValue(part, "filename=\"", "\"");
                                if (filename != null && !filename.isEmpty()) {
                                    // 提取文件内容
                                    int contentStart = part.indexOf("\r\n\r\n") + 4;
                                    int contentEnd = part.lastIndexOf("\r\n");
                                    if (contentStart > 0 && contentEnd > contentStart) {
                                        byte[] fileContent = part.substring(contentStart, contentEnd).getBytes(StandardCharsets.UTF_8);
                                        fileParts.put(name, fileContent);
                                        fileNames.put(name, filename);
                                    }
                                }
                            } else {
                                // 文本字段
                                int valueStart = part.indexOf("\r\n\r\n") + 4;
                                int valueEnd = part.lastIndexOf("\r\n");
                                if (valueStart > 0 && valueEnd > valueStart) {
                                    String value = part.substring(valueStart, valueEnd);
                                    textParts.put(name, value);
                                }
                            }
                        }
                    }
                }

                // 获取目标用户
                String targetUser = textParts.get("targetUser");
                if (targetUser == null || targetUser.trim().isEmpty()) {
                    targetUser = "admin"; // 默认发送给管理员
                }

                // 获取文件数据
                byte[] fileData = fileParts.get("file");
                String originalFilename = fileNames.get("file");

                if (fileData == null || originalFilename == null) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "未找到文件数据"));
                    return;
                }

                // 使用FileManager保存文件
                FileInfo fileInfo = fileManager.saveFile(username, originalFilename, fileData);

                System.out.println("文件保存成功: " + fileInfo.getStoredName() + ", 大小: " + fileData.length + " 字节");
                System.out.println("目标用户: " + targetUser);

                // 创建文件信息响应
                Map<String, Object> responseFileInfo = new HashMap<>();
                responseFileInfo.put("originalName", fileInfo.getOriginalName());
                responseFileInfo.put("storedName", fileInfo.getStoredName());
                responseFileInfo.put("size", fileInfo.getSize());
                responseFileInfo.put("uploadTime", System.currentTimeMillis());
                responseFileInfo.put("downloadUrl", "/api/download?file=" + fileInfo.getStoredName());

                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", true);
                responseData.put("message", "文件上传成功");
                responseData.put("fileInfo", responseFileInfo);

                sendJsonResponse(exchange, 200, responseData);

            } catch (Exception e) {
                System.err.println("文件上传错误: " + e.getMessage());
                e.printStackTrace();
                sendJsonResponse(exchange, 500, new ApiResponse(false, "文件上传错误: " + e.getMessage()));
            }
        }

        private String extractValue(String text, String start, String end) {
            int startIndex = text.indexOf(start);
            if (startIndex == -1) return null;
            startIndex += start.length();
            int endIndex = text.indexOf(end, startIndex);
            if (endIndex == -1) return null;
            return text.substring(startIndex, endIndex);
        }
    }

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

            } catch (Exception e) {
                System.err.println("文件下载错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "文件下载错误: " + e.getMessage()));
            }
        }
    }

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

            } catch (Exception e) {
                System.err.println("发送消息错误: " + e.getMessage());
                sendJsonResponse(exchange, 400, new ApiResponse(false, "发送消息失败: " + e.getMessage()));
            }
        }
    }

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

                // Get user's chat history - 直接从文件读取
                String encodedUsername = Base64.getEncoder().encodeToString(username.getBytes());
                Path userDir = Paths.get(config.getDataDir()).resolve(encodedUsername);
                Path chatLog = userDir.resolve("chat.log");

                List<Message> messages = new ArrayList<>();

                if (Files.exists(chatLog)) {
                    List<String> lines = Files.readAllLines(chatLog, StandardCharsets.UTF_8);
                    for (String line : lines) {
                        if (!line.trim().isEmpty()) {
                            try {
                                Message message = objectMapper.readValue(line, Message.class);
                                messages.add(message);
                            } catch (Exception e) {
                                System.err.println("解析消息失败: " + e.getMessage() + " - 行内容: " + line);
                            }
                        }
                    }
                }

                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", true);
                responseData.put("messages", messages);
                responseData.put("refreshed", true); // 添加刷新标记

                sendJsonResponse(exchange, 200, responseData);

            } catch (Exception e) {
                System.err.println("加载聊天记录错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "加载聊天记录错误: " + e.getMessage()));
            }
        }
    }

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

    private class VerificationHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                VerificationRequest request = objectMapper.readValue(exchange.getRequestBody(), VerificationRequest.class);

                boolean verified = "I am human".equalsIgnoreCase(request.captcha);

                if (verified) {
                    sendJsonResponse(exchange, 200, new ApiResponse(true, "验证成功"));
                } else {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "验证失败"));
                }

            } catch (Exception e) {
                sendJsonResponse(exchange, 400, new ApiResponse(false, "验证请求错误"));
            }
        }
    }

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

            System.out.println("SSE连接建立: " + username);
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
                    System.out.println("SSE心跳连接已关闭: " + e.getMessage());
                }
            });
            heartbeatThread.setDaemon(true);
            heartbeatThread.start();
        }
    }

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

                System.out.println("用户退出登录: " + username);
            }

            // Clear cookie
            exchange.getResponseHeaders().set("Set-Cookie", "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");

            sendJsonResponse(exchange, 200, new ApiResponse(true, "退出登录成功"));
        }
    }

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

    // Utility methods
    private String getClientIp(HttpExchange exchange) {
        return exchange.getRemoteAddress().getAddress().getHostAddress();
    }

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

    // Internal request response classes
    private static class LoginRequest {
        public String username;
        public String password;
        public Boolean rememberMe;
    }

    private static class VerificationRequest {
        public String captcha;
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