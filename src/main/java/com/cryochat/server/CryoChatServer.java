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
        server.createContext("/api/files/check", new FileCheckHandler());
        server.createContext("/api/verify", new VerificationHandler());
        server.createContext("/api/sse", new SSEHandler());

        server.start();

        // 启动文件清理任务
        startFileCleanupTask();

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

    // 清理超过10天的文件
    private void cleanupOldFiles() {
        try {
            Path dataDir = Paths.get(config.getDataDir());
            if (!Files.exists(dataDir)) {
                return;
            }

            Instant tenDaysAgo = Instant.now().minus(10, ChronoUnit.DAYS);
            AtomicInteger deletedFiles = new AtomicInteger(0);

            // 遍历所有用户目录
            Files.list(dataDir).forEach(userDir -> {
                if (Files.isDirectory(userDir)) {
                    try {
                        Path filesDir = userDir.resolve("files");
                        if (Files.exists(filesDir)) {
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
                        }
                    } catch (IOException e) {
                        System.err.println("遍历用户目录失败: " + userDir.getFileName() + " - " + e.getMessage());
                    }
                }
            });

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
                String clientIp = getClientIp(exchange);

                // Human verification
                if (!webSocketHandler.verifyHuman(clientIp)) {
                    sendJsonResponse(exchange, 429, new ApiResponse(false, "Too many requests, please try again later"));
                    return;
                }

                boolean authenticated = authManager.authenticate(
                        request.username, request.password, clientIp);

                if (authenticated) {
                    String sessionId = generateSessionId();
                    userSessions.put(sessionId, request.username);

                    // 修复：使用正确的参数调用isAdmin方法
                    boolean isAdmin = authManager.isAdmin(request.username);

                    LoginResponse response = new LoginResponse(
                            true,
                            "登录成功",
                            isAdmin,
                            sessionId
                    );

                    exchange.getResponseHeaders().set("Set-Cookie", "session=" + sessionId + "; Path=/");
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

                // 保存文件到目标用户的目录
                String encodedTargetUser = Base64.getEncoder().encodeToString(targetUser.getBytes());
                Path targetUserDir = Paths.get(config.getDataDir()).resolve(encodedTargetUser);
                Path filesDir = targetUserDir.resolve("files");
                Files.createDirectories(filesDir);

                // 使用原始文件名保存文件
                Path filePath = filesDir.resolve(originalFilename);
                Files.write(filePath, fileData);

                System.out.println("文件保存成功: " + filePath.toAbsolutePath() + ", 大小: " + fileData.length + " 字节");
                System.out.println("目标用户: " + targetUser);

                // 创建文件信息
                Map<String, Object> fileInfo = new HashMap<>();
                fileInfo.put("originalName", originalFilename);
                fileInfo.put("storedName", originalFilename);
                fileInfo.put("size", fileData.length);
                fileInfo.put("uploadTime", System.currentTimeMillis());
                fileInfo.put("downloadUrl", "/api/download?user=" + targetUser + "&file=" + originalFilename);

                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", true);
                responseData.put("message", "文件上传成功");
                responseData.put("fileInfo", fileInfo);

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

            try {
                // Get file and user parameters from query
                String query = exchange.getRequestURI().getQuery();
                String fileName = null;
                String targetUser = username; // 默认下载当前用户的文件

                if (query != null) {
                    String[] params = query.split("&");
                    for (String param : params) {
                        if (param.startsWith("file=")) {
                            fileName = param.substring(5);
                        } else if (param.startsWith("user=")) {
                            targetUser = param.substring(5);
                        }
                    }
                }

                if (fileName == null || fileName.isEmpty()) {
                    sendJsonResponse(exchange, 400, new ApiResponse(false, "文件名不能为空"));
                    return;
                }

                // Create target user file directory path
                String encodedTargetUser = Base64.getEncoder().encodeToString(targetUser.getBytes());
                Path targetUserDir = Paths.get(config.getDataDir()).resolve(encodedTargetUser);
                Path filesDir = targetUserDir.resolve("files");
                Path filePath = filesDir.resolve(fileName);

                if (!Files.exists(filePath)) {
                    sendJsonResponse(exchange, 404, new ApiResponse(false, "文件不存在"));
                    return;
                }

                // Read file data
                byte[] fileData = Files.readAllBytes(filePath);

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

            try {
                // 清除消息时间缓存，避免重复消息检查
                lastMessageTime.entrySet().removeIf(entry -> entry.getKey().startsWith(username + "_"));

                // Get user's chat history
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
                                System.err.println("解析消息失败: " + e.getMessage());
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

            try {
                // Get online users from chat manager
                var activeSessions = chatManager.getActiveSessions();
                List<String> onlineUsers = new ArrayList<>(activeSessions.keySet());

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

    private class FileCheckHandler implements HttpHandler {
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

            try {
                // Create user file directory path
                String encodedUsername = Base64.getEncoder().encodeToString(username.getBytes());
                Path userDir = Paths.get(config.getDataDir()).resolve(encodedUsername);
                Path filesDir = userDir.resolve("files");

                List<Map<String, Object>> fileList = new ArrayList<>();

                if (Files.exists(filesDir)) {
                    Files.list(filesDir).forEach(filePath -> {
                        try {
                            Map<String, Object> fileInfo = new HashMap<>();
                            fileInfo.put("name", filePath.getFileName().toString());
                            fileInfo.put("size", Files.size(filePath));
                            fileInfo.put("lastModified", Files.getLastModifiedTime(filePath).toMillis());
                            fileInfo.put("path", filePath.toAbsolutePath().toString());
                            fileList.add(fileInfo);
                        } catch (IOException e) {
                            System.err.println("读取文件信息失败: " + e.getMessage());
                        }
                    });
                }

                Map<String, Object> responseData = new HashMap<>();
                responseData.put("success", true);
                responseData.put("files", fileList);
                responseData.put("filesDir", filesDir.toAbsolutePath().toString());

                sendJsonResponse(exchange, 200, responseData);

            } catch (Exception e) {
                System.err.println("检查文件错误: " + e.getMessage());
                sendJsonResponse(exchange, 500, new ApiResponse(false, "检查文件错误: " + e.getMessage()));
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
                String clientIp = getClientIp(exchange);

                boolean verified = webSocketHandler.verifyHuman(clientIp) &&
                        "I am human".equalsIgnoreCase(request.captcha);

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

            // Set SSE headers
            exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
            exchange.getResponseHeaders().set("Cache-Control", "no-cache");
            exchange.getResponseHeaders().set("Connection", "keep-alive");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, 0);

            // Create SSE connection
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
                    // Response body will be automatically closed when connection closes
                }
            };

            // Register SSE connection
            webSocketHandler.addSSEConnection(username, sseConnection);

            // Keep connection open until client disconnects
            // Note: In production environment, need to handle connection timeout and heartbeat
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