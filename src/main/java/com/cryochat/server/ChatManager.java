package com.cryochat.server;

import com.cryochat.model.Message;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

public class ChatManager {
    private final Map<String, CopyOnWriteArrayList<Consumer<Message>>> userSessions =
            new ConcurrentHashMap<>();
    private final Path dataDir;
    private final ObjectMapper objectMapper;

    public ChatManager(String dataDir) {
        this.dataDir = Paths.get(dataDir);
        this.objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();

        // Ensure data directory exists
        try {
            Files.createDirectories(this.dataDir);
        } catch (IOException e) {
            System.err.println("Failed to create data directory: " + e.getMessage());
        }
    }

    public void addUserSession(String username, Consumer<Message> messageHandler) {
        userSessions.computeIfAbsent(username, k -> new CopyOnWriteArrayList<>())
                .add(messageHandler);
        System.out.println("User session added: " + username + ", active sessions: " + userSessions.size());
    }

    public void removeUserSession(String username, Consumer<Message> messageHandler) {
        CopyOnWriteArrayList<Consumer<Message>> sessions = userSessions.get(username);
        if (sessions != null) {
            if (messageHandler != null) {
                sessions.remove(messageHandler);
            } else {
                sessions.clear();
            }
            if (sessions.isEmpty()) {
                userSessions.remove(username);
            }
        }
        System.out.println("User session removed: " + username + ", active sessions: " + userSessions.size());
    }

    public void sendMessage(Message message) throws IOException {
        // 保存消息到相关用户的记录中
        if ("group".equals(message.getTo())) {
            // 群聊消息：保存到所有用户的群聊记录中
            saveGroupMessageToAllUsers(message);
        } else {
            // 私聊消息：保存到发送者和接收者的私聊记录中
            savePrivateMessage(message);
        }

        // 发送到目标用户
        if ("group".equals(message.getTo())) {
            // 群聊消息发送给所有在线用户（除了发送者自己）
            userSessions.forEach((username, sessions) -> {
                if (!username.equals(message.getFrom())) {
                    System.out.println("Sending group message to " + username);
                    sessions.forEach(handler -> {
                        try {
                            handler.accept(message);
                        } catch (Exception e) {
                            System.err.println("Error sending message to " + username + ": " + e.getMessage());
                        }
                    });
                }
            });
        } else {
            // 私聊消息
            CopyOnWriteArrayList<Consumer<Message>> targetSessions = userSessions.get(message.getTo());
            if (targetSessions != null) {
                System.out.println("Sending private message to " + message.getTo());
                targetSessions.forEach(handler -> {
                    try {
                        handler.accept(message);
                    } catch (Exception e) {
                        System.err.println("Error sending private message to " + message.getTo() + ": " + e.getMessage());
                    }
                });
            } else {
                System.out.println("Target user not online: " + message.getTo());
            }

            // 如果是发送给管理员的消息，管理员也能看到
            if ("admin".equals(message.getTo())) {
                CopyOnWriteArrayList<Consumer<Message>> adminSessions = userSessions.get("admin");
                if (adminSessions != null && !message.getFrom().equals("admin")) {
                    System.out.println("Sending message to admin");
                    adminSessions.forEach(handler -> {
                        try {
                            handler.accept(message);
                        } catch (Exception e) {
                            System.err.println("Error sending message to admin: " + e.getMessage());
                        }
                    });
                }
            }

            // 如果是管理员发送的消息，发送给目标用户
            if ("admin".equals(message.getFrom()) && !"admin".equals(message.getTo())) {
                CopyOnWriteArrayList<Consumer<Message>> userTargetSessions = userSessions.get(message.getTo());
                if (userTargetSessions != null) {
                    System.out.println("Admin sending message to " + message.getTo());
                    userTargetSessions.forEach(handler -> {
                        try {
                            handler.accept(message);
                        } catch (Exception e) {
                            System.err.println("Error sending admin message to " + message.getTo() + ": " + e.getMessage());
                        }
                    });
                }
            }
        }
    }

    private void saveGroupMessageToAllUsers(Message message) throws IOException {
        // 群聊消息保存到所有用户的群聊记录中
        userSessions.forEach((username, sessions) -> {
            try {
                String encodedUsername = Base64.getEncoder().encodeToString(username.getBytes());
                Path userDir = dataDir.resolve(encodedUsername);

                if (!Files.exists(userDir)) {
                    Files.createDirectories(userDir);
                }

                // 群聊消息保存到专门的群聊文件
                Path groupChatLog = userDir.resolve("group_chat.log");
                String logEntry = objectMapper.writeValueAsString(message) + "\n";
                Files.writeString(groupChatLog, logEntry,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                System.err.println("Error saving group message to " + username + ": " + e.getMessage());
            }
        });
    }

    private void savePrivateMessage(Message message) throws IOException {
        // 私聊消息保存到发送者和接收者的私聊记录中

        // 保存到发送者的记录
        savePrivateMessageToUser(message.getFrom(), message);

        // 保存到接收者的记录
        savePrivateMessageToUser(message.getTo(), message);
    }

    private void savePrivateMessageToUser(String username, Message message) throws IOException {
        String encodedUsername = Base64.getEncoder().encodeToString(username.getBytes());
        Path userDir = dataDir.resolve(encodedUsername);

        // Ensure user directory exists
        if (!Files.exists(userDir)) {
            Files.createDirectories(userDir);
            System.out.println("Created user directory: " + userDir.toAbsolutePath());
        }

        // 私聊消息保存到专门的私聊文件
        Path privateChatLog = userDir.resolve("private_chat.log");
        String logEntry = objectMapper.writeValueAsString(message) + "\n";
        Files.writeString(privateChatLog, logEntry,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        System.out.println("Private message saved to user: " + username);
    }

    // 新增方法：获取用户的聊天记录
    public java.util.List<Message> getUserChatHistory(String username, String chatType, String targetUser) throws IOException {
        java.util.List<Message> messages = new java.util.ArrayList<>();
        String encodedUsername = Base64.getEncoder().encodeToString(username.getBytes());
        Path userDir = dataDir.resolve(encodedUsername);

        if ("group".equals(chatType)) {
            // 加载群聊记录
            Path groupChatLog = userDir.resolve("group_chat.log");
            if (Files.exists(groupChatLog)) {
                java.util.List<String> lines = Files.readAllLines(groupChatLog, StandardCharsets.UTF_8);
                for (String line : lines) {
                    if (!line.trim().isEmpty()) {
                        try {
                            Message message = objectMapper.readValue(line, Message.class);
                            messages.add(message);
                        } catch (Exception e) {
                            System.err.println("Failed to parse group message: " + e.getMessage());
                        }
                    }
                }
            }
        } else {
            // 加载私聊记录
            Path privateChatLog = userDir.resolve("private_chat.log");
            if (Files.exists(privateChatLog)) {
                java.util.List<String> lines = Files.readAllLines(privateChatLog, StandardCharsets.UTF_8);
                for (String line : lines) {
                    if (!line.trim().isEmpty()) {
                        try {
                            Message message = objectMapper.readValue(line, Message.class);
                            // 只加载与目标用户相关的私聊消息
                            if ((message.getFrom().equals(username) && message.getTo().equals(targetUser)) ||
                                    (message.getFrom().equals(targetUser) && message.getTo().equals(username))) {
                                messages.add(message);
                            }
                        } catch (Exception e) {
                            System.err.println("Failed to parse private message: " + e.getMessage());
                        }
                    }
                }
            }
        }

        return messages;
    }

    public Map<String, CopyOnWriteArrayList<Consumer<Message>>> getActiveSessions() {
        return userSessions;
    }

    public void ensureAdminDirectory() {
        try {
            String encodedUsername = Base64.getEncoder().encodeToString("admin".getBytes());
            Path adminDir = dataDir.resolve(encodedUsername);
            Files.createDirectories(adminDir);

            // 确保管理员有群聊和私聊文件
            Path groupChatLog = adminDir.resolve("group_chat.log");
            Path privateChatLog = adminDir.resolve("private_chat.log");
            if (!Files.exists(groupChatLog)) {
                Files.createFile(groupChatLog);
            }
            if (!Files.exists(privateChatLog)) {
                Files.createFile(privateChatLog);
            }

            System.out.println("Admin directory ensured: " + adminDir.toAbsolutePath());
        } catch (IOException e) {
            System.err.println("Failed to create admin directory: " + e.getMessage());
        }
    }
}