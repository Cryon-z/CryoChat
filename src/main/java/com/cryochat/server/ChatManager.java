package com.cryochat.server;

import com.cryochat.model.Message;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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
            sessions.remove(messageHandler);
            if (sessions.isEmpty()) {
                userSessions.remove(username);
            }
        }
        System.out.println("User session removed: " + username + ", active sessions: " + userSessions.size());
    }

    public void sendMessage(Message message) throws IOException {
        // Save message to both sender and receiver
        saveMessageToSender(message);
        saveMessageToReceiver(message);

        // Send to target user
        CopyOnWriteArrayList<Consumer<Message>> targetSessions = userSessions.get(message.getTo());
        if (targetSessions != null) {
            System.out.println("Sending message to " + message.getTo());
            targetSessions.forEach(handler -> handler.accept(message));
        } else {
            System.out.println("Target user not online: " + message.getTo());
        }

        // 如果是发送给管理员的消息，管理员也能看到
        if ("admin".equals(message.getTo())) {
            CopyOnWriteArrayList<Consumer<Message>> adminSessions = userSessions.get("admin");
            if (adminSessions != null && !message.getFrom().equals("admin")) {
                System.out.println("Sending message to admin");
                adminSessions.forEach(handler -> handler.accept(message));
            }
        }

        // 如果是管理员发送的消息，发送给目标用户
        if ("admin".equals(message.getFrom()) && !"admin".equals(message.getTo())) {
            CopyOnWriteArrayList<Consumer<Message>> userTargetSessions = userSessions.get(message.getTo());
            if (userTargetSessions != null) {
                System.out.println("Admin sending message to " + message.getTo());
                userTargetSessions.forEach(handler -> handler.accept(message));
            }
        }
    }

    private void saveMessageToSender(Message message) throws IOException {
        String encodedUsername = Base64.getEncoder().encodeToString(message.getFrom().getBytes());
        Path userDir = dataDir.resolve(encodedUsername);

        // Ensure user directory exists
        if (!Files.exists(userDir)) {
            Files.createDirectories(userDir);
            System.out.println("Created user directory: " + userDir.toAbsolutePath());
        }

        Path chatLog = userDir.resolve("chat.log");

        String logEntry = objectMapper.writeValueAsString(message) + "\n";
        Files.writeString(chatLog, logEntry,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        System.out.println("Message saved to sender: " + chatLog.toAbsolutePath());
    }

    private void saveMessageToReceiver(Message message) throws IOException {
        String encodedUsername = Base64.getEncoder().encodeToString(message.getTo().getBytes());
        Path userDir = dataDir.resolve(encodedUsername);

        // Ensure user directory exists
        if (!Files.exists(userDir)) {
            Files.createDirectories(userDir);
            System.out.println("Created user directory: " + userDir.toAbsolutePath());
        }

        Path chatLog = userDir.resolve("chat.log");

        String logEntry = objectMapper.writeValueAsString(message) + "\n";
        Files.writeString(chatLog, logEntry,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        System.out.println("Message saved to receiver: " + chatLog.toAbsolutePath());
    }

    public Map<String, CopyOnWriteArrayList<Consumer<Message>>> getActiveSessions() {
        return userSessions;
    }

    // 添加缺失的方法
    public void ensureAdminDirectory() {
        try {
            String encodedUsername = Base64.getEncoder().encodeToString("admin".getBytes());
            Path adminDir = dataDir.resolve(encodedUsername);
            Files.createDirectories(adminDir);
            System.out.println("Admin directory ensured: " + adminDir.toAbsolutePath());
        } catch (IOException e) {
            System.err.println("Failed to create admin directory: " + e.getMessage());
        }
    }
}