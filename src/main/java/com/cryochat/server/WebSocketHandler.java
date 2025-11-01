package com.cryochat.server;

import com.cryochat.model.Message;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class WebSocketHandler {
    private final ChatManager chatManager;
    private final FileManager fileManager;
    private final ObjectMapper objectMapper;
    private final ConcurrentHashMap<String, AtomicInteger> connectionCounts;
    private final ConcurrentHashMap<String, SSEConnection> sseConnections;

    public WebSocketHandler(ChatManager chatManager, FileManager fileManager) {
        this.chatManager = chatManager;
        this.fileManager = fileManager;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.findAndRegisterModules();
        this.connectionCounts = new ConcurrentHashMap<>();
        this.sseConnections = new ConcurrentHashMap<>();
    }

    public void addSSEConnection(String username, SSEConnection connection) {
        sseConnections.put(username, connection);

        // Add user session to chat manager
        chatManager.addUserSession(username, message -> {
            try {
                connection.sendMessage(objectMapper.writeValueAsString(message));
            } catch (IOException e) {
                // Connection might be closed, remove session
                System.err.println("Failed to send message: " + e.getMessage());
                removeSSEConnection(username);
            }
        });
    }

    public void removeSSEConnection(String username) {
        SSEConnection connection = sseConnections.remove(username);
        if (connection != null) {
            try {
                connection.close();
            } catch (IOException e) {
                // Ignore close exception
                System.err.println("Failed to close SSE connection: " + e.getMessage());
            }
        }
        chatManager.removeUserSession(username, null);
    }

    public void handleMessage(String username, String messageJson) {
        try {
            Message message = objectMapper.readValue(messageJson, Message.class);
            message.setFrom(username);

            if ("file".equals(message.getType())) {
                handleFileMessage(message);
            } else {
                chatManager.sendMessage(message);
            }

        } catch (IOException e) {
            System.err.println("Failed to process message: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleFileMessage(Message message) throws IOException {
        // In actual implementation, this should handle file upload and download
        // Simplified implementation, directly send message
        try {
            chatManager.sendMessage(message);
        } catch (IOException e) {
            System.err.println("Failed to send file message: " + e.getMessage());
            throw e;
        }
    }

    // Human verification - simple connection frequency limit
    public boolean verifyHuman(String clientIp) {
        AtomicInteger count = connectionCounts.computeIfAbsent(clientIp, k -> new AtomicInteger(0));
        int currentCount = count.incrementAndGet();

        // Simple rate limit: maximum 10 connections per minute
        if (currentCount > 10) {
            return false;
        }

        // Reset counter (simplified implementation)
        new Thread(() -> {
            try {
                Thread.sleep(60000); // 1 minute
                count.decrementAndGet();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();

        return true;
    }

    // SSE connection interface
    public interface SSEConnection {
        void sendMessage(String message) throws IOException;
        void close() throws IOException;
    }
}