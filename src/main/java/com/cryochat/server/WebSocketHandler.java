package com.cryochat.server;

import com.cryochat.model.Message;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

public class WebSocketHandler {
    private final ChatManager chatManager;
    private final FileManager fileManager;
    private final ObjectMapper objectMapper;
    private final ConcurrentHashMap<String, SSEConnection> sseConnections;

    public WebSocketHandler(ChatManager chatManager, FileManager fileManager) {
        this.chatManager = chatManager;
        this.fileManager = fileManager;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.findAndRegisterModules();
        this.sseConnections = new ConcurrentHashMap<>();
    }

    public void addSSEConnection(String username, SSEConnection connection) {
        // 移除旧的连接（如果存在）
        removeSSEConnection(username);

        sseConnections.put(username, connection);

        // Add user session to chat manager
        chatManager.addUserSession(username, message -> {
            try {
                if (!connection.isClosed()) {
                    connection.sendMessage(objectMapper.writeValueAsString(message));
                } else {
                    // 连接已关闭，移除会话
                    removeSSEConnection(username);
                }
            } catch (IOException e) {
                // Connection might be closed, remove session
                System.err.println("Failed to send message to " + username + ": " + e.getMessage());
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
                System.err.println("Failed to close SSE connection for " + username + ": " + e.getMessage());
            }
        }
        chatManager.removeUserSession(username, null);
        System.out.println("SSE连接已移除: " + username);
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
        try {
            chatManager.sendMessage(message);
        } catch (IOException e) {
            System.err.println("Failed to send file message: " + e.getMessage());
            throw e;
        }
    }

    // SSE connection interface
    public interface SSEConnection {
        void sendMessage(String message) throws IOException;
        void close() throws IOException;
        boolean isClosed();
    }
}