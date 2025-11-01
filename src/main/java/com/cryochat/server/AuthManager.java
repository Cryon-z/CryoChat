package com.cryochat.server;

import com.cryochat.model.User;
import com.cryochat.config.Config;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

public class AuthManager {
    private final Path dataDir;
    private final Path userFile;
    private final String adminPassword;
    private final Map<String, String> userMap; // username -> encodedUsername
    private final ObjectMapper objectMapper;

    public AuthManager(Config config) throws IOException {
        this.dataDir = Paths.get(config.getDataDir());
        this.userFile = dataDir.resolve("user.txt");
        this.adminPassword = config.getAdminPassword();
        this.userMap = new ConcurrentHashMap<>();
        this.objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules();

        loadUsers();
    }

    private void loadUsers() throws IOException {
        if (Files.exists(userFile)) {
            System.out.println("Loading user file: " + userFile.toAbsolutePath());
            Files.lines(userFile, StandardCharsets.UTF_8)
                    .filter(line -> line.contains(":"))
                    .forEach(line -> {
                        String[] parts = line.split(":", 2);
                        if (parts.length == 2) {
                            userMap.put(parts[0].trim(), parts[1].trim());
                            System.out.println("Loaded user: " + parts[0].trim() + " -> " + parts[1].trim());
                        }
                    });
        } else {
            System.out.println("User file does not exist: " + userFile.toAbsolutePath());
            // Create empty user.txt file
            Files.createFile(userFile);
        }
    }

    public boolean authenticate(String username, String password, String clientIp) {
        System.out.println("=== Starting Authentication ===");
        System.out.println("Username: " + username);
        System.out.println("Client IP: " + clientIp);

        // 只有用户名为 "admin" 才是真正的管理员
        boolean isAdminUser = "admin".equals(username);

        if (isAdminUser) {
            boolean adminMatch = password.equals(adminPassword);
            System.out.println("Admin authentication result: " + adminMatch);
            return adminMatch;
        }

        // 普通用户认证
        String encodedUsername = userMap.get(username);
        System.out.println("User found in user.txt: " + (encodedUsername != null));

        if (encodedUsername == null) {
            System.out.println("Error: User not found in user.txt");
            return false;
        }

        try {
            Path userDir = dataDir.resolve(encodedUsername);
            Path userJson = userDir.resolve("user.json");
            System.out.println("User JSON path: " + userJson.toAbsolutePath());

            if (!Files.exists(userJson)) {
                System.out.println("Error: user.json file does not exist");
                return false;
            }

            // 读取用户数据
            String jsonContent = Files.readString(userJson, StandardCharsets.UTF_8);
            System.out.println("user.json content: " + jsonContent);

            User user = objectMapper.readValue(userJson.toFile(), User.class);
            String storedPassword = user.getPassword();
            String inputPassword = encodePassword10Times(password);

            System.out.println("Stored password: " + storedPassword);
            System.out.println("Input password (encoded): " + inputPassword);
            System.out.println("Password length comparison - stored: " + storedPassword.length() + ", input: " + inputPassword.length());
            System.out.println("Password exact match: " + storedPassword.equals(inputPassword));

            boolean result = storedPassword.equals(inputPassword);
            System.out.println("Authentication result: " + result);
            return result;

        } catch (IOException e) {
            System.err.println("Error reading user data: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public boolean register(String username, String password) throws IOException {
        System.out.println("=== Starting Registration ===");
        System.out.println("Username: " + username);

        if (userMap.containsKey(username)) {
            System.out.println("Error: Username already exists");
            return false;
        }

        // Encode username as folder name
        String encodedUsername = Base64.getEncoder().encodeToString(username.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encoded username: " + encodedUsername);

        // Create user directory
        Path userDir = dataDir.resolve(encodedUsername);
        Files.createDirectories(userDir);
        System.out.println("Created user directory: " + userDir.toAbsolutePath());

        // Encode password
        String encodedPassword = encodePassword10Times(password);
        System.out.println("Encoded password: " + encodedPassword);

        // Create user JSON file
        User user = new User(username, encodedPassword);
        Path userJson = userDir.resolve("user.json");
        objectMapper.writeValue(userJson.toFile(), user);
        System.out.println("Created user.json: " + userJson.toAbsolutePath());

        // Update user.txt
        userMap.put(username, encodedUsername);
        String userRecord = username + ":" + encodedUsername + System.lineSeparator();
        Files.writeString(userFile, userRecord, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        System.out.println("Updated user.txt");
        System.out.println("=== Registration Complete ===");
        return true;
    }

    private String encodePassword10Times(String password) {
        String result = password;
        Base64.Encoder encoder = Base64.getEncoder();

        for (int i = 0; i < 10; i++) {
            result = encoder.encodeToString(result.getBytes(StandardCharsets.UTF_8));
        }
        return result;
    }

    // 修复方法签名，移除不需要的clientIp参数
    public boolean isAdmin(String username) {
        // 只有用户名为 "admin" 才是真正的管理员
        return "admin".equals(username);
    }

    public String getEncodedUsername(String username) {
        return userMap.get(username);
    }

    public Map<String, String> getAllUsers() {
        return new HashMap<>(userMap);
    }
}