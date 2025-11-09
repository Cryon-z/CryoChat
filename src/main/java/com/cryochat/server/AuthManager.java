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
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class AuthManager {
    private final Path dataDir;
    private final Path userFile;
    private final Path banFile;
    private final String adminUsername;
    private final String adminPassword;
    private final Map<String, String> userMap; // username -> encodedUsername
    private final List<String> bannedUsers;
    private final ObjectMapper objectMapper;
    private final ConcurrentHashMap<String, Long> userLastActivity;

    public AuthManager(Config config) throws IOException {
        this.dataDir = Paths.get(config.getDataDir());
        this.userFile = dataDir.resolve("user.txt");
        this.banFile = dataDir.resolve("banned_users.txt");
        this.adminUsername = config.getAdminUsername();
        this.adminPassword = config.getAdminPassword();
        this.userMap = new ConcurrentHashMap<>();
        this.bannedUsers = new ArrayList<>();
        this.objectMapper = new ObjectMapper();
        this.userLastActivity = new ConcurrentHashMap<>();
        objectMapper.findAndRegisterModules();

        loadUsers();
        loadBannedUsers();
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

    private void loadBannedUsers() throws IOException {
        if (Files.exists(banFile)) {
            System.out.println("Loading banned users file: " + banFile.toAbsolutePath());
            bannedUsers.addAll(Files.readAllLines(banFile, StandardCharsets.UTF_8)
                    .stream()
                    .filter(line -> !line.trim().isEmpty())
                    .collect(Collectors.toList()));
            System.out.println("Loaded " + bannedUsers.size() + " banned users");
        } else {
            System.out.println("Banned users file does not exist: " + banFile.toAbsolutePath());
            // Create empty banned_users.txt file
            Files.createFile(banFile);
        }
    }

    public boolean authenticate(String username, String password) {
        System.out.println("=== Starting Authentication ===");
        System.out.println("Username: " + username);

        // 检查是否被封禁
        if (bannedUsers.contains(username)) {
            System.out.println("User is banned: " + username);
            return false;
        }

        // 管理员认证
        if (adminUsername.equals(username)) {
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

            // 更新用户活动时间
            if (result) {
                userLastActivity.put(username, System.currentTimeMillis());
            }

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

    public boolean isAdmin(String username) {
        return adminUsername.equals(username);
    }

    public String getEncodedUsername(String username) {
        return userMap.get(username);
    }

    public Map<String, String> getAllUsers() {
        return new HashMap<>(userMap);
    }

    // 新增方法：获取在线用户数量
    public int getOnlineUsersCount() {
        long fiveMinutesAgo = System.currentTimeMillis() - (5 * 60 * 1000);
        return (int) userLastActivity.entrySet().stream()
                .filter(entry -> entry.getValue() > fiveMinutesAgo)
                .count();
    }

    // 新增方法：获取封禁用户列表
    public List<String> getBannedUsers() {
        return new ArrayList<>(bannedUsers);
    }

    // 新增方法：封禁用户
    public boolean banUser(String username, String reason, int duration) {
        try {
            if (!userMap.containsKey(username) || bannedUsers.contains(username)) {
                return false;
            }

            bannedUsers.add(username);
            String banRecord = username + ":" + reason + ":" + duration + ":" + System.currentTimeMillis() + System.lineSeparator();
            Files.writeString(banFile, banRecord, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);

            System.out.println("User banned: " + username + ", reason: " + reason + ", duration: " + duration + " days");
            return true;
        } catch (IOException e) {
            System.err.println("Error banning user: " + e.getMessage());
            return false;
        }
    }

    // 新增方法：解封用户
    public boolean unbanUser(String username) {
        try {
            if (!bannedUsers.contains(username)) {
                return false;
            }

            bannedUsers.remove(username);

            // 重新写入封禁文件，排除该用户
            List<String> lines = Files.readAllLines(banFile, StandardCharsets.UTF_8);
            List<String> newLines = lines.stream()
                    .filter(line -> !line.startsWith(username + ":"))
                    .collect(Collectors.toList());

            Files.write(banFile, newLines, StandardCharsets.UTF_8);

            System.out.println("User unbanned: " + username);
            return true;
        } catch (IOException e) {
            System.err.println("Error unbanning user: " + e.getMessage());
            return false;
        }
    }

    // 新增方法：删除用户
    public boolean deleteUser(String username) {
        try {
            if (!userMap.containsKey(username)) {
                return false;
            }

            String encodedUsername = userMap.get(username);

            // 删除用户目录
            Path userDir = dataDir.resolve(encodedUsername);
            if (Files.exists(userDir)) {
                deleteDirectory(userDir);
            }

            // 从用户映射中移除
            userMap.remove(username);

            // 更新user.txt文件
            List<String> lines = Files.readAllLines(userFile, StandardCharsets.UTF_8);
            List<String> newLines = lines.stream()
                    .filter(line -> !line.startsWith(username + ":"))
                    .collect(Collectors.toList());

            Files.write(userFile, newLines, StandardCharsets.UTF_8);

            // 如果用户被封禁，也从封禁列表中移除
            if (bannedUsers.contains(username)) {
                unbanUser(username);
            }

            System.out.println("User deleted: " + username);
            return true;
        } catch (IOException e) {
            System.err.println("Error deleting user: " + e.getMessage());
            return false;
        }
    }

    // 新增方法：获取所有用户信息
    public List<Map<String, Object>> getAllUserInfo() {
        List<Map<String, Object>> users = new ArrayList<>();

        for (String username : userMap.keySet()) {
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("username", username);
            userInfo.put("banned", bannedUsers.contains(username));
            userInfo.put("lastLogin", "未知");
            userInfo.put("registerTime", "未知");
            users.add(userInfo);
        }

        return users;
    }

    // 新增方法：搜索用户
    public List<Map<String, Object>> searchUsers(String searchTerm) {
        List<Map<String, Object>> users = new ArrayList<>();

        if (searchTerm == null || searchTerm.trim().isEmpty()) {
            return getAllUserInfo();
        }

        for (String username : userMap.keySet()) {
            if (username.toLowerCase().contains(searchTerm.toLowerCase())) {
                Map<String, Object> userInfo = new HashMap<>();
                userInfo.put("username", username);
                userInfo.put("banned", bannedUsers.contains(username));
                userInfo.put("lastLogin", "未知");
                userInfo.put("registerTime", "未知");
                users.add(userInfo);
            }
        }

        return users;
    }

    // 辅助方法：递归删除目录
    private void deleteDirectory(Path path) throws IOException {
        if (Files.isDirectory(path)) {
            try (var stream = Files.list(path)) {
                for (Path entry : stream.collect(Collectors.toList())) {
                    deleteDirectory(entry);
                }
            }
        }
        Files.delete(path);
    }

    // 更新用户活动时间
    public void updateUserActivity(String username) {
        userLastActivity.put(username, System.currentTimeMillis());
    }
}