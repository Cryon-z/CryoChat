package com.cryochat.server;

import com.cryochat.model.FileInfo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

public class FileManager {
    private final Path storageDir;

    public FileManager(String dataDir) throws IOException {
        // 文件一律存放到 ./CryoChat/files/ 里面
        this.storageDir = Paths.get("./CryoChat/files/");
        Files.createDirectories(storageDir);
        System.out.println("文件存储目录: " + storageDir.toAbsolutePath());
    }

    public FileInfo saveFile(String username, String originalFilename, byte[] fileData) throws IOException {
        // 生成唯一的文件名
        String fileId = UUID.randomUUID().toString();
        String extension = getFileExtension(originalFilename);
        String storedFilename = fileId + (extension.isEmpty() ? "" : "." + extension);

        Path filePath = storageDir.resolve(storedFilename);

        // 使用 Files.write 确保二进制数据正确保存
        Files.write(filePath, fileData);

        System.out.println("文件保存成功: " + storedFilename);
        System.out.println("原始文件名: " + originalFilename);
        System.out.println("文件大小: " + fileData.length + " 字节");
        System.out.println("存储路径: " + filePath.toAbsolutePath());

        return new FileInfo(originalFilename, storedFilename, fileData.length,
                getMimeType(originalFilename));
    }

    public byte[] getFile(String storedFilename) throws IOException {
        Path filePath = storageDir.resolve(storedFilename);
        if (!Files.exists(filePath)) {
            throw new IOException("文件不存在: " + storedFilename);
        }
        return Files.readAllBytes(filePath);
    }

    private String getFileExtension(String filename) {
        if (filename == null || filename.isEmpty()) {
            return "";
        }
        int lastDot = filename.lastIndexOf('.');
        return lastDot > 0 ? filename.substring(lastDot + 1) : "";
    }

    private String getMimeType(String filename) {
        String extension = getFileExtension(filename).toLowerCase();
        return switch (extension) {
            case "txt" -> "text/plain";
            case "jpg", "jpeg" -> "image/jpeg";
            case "png" -> "image/png";
            case "pdf" -> "application/pdf";
            case "zip" -> "application/zip";
            default -> "application/octet-stream";
        };
    }
}