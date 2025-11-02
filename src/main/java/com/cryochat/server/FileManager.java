package com.cryochat.server;

import com.cryochat.model.FileInfo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.UUID;

public class FileManager {
    private final Path storageDir;

    public FileManager(String dataDir) throws IOException {
        // 文件一律存放到 ./CryoChat/files/ 里面
        this.storageDir = Paths.get("./CryoChat/files/");
        Files.createDirectories(storageDir);
    }

    public FileInfo saveFile(String username, String originalFilename, byte[] fileData) throws IOException {
        String fileId = UUID.randomUUID().toString();
        String extension = getFileExtension(originalFilename);
        String storedFilename = fileId + (extension.isEmpty() ? "" : "." + extension);

        Path filePath = storageDir.resolve(storedFilename);
        Files.write(filePath, fileData);

        return new FileInfo(originalFilename, storedFilename, fileData.length,
                getMimeType(originalFilename));
    }

    public byte[] getFile(String storedFilename) throws IOException {
        Path filePath = storageDir.resolve(storedFilename);
        return Files.readAllBytes(filePath);
    }

    public String compressAndEncode(byte[] data) {
        // In actual implementation, should compress data first then encode
        // Simplified implementation, directly Base64 encode
        return Base64.getEncoder().encodeToString(data);
    }

    public byte[] decodeAndDecompress(String base64Data) {
        // In actual implementation, should decode first then decompress
        return Base64.getDecoder().decode(base64Data);
    }

    private String getFileExtension(String filename) {
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