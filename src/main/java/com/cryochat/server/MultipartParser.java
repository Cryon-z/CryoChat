package com.cryochat.server;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class MultipartParser {
    private final byte[] data;
    private final byte[] boundary;
    private final Map<String, String> textParts;
    private final Map<String, byte[]> fileParts;
    private final Map<String, String> fileNames;

    public MultipartParser(byte[] data, byte[] boundary) {
        this.data = data;
        this.boundary = boundary;
        this.textParts = new HashMap<>();
        this.fileParts = new HashMap<>();
        this.fileNames = new HashMap<>();
        parse();
    }

    private void parse() {
        byte[] boundaryWithPrefix = ("--" + new String(boundary, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);

        int start = findBoundary(data, boundaryWithPrefix, 0);
        if (start == -1) return;

        while (true) {
            int partStart = start + boundaryWithPrefix.length;
            if (partStart >= data.length) break;

            // 跳过 CRLF
            if (data[partStart] == '\r' && data[partStart + 1] == '\n') {
                partStart += 2;
            }

            int headersEnd = findCRLFCRLF(data, partStart);
            if (headersEnd == -1) break;

            // 解析头部
            String headers = new String(data, partStart, headersEnd - partStart, StandardCharsets.UTF_8);
            int contentStart = headersEnd + 4; // 跳过 \r\n\r\n

            // 查找下一个边界
            int nextBoundary = findBoundary(data, boundaryWithPrefix, contentStart);
            if (nextBoundary == -1) break;

            // 提取内容 (减去最后的 \r\n)
            int contentEnd = nextBoundary - 2;
            if (contentEnd < contentStart) {
                contentEnd = nextBoundary;
            }

            byte[] content = new byte[contentEnd - contentStart];
            System.arraycopy(data, contentStart, content, 0, content.length);

            // 解析头部信息
            String name = extractHeaderValue(headers, "name=\"", "\"");
            String filename = extractHeaderValue(headers, "filename=\"", "\"");

            if (filename != null && !filename.isEmpty()) {
                // 文件部分
                fileParts.put(name, content);
                fileNames.put(name, filename);
                System.out.println("解析到文件: " + filename + ", 大小: " + content.length + " 字节");
            } else {
                // 文本部分
                textParts.put(name, new String(content, StandardCharsets.UTF_8));
            }

            start = nextBoundary;
        }
    }

    private int findBoundary(byte[] data, byte[] boundary, int start) {
        for (int i = start; i <= data.length - boundary.length; i++) {
            boolean found = true;
            for (int j = 0; j < boundary.length; j++) {
                if (data[i + j] != boundary[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }
        return -1;
    }

    private int findCRLFCRLF(byte[] data, int start) {
        for (int i = start; i <= data.length - 4; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' &&
                    data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private String extractHeaderValue(String headers, String startDelim, String endDelim) {
        int startIndex = headers.indexOf(startDelim);
        if (startIndex == -1) return null;

        startIndex += startDelim.length();
        int endIndex = headers.indexOf(endDelim, startIndex);
        if (endIndex == -1) return null;

        return headers.substring(startIndex, endIndex);
    }

    public Map<String, String> getTextParts() {
        return textParts;
    }

    public Map<String, byte[]> getFileParts() {
        return fileParts;
    }

    public Map<String, String> getFileNames() {
        return fileNames;
    }
}