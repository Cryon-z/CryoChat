package com.cryochat.model;

import java.time.LocalDateTime;
import com.fasterxml.jackson.annotation.JsonInclude;

public class Message {
    private String from;
    private String to;
    private String content;
    private String type; // "text" or "file"
    private LocalDateTime timestamp;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Object fileInfo; // 文件信息，如果是文件消息

    public Message() {
        this.timestamp = LocalDateTime.now();
    }

    public Message(String from, String to, String content, String type) {
        this();
        this.from = from;
        this.to = to;
        this.content = content;
        this.type = type;
    }

    // Getters and Setters
    public String getFrom() { return from; }
    public void setFrom(String from) { this.from = from; }

    public String getTo() { return to; }
    public void setTo(String to) { this.to = to; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

    public Object getFileInfo() { return fileInfo; }
    public void setFileInfo(Object fileInfo) { this.fileInfo = fileInfo; }
}