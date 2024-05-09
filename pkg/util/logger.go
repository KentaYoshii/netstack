package util

import (
    "context"
    "io"
    "log"
    "log/slog"

    "github.com/fatih/color"
)

// Custom Logger Class

type PrettyHandlerOptions struct {
    SlogOpts slog.HandlerOptions
}

type PrettyHandler struct {
    slog.Handler
    L *log.Logger
}

type LogLevel int

const (
    // Different enums for log levels
    
    DEBUG LogLevel = iota
    INFO
    WARN 
    ERROR
)   

func (h *PrettyHandler) Handle(ctx context.Context, r slog.Record) error {
    level := r.Level.String() + ":"

    // Add colors
    switch r.Level {
    case slog.LevelDebug:
        level = color.MagentaString(level)
    case slog.LevelInfo:
        level = color.BlueString(level)
    case slog.LevelWarn:
        level = color.YellowString(level)
    case slog.LevelError:
        level = color.RedString(level)
    }

    // Time prefix
    timeStr := r.Time.Format("[15:05:05.000]")
    msg := color.CyanString(r.Message)

    h.L.Println()
    h.L.Println(timeStr, level, msg)

    return nil
}

// Function to initialize the logger
func NewPrettyHandler(
    out io.Writer,
    opts PrettyHandlerOptions,
) *PrettyHandler {
    h := &PrettyHandler{
        Handler: slog.NewJSONHandler(out, &opts.SlogOpts),
        L:       log.New(out, "", 0),
    }

    return h
}
