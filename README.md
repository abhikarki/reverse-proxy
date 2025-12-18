## reverse-proxy

An asynchronous, multi-threaded reverse proxy for Windows, designed to efficiently handle thousands of concurrent connections. Features include per-client rate limiting to mitigate application layer attacks and built-in TLS support (with session caching) for secure, high-performance communication.

## Features

- **Asynchronous I/O:** Uses IOCP (I/O Completion Ports) for scalable, non-blocking networking.
- **Multi-threaded:** Worker thread pool for efficient event handling.
- **TLS Termination:** Secure connections with OpenSSL, including session caching for fast resumption.
- **Per-client Rate Limiting:** Prevents abuse and application-layer attacks.
- **Connection Management:** Robust handling of thousands of concurrent sockets.


### System Architecture And Workflow

```mermaid
flowchart TB
    %% =========================
    %% EXTERNAL
    %% =========================
    Client["Client"]
    style Client fill:#e3f2fd,stroke:#1976d2,stroke-width:2px

    %% =========================
    %% ACCEPT LAYER
    %% =========================
    subgraph AcceptLayer["Accept Layer"]
        Listen["Listening Socket"]
        Accept["Accept New Connection"]
        AcceptBuf["Address Buffer"]
    end
    style AcceptLayer fill:#fffde7,stroke:#fbc02d,stroke-width:2px

    %% =========================
    %% IOCP CORE
    %% =========================
    subgraph IOCP_Core["IOCP Core"]
        IOCP["Completion Port"]
        CQ["Completion Queue"]
    end
    style IOCP_Core fill:#e1f5fe,stroke:#0288d1,stroke-width:2px

    %% =========================
    %% WORKERS
    %% =========================
    subgraph Workers["Worker Threads"]
        GQCS["Wait for Events"]
        Dispatch["Handle Event Type"]
    end
    style Workers fill:#e8f5e9,stroke:#43a047,stroke-width:2px

    %% =========================
    %% CONNECTION STATE
    %% =========================
    subgraph ConnState["Connection State"]
        Sock["Socket"]
        PendingIO["Pending Operations"]
        Closing["Closing Flag"]
        ClientIP["Client IP"]
        TLSConn["TLS State"]
    end
    style ConnState fill:#ede7f6,stroke:#7e57c2,stroke-width:2px

    %% =========================
    %% RATE LIMITING
    %% =========================
    subgraph RateLimit["Rate Limiting"]
        RLAccept["Check at Accept"]
        RLApp["Check on Data"]
    end
    style RateLimit fill:#fff3e0,stroke:#f57c00,stroke-width:2px

    %% =========================
    %% TLS PIPELINE
    %% =========================
    subgraph TLS["TLS Processing"]
        Handshake["Handshake"]
        Decrypt["Decrypt Data"]
        Encrypt["Encrypt Data"]
        TLSBuf["TLS Output Buffer"]
    end
    style TLS fill:#e0f7fa,stroke:#00acc1,stroke-width:2px

    %% =========================
    %% ASYNC IO
    %% =========================
    subgraph AsyncIO["Async I/O"]
        PostRecv["Receive Data"]
        PostSend["Send Data"]
    end
    style AsyncIO fill:#fce4ec,stroke:#d81b60,stroke-width:2px

    %% =========================
    %% FLOW
    %% =========================
    Client -->|Connect| Listen
    Listen --> Accept
    Accept --> AcceptBuf
    Accept -->|Ready| IOCP
    IOCP --> CQ
    CQ --> GQCS
    GQCS --> Dispatch

    %% OP_ACCEPT workflow
    Dispatch -->|Accept Event| RLAccept
    RLAccept -->|Allowed| ConnState
    RLAccept -->|Rejected| Client
    ConnState -->|Register| IOCP
    ConnState -->|Start| PostRecv

    %% OP_READ workflow
    Dispatch -->|Read Event| Handshake
    Handshake -->|If Complete| Decrypt
    Decrypt -->|Plain Data| RLApp
    RLApp -->|Allowed| Encrypt
    RLApp -->|Rate Limited| Encrypt
    Encrypt --> TLSBuf
    TLSBuf --> PostSend

    %% OP_WRITE workflow
    Dispatch -->|Write Event| PendingIO
    PendingIO -->|If Done & Closing| Closing
    Closing -->|Cleanup| Sock
```



3. **Starting the Proxy:**

```bash
make clean
```
```bash
make
```
```bash
./main.exe
```

## License

MIT License
